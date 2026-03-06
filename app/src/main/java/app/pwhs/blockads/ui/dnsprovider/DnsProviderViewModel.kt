package app.pwhs.blockads.ui.dnsprovider

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.pwhs.blockads.data.datastore.AppPreferences
import app.pwhs.blockads.data.entities.DnsCategory
import app.pwhs.blockads.data.entities.DnsProtocol
import app.pwhs.blockads.data.entities.DnsProvider
import app.pwhs.blockads.data.entities.DnsProviders
import app.pwhs.blockads.service.AdBlockVpnService
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class DnsProviderViewModel(
    private val appPrefs: AppPreferences,
    application: Application
) : AndroidViewModel(application) {

    val upstreamDns: StateFlow<String> = appPrefs.upstreamDns
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5000),
            AppPreferences.DEFAULT_UPSTREAM_DNS
        )

    val fallbackDns: StateFlow<String> = appPrefs.fallbackDns
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5000),
            AppPreferences.DEFAULT_FALLBACK_DNS
        )

    val selectedProviderId: StateFlow<String?> = combine(
        appPrefs.dnsProviderId,
        appPrefs.upstreamDns
    ) { providerId, upstreamDns ->
        // If provider ID is set, use it
        providerId ?: // Otherwise, try to detect provider from current upstream DNS
        DnsProviders.getByIp(upstreamDns)?.id
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    val customDnsEnabled: StateFlow<Boolean> = combine(
        appPrefs.dnsProviderId,
        appPrefs.upstreamDns
    ) { providerId, upstreamDns ->
        // Custom DNS is enabled if no provider ID is set and IP doesn't match any preset
        providerId == null && DnsProviders.getByIp(upstreamDns) == null
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), false)

    fun selectProvider(provider: DnsProvider) {
        viewModelScope.launch {
            appPrefs.setDnsProviderId(provider.id)
            appPrefs.setUpstreamDns(provider.ipAddress)
            // Set fallback DNS to a different provider for redundancy
            // Use privacy-friendly Quad9 <-> AdGuard pairing
            val fallbackProvider = when (provider.id) {
                DnsProviders.QUAD9.id -> DnsProviders.ADGUARD
                DnsProviders.ADGUARD.id -> DnsProviders.QUAD9
                else -> {
                    // Find first privacy provider different from selected
                    DnsProviders.ALL_PROVIDERS.firstOrNull {
                        it.id != provider.id && it.category == DnsCategory.PRIVACY
                    } ?: DnsProviders.QUAD9
                }
            }
            appPrefs.setFallbackDns(fallbackProvider.ipAddress)
            AdBlockVpnService.requestRestart(getApplication<Application>().applicationContext)
        }
    }

    fun setCustomDns(upstream: String, fallback: String) {
        val trimmed = upstream.trim()
        viewModelScope.launch {
            appPrefs.setDnsProviderId(null)
            when {
                trimmed.startsWith("https://", ignoreCase = true) -> {
                    appPrefs.setDnsProtocol(DnsProtocol.DOH)
                    appPrefs.setDohUrl(trimmed)
                }
                trimmed.startsWith("tls://", ignoreCase = true) -> {
                    appPrefs.setDnsProtocol(DnsProtocol.DOT)
                    appPrefs.setUpstreamDns(trimmed.removePrefix("tls://").removePrefix("TLS://"))
                }
                else -> {
                    appPrefs.setDnsProtocol(DnsProtocol.PLAIN)
                    appPrefs.setUpstreamDns(trimmed)
                }
            }
            appPrefs.setFallbackDns(fallback)
            AdBlockVpnService.requestRestart(getApplication<Application>().applicationContext)
        }
    }
}
