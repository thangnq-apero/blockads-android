package app.pwhs.blockads.dns

import android.net.VpnService
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

/**
 * DNS-over-HTTPS (DoH) client with VPN socket protection.
 *
 * Uses [OkHttpClient] with a custom [SocketFactory] that calls
 * [VpnService.protect] on every created socket, preventing VPN routing loops.
 *
 * Without protect(), DoH requests route through the VPN tunnel,
 * which itself waits for DNS → infinite loop → EOFException.
 */
class DohClient {

    companion object {
        private const val QUERY_TIMEOUT_MS = 5000L
        private val DNS_MEDIA_TYPE = "application/dns-message".toMediaType()
    }

    @Volatile
    private var vpnService: VpnService? = null

    @Volatile
    private var okHttpClient: OkHttpClient? = null

    /** Default unprotected client for use before VPN starts */
    private val defaultClient: OkHttpClient by lazy {
        buildOkHttpClient(null)
    }

    /**
     * Set the VpnService reference. Must be called when VPN starts.
     * Pass null when VPN stops to release the service reference.
     */
    fun setVpnService(service: VpnService?) {
        vpnService = service
        okHttpClient = if (service != null) {
            buildOkHttpClient(service)
        } else null
    }

    private fun buildOkHttpClient(service: VpnService?): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(3, TimeUnit.SECONDS)
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            .retryOnConnectionFailure(false) // We handle retries ourselves

        if (service != null) {
            builder.socketFactory(ProtectedSocketFactory(service))
        }

        return builder.build()
    }

    private fun getClient(): OkHttpClient = okHttpClient ?: defaultClient

    /**
     * Perform a DNS query over HTTPS.
     * Tries GET first (more reliable), falls back to POST.
     */
    suspend fun query(dohUrl: String, dnsPayload: ByteArray): ByteArray? {
        return queryGet(dohUrl, dnsPayload) ?: queryPost(dohUrl, dnsPayload)
    }

    /**
     * DoH GET query (RFC 8484 §4.1)
     */
    suspend fun queryGet(dohUrl: String, dnsPayload: ByteArray): ByteArray? {
        return withContext(Dispatchers.IO) {
            try {
                withTimeout(QUERY_TIMEOUT_MS) {
                    val base64Dns = Base64.encodeToString(
                        dnsPayload,
                        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
                    )

                    val request = Request.Builder()
                        .url("$dohUrl?dns=$base64Dns")
                        .header("Accept", "application/dns-message")
                        .get()
                        .build()

                    val response = getClient().newCall(request).execute()
                    response.use { resp ->
                        if (!resp.isSuccessful) {
                            Timber.w("DoH GET returned ${resp.code}")
                            return@withTimeout null
                        }

                        val bytes = resp.body?.bytes()
                        if (bytes == null || bytes.size < 12) {
                            Timber.w("DoH GET response invalid: ${bytes?.size ?: 0} bytes")
                            return@withTimeout null
                        }

                        Timber.d("DoH GET ok: ${bytes.size} bytes")
                        bytes
                    }
                }
            } catch (e: Exception) {
                Timber.e("DoH GET failed: $e")
                null
            }
        }
    }

    /**
     * DoH POST query (RFC 8484 §4.1)
     */
    suspend fun queryPost(dohUrl: String, dnsPayload: ByteArray): ByteArray? {
        return withContext(Dispatchers.IO) {
            try {
                withTimeout(QUERY_TIMEOUT_MS) {
                    val request = Request.Builder()
                        .url(dohUrl)
                        .header("Accept", "application/dns-message")
                        .post(dnsPayload.toRequestBody(DNS_MEDIA_TYPE))
                        .build()

                    val response = getClient().newCall(request).execute()
                    response.use { resp ->
                        if (!resp.isSuccessful) {
                            Timber.w("DoH POST returned ${resp.code}")
                            return@withTimeout null
                        }

                        val bytes = resp.body?.bytes()
                        if (bytes == null || bytes.size < 12) {
                            Timber.w("DoH POST response invalid: ${bytes?.size ?: 0} bytes")
                            return@withTimeout null
                        }

                        Timber.d("DoH POST ok: ${bytes.size} bytes")
                        bytes
                    }
                }
            } catch (e: Exception) {
                Timber.e("DoH POST failed: $e")
                null
            }
        }
    }

    /**
     * SocketFactory that protects every socket from VPN routing via [VpnService.protect].
     * OkHttp calls this factory for raw TCP sockets BEFORE TLS handshake,
     * so protect() is applied at the right level.
     */
    private class ProtectedSocketFactory(
        private val vpnService: VpnService
    ) : SocketFactory() {

        override fun createSocket(): Socket {
            return Socket().also { vpnService.protect(it) }
        }

        override fun createSocket(host: String?, port: Int): Socket {
            return Socket(host, port).also { vpnService.protect(it) }
        }

        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket {
            return Socket(host, port, localHost, localPort).also { vpnService.protect(it) }
        }

        override fun createSocket(host: InetAddress?, port: Int): Socket {
            return Socket(host, port).also { vpnService.protect(it) }
        }

        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket {
            return Socket(address, port, localAddress, localPort).also { vpnService.protect(it) }
        }
    }
}
