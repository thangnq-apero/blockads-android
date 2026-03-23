package app.pwhs.blockads.utils

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import app.pwhs.blockads.service.AdBlockVpnService

object VpnUtils {
    fun isOtherVpnActive(context: Context): Boolean {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val allNetworks = connectivityManager.allNetworks
        
        for (network in allNetworks) {
            val capabilities = connectivityManager.getNetworkCapabilities(network)
            if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                // Determine if the detected VPN belongs to our app 
                // Assumes AdBlockVpnService.isRunning is accurately tracking our VPN lifecycle
                if (!AdBlockVpnService.isRunning) {
                    return true 
                }
            }
        }
        return false
    }
}
