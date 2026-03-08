package app.pwhs.blockads.dns

import android.net.VpnService
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import timber.log.Timber
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

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
    suspend fun queryGet(dohUrl: String, dnsPayload: ByteArray): ByteArray? =
        withContext(Dispatchers.IO) {
            try {
                val base64Dns = Base64.encodeToString(
                    dnsPayload,
                    Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
                )

                val request = Request.Builder()
                    .url("$dohUrl?dns=$base64Dns")
                    .header("Accept", "application/dns-message")
                    .get()
                    .build()

                executeAndParse(request, "DoH GET")
            } catch (e: Exception) {
                Timber.e("DoH GET failed: $e")
                null
            }
        }

    /**
     * DoH POST query (RFC 8484 §4.1)
     */
    suspend fun queryPost(dohUrl: String, dnsPayload: ByteArray): ByteArray? =
        withContext(Dispatchers.IO) {
            try {
                val request = Request.Builder()
                    .url(dohUrl)
                    .header("Accept", "application/dns-message")
                    .post(dnsPayload.toRequestBody(DNS_MEDIA_TYPE))
                    .build()

                executeAndParse(request, "DoH POST")
            } catch (e: Exception) {
                Timber.e("DoH POST failed: $e")
                null
            }
        }

    /**
     * Execute an OkHttp request using async enqueue + suspendCancellableCoroutine
     * to avoid blocking threads, and parse the DNS response.
     */
    private suspend fun executeAndParse(request: Request, label: String): ByteArray? {
        return withTimeoutOrNull(QUERY_TIMEOUT_MS) {
            val response = getClient().newCall(request).await()

            response.use { resp ->
                val protocol = resp.protocol
                if (!resp.isSuccessful) {
                    Timber.w("$label returned ${resp.code} via $protocol")
                    return@withTimeoutOrNull null
                }

                val bytes = resp.body.bytes()
                if (bytes.size < 12) {
                    Timber.w("$label response invalid: ${bytes.size} bytes")
                    return@withTimeoutOrNull null
                }

                Timber.d("$label ok: ${bytes.size} bytes via $protocol")
                bytes
            }
        }
    }

    /**
     * Extension to convert OkHttp's blocking Call into a suspend function
     * using enqueue() for proper coroutine cancellation support.
     *
     * Unlike execute() which blocks the thread and can't be interrupted
     * by withTimeout, enqueue() is truly async and cancel() propagates correctly.
     */
    private suspend fun Call.await(): Response = suspendCancellableCoroutine { continuation ->
        enqueue(object : Callback {
            override fun onResponse(call: Call, response: Response) {
                continuation.resume(response)
            }

            override fun onFailure(call: Call, e: IOException) {
                if (continuation.isCancelled) return
                continuation.resumeWithException(e)
            }
        })

        continuation.invokeOnCancellation {
            try {
                cancel()
            } catch (ex: Throwable) {
                Timber.w("Failed to cancel OkHttp call: $ex")
            }
        }
    }

    /**
     * SocketFactory that protects every socket from VPN routing via [VpnService.protect].
     *
     * CRITICAL: Must create an unconnected socket, call protect(), then connect().
     * Using Socket(host, port) would connect immediately BEFORE protect() is called,
     * causing a VPN routing loop.
     */
    private class ProtectedSocketFactory(
        private val vpnService: VpnService
    ) : SocketFactory() {

        override fun createSocket(): Socket {
            return Socket().also { vpnService.protect(it) }
        }

        override fun createSocket(host: String?, port: Int): Socket {
            val socket = createSocket()
            socket.connect(InetSocketAddress(host, port))
            return socket
        }

        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket {
            val socket = createSocket()
            socket.bind(InetSocketAddress(localHost, localPort))
            socket.connect(InetSocketAddress(host, port))
            return socket
        }

        override fun createSocket(host: InetAddress?, port: Int): Socket {
            val socket = createSocket()
            socket.connect(InetSocketAddress(host, port))
            return socket
        }

        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket {
            val socket = createSocket()
            socket.bind(InetSocketAddress(localAddress, localPort))
            socket.connect(InetSocketAddress(address, port))
            return socket
        }
    }
}
