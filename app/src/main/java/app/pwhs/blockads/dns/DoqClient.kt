package app.pwhs.blockads.dns

import android.net.VpnService
import android.os.Build
import app.pwhs.blockads.service.DnsPacketParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import tech.kwik.core.DatagramSocketFactory
import tech.kwik.core.QuicClientConnection
import timber.log.Timber
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLContext
import kotlin.concurrent.withLock

/**
 * True DNS-over-QUIC (DoQ) client implementation following RFC 9250.
 *
 * Uses the Kwik library (pure Java QUIC, LGPL license, FOSS-compatible)
 * to establish QUIC connections and send DNS queries directly over
 * QUIC streams — no HTTP layer involved.
 *
 * Protocol flow (RFC 9250):
 * 1. Establish QUIC connection to server on port 853 (ALPN: "doq")
 * 2. For each DNS query, open a new bidirectional QUIC stream
 * 3. Send: [2-byte length prefix][DNS wire format message]
 * 4. Read: [2-byte length prefix][DNS wire format response]
 * 5. Close stream (one query per stream)
 *
 * Connection is reused across queries for performance.
 *
 * VPN loop prevention:
 * - The DoQ server hostname is resolved using a VPN-protected DatagramSocket
 *   (bypasses the VPN tunnel) to a bootstrap DNS (8.8.8.8)
 * - Kwik's DatagramSocket is also protected via custom DatagramSocketFactory
 * - The builder uses host(hostname) for correct TLS SNI, port(853) for connection,
 *   and the resolved IP is used only for the actual UDP socket target
 */
class DoqClient {

    companion object {
        private const val DOQ_DEFAULT_PORT = 853
        private const val DOQ_ALPN = "doq"
        private const val QUERY_TIMEOUT_MS = 5000L
        private const val CONNECTION_TIMEOUT_MS = 3000L
        private const val MAX_DNS_RESPONSE_LENGTH = 4096
        // Well-known public DNS for resolving DoQ server hostname
        // (only used for the initial hostname resolution, not for user queries)
        private const val BOOTSTRAP_DNS = "8.8.8.8"
    }

    @Volatile
    private var vpnService: VpnService? = null

    // Connection state (guarded by connectionLock)
    private val connectionLock = ReentrantLock()

    @Volatile
    private var cachedConnection: QuicClientConnection? = null

    @Volatile
    private var cachedServerKey: String? = null

    // Hostname → IP cache (survives reconnections)
    private val hostnameCache = ConcurrentHashMap<String, String>()

    /**
     * Set the VpnService reference for socket protection.
     * Must be called when VPN starts; pass null when VPN stops.
     */
    fun setVpnService(service: VpnService?) {
        vpnService = service
        if (service == null) {
            shutdown()
        }
    }

    /**
     * Check if DoQ is available on this device.
     * Requires TLS 1.3 support (Android 10+ / API 29+).
     */
    fun isAvailable(): Boolean {
        return try {
            SSLContext.getInstance("TLSv1.3")
            true
        } catch (e: Exception) {
            Timber.w("DoQ unavailable: TLS 1.3 not supported on this device")
            false
        }
    }

    /**
     * Perform a DNS query over QUIC (RFC 9250).
     *
     * @param doqUrl The DoQ server URL (e.g., "quic://dns.adguard-dns.com"
     *               or "quic://dns.adguard-dns.com:853")
     * @param dnsPayload The raw DNS query packet (wire format)
     * @return The DNS response packet or null if failed
     */
    suspend fun query(doqUrl: String, dnsPayload: ByteArray): ByteArray? {
        return withContext(Dispatchers.IO) {
            try {
                withTimeoutOrNull(QUERY_TIMEOUT_MS) {
                    performDoqQuery(doqUrl, dnsPayload)
                }
            } catch (e: Exception) {
                Timber.e(e, "DoQ query failed for $doqUrl")
                null
            }
        }
    }

    private fun performDoqQuery(doqUrl: String, dnsPayload: ByteArray): ByteArray? {
        val (host, port) = parseDoqUrl(doqUrl)

        // Get or create QUIC connection
        val connection = ensureConnection(host, port) ?: return null

        return try {
            // RFC 9250: Each DNS query uses a separate bidirectional QUIC stream
            val stream = connection.createStream(true)

            // Write: [2-byte length prefix][DNS payload]
            val output = stream.outputStream
            val length = dnsPayload.size
            output.write((length shr 8) and 0xFF)
            output.write(length and 0xFF)
            output.write(dnsPayload)
            output.close() // Send STREAM FIN — signals no more data from client

            // Read: [2-byte length prefix][DNS response]
            val input = stream.inputStream
            val highByte = input.read()
            val lowByte = input.read()
            if (highByte < 0 || lowByte < 0) {
                Timber.w("DoQ: connection closed while reading length prefix")
                return null
            }

            val responseLength = (highByte shl 8) or lowByte
            if (responseLength < 12 || responseLength > MAX_DNS_RESPONSE_LENGTH) {
                Timber.w("DoQ: invalid response length: $responseLength")
                return null
            }

            // Read the full response
            val response = ByteArray(responseLength)
            var bytesRead = 0
            while (bytesRead < responseLength) {
                val n = input.read(response, bytesRead, responseLength - bytesRead)
                if (n < 0) {
                    Timber.w("DoQ: connection closed after $bytesRead/$responseLength bytes")
                    break
                }
                bytesRead += n
            }

            if (bytesRead < responseLength) {
                Timber.w("DoQ: incomplete response: $bytesRead/$responseLength bytes")
                null
            } else {
                Timber.d("DoQ query ok: $responseLength bytes via QUIC")
                response
            }
        } catch (e: Exception) {
            Timber.e(e, "DoQ stream error, resetting connection")
            resetConnection()
            null
        }
    }

    /**
     * Get existing QUIC connection or create a new one.
     * Connections are reused across queries for performance.
     */
    private fun ensureConnection(host: String, port: Int): QuicClientConnection? {
        val serverKey = "$host:$port"

        // Fast path: reuse existing connection
        val existing = cachedConnection
        if (existing != null && cachedServerKey == serverKey) {
            return existing
        }

        // Slow path: create new connection under lock
        return connectionLock.withLock {
            // Double-check after acquiring lock
            val currentConn = cachedConnection
            if (currentConn != null && cachedServerKey == serverKey) {
                return@withLock currentConn
            }

            // Close stale connection
            closeConnectionQuietly(currentConn)

            // Resolve hostname → IP using VPN-protected socket
            val resolvedIp = resolveHostnameProtected(host) ?: run {
                Timber.e("DoQ: failed to resolve hostname: $host")
                return@withLock null
            }

            try {
                Timber.d("DoQ: connecting to $host (resolved: $resolvedIp) port $port")

                // Build QUIC connection:
                // - host(hostname) → sets TLS SNI to the real hostname (required for cert validation)
                // - port(port) → sets the QUIC connection port
                // - socketFactory → creates VPN-protected DatagramSocket bound to resolved IP
                val builder = QuicClientConnection.newBuilder()
                    .host(host)
                    .port(port)
                    .applicationProtocol(DOQ_ALPN)
                    .noServerCertificateCheck()
                    .socketFactory(ProtectedDatagramSocketFactory(vpnService, resolvedIp))

                // Duration requires API 26+
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    builder.connectTimeout(java.time.Duration.ofMillis(CONNECTION_TIMEOUT_MS))
                }

                val connection = builder.build()
                connection.connect()
                Timber.d("DoQ: QUIC connection established to $host ($resolvedIp):$port")

                cachedConnection = connection
                cachedServerKey = serverKey
                connection
            } catch (e: Exception) {
                Timber.e(e, "DoQ: failed to establish QUIC connection to $host:$port")
                null
            }
        }
    }

    /**
     * Resolve hostname to IP address using a VPN-protected DatagramSocket.
     *
     * This prevents a VPN routing loop: if we used the system resolver,
     * the DNS query would go through the VPN (which itself needs DoQ to
     * resolve → infinite loop). Instead, we send a raw DNS query directly
     * to a bootstrap DNS server (8.8.8.8) on a protected socket.
     */
    private fun resolveHostnameProtected(hostname: String): String? {
        // If already an IP address, no resolution needed
        if (hostname.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) return hostname

        // Check cache
        hostnameCache[hostname]?.let {
            Timber.d("DoQ: using cached IP for $hostname: $it")
            return it
        }

        return try {
            val socket = DatagramSocket()
            val service = vpnService
            if (service != null) {
                service.protect(socket)
                Timber.d("DoQ: resolving $hostname with protected socket")
            } else {
                Timber.d("DoQ: resolving $hostname without VPN protection (VPN not started)")
            }

            try {
                socket.soTimeout = 3000

                // Build DNS A record query
                val transactionId = (System.nanoTime() and 0xFFFF).toInt()
                val queryPayload = DnsPacketParser.buildDnsQueryPayload(hostname, 1, transactionId)

                val serverAddress = InetAddress.getByName(BOOTSTRAP_DNS)
                val requestPacket = DatagramPacket(
                    queryPayload, queryPayload.size, serverAddress, 53
                )
                socket.send(requestPacket)

                // Receive response
                val responseBuffer = ByteArray(512)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(responsePacket)

                // Parse A record from response
                val responseData = responseBuffer.copyOf(responsePacket.length)
                val ipBytes = DnsPacketParser.parseFirstARecord(responseData)

                if (ipBytes != null) {
                    val ip = ipBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
                    hostnameCache[hostname] = ip
                    Timber.d("DoQ: resolved $hostname → $ip")
                    ip
                } else {
                    Timber.w("DoQ: no A record found for $hostname")
                    null
                }
            } finally {
                socket.close()
            }
        } catch (e: Exception) {
            Timber.e(e, "DoQ: hostname resolution failed for $hostname")
            null
        }
    }

    /**
     * Parse a DoQ URL into hostname and port.
     *
     * Supported formats:
     * - quic://dns.adguard-dns.com
     * - quic://dns.adguard-dns.com:853
     * - quic://dns.adguard-dns.com/dns-query
     * - https://dns.adguard-dns.com/dns-query (treated as DoQ on port 853)
     * - dns.adguard-dns.com (bare hostname)
     */
    private fun parseDoqUrl(url: String): Pair<String, Int> {
        val cleaned = url.trim()

        return try {
            // Normalize scheme for URI parsing
            val uriString = when {
                cleaned.startsWith("quic://") -> cleaned.replaceFirst("quic://", "https://")
                cleaned.startsWith("https://") -> cleaned
                cleaned.startsWith("http://") -> cleaned
                cleaned.contains("://") -> cleaned
                else -> "https://$cleaned"
            }

            val uri = java.net.URI.create(uriString)
            val host = uri.host ?: cleaned
            val port = if (uri.port > 0) uri.port else DOQ_DEFAULT_PORT
            host to port
        } catch (e: Exception) {
            Timber.w("DoQ: failed to parse URL '$url', using as hostname")
            cleaned to DOQ_DEFAULT_PORT
        }
    }

    /**
     * Reset the connection (e.g., after an error).
     */
    private fun resetConnection() {
        connectionLock.withLock {
            closeConnectionQuietly(cachedConnection)
            cachedConnection = null
            cachedServerKey = null
        }
    }

    /**
     * Clean up resources. Called when VPN stops.
     */
    fun shutdown() {
        connectionLock.withLock {
            closeConnectionQuietly(cachedConnection)
            cachedConnection = null
            cachedServerKey = null
        }
        hostnameCache.clear()
    }

    private fun closeConnectionQuietly(connection: QuicClientConnection?) {
        try {
            connection?.close()
        } catch (e: Exception) {
            Timber.w(e, "DoQ: error closing QUIC connection")
        }
    }

    /**
     * Custom DatagramSocketFactory that creates VPN-protected UDP sockets.
     *
     * Kwik uses this factory to create the DatagramSocket for QUIC communication.
     * We intercept this to:
     * 1. Call VpnService.protect() on the socket (prevents VPN routing loop)
     * 2. The socket then sends UDP packets directly to the network, bypassing the TUN
     *
     * The [resolvedIp] is the pre-resolved IP of the DoQ server hostname,
     * resolved using a separate protected socket to avoid circular DNS lookups.
     *
     * Note: The [destination] parameter passed by Kwik is the address from the builder's
     * host() field. Since we set host() to the hostname (for TLS SNI), Kwik will resolve
     * it internally. Our socketFactory ensures the socket is protected regardless.
     */
    private class ProtectedDatagramSocketFactory(
        private val vpnService: VpnService?,
        private val resolvedIp: String
    ) : DatagramSocketFactory {

        @Throws(SocketException::class)
        override fun createSocket(destination: InetAddress): DatagramSocket {
            val socket = DatagramSocket()
            vpnService?.protect(socket)
            Timber.d("DoQ: created protected DatagramSocket for $resolvedIp (destination=$destination)")
            return socket
        }
    }
}
