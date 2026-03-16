package app.pwhs.blockads.util

import app.pwhs.blockads.data.entities.WireGuardConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class WireGuardConfigParserTest {

    private val validSinglePeer = """
        [Interface]
        PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
        Address = 10.200.200.2/32, fd86:ea04:1111::2/128
        ListenPort = 51820
        DNS = 1.1.1.1, 8.8.8.8

        [Peer]
        PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
        PresharedKey = AABBCCDD==
        Endpoint = demo.wireguard.com:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
    """.trimIndent()

    @Test
    fun `parse valid single peer config`() {
        val config = WireGuardConfigParser.parse(validSinglePeer)

        // Interface
        assertEquals("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", config.interfaceConfig.privateKey)
        assertEquals(listOf("10.200.200.2/32", "fd86:ea04:1111::2/128"), config.interfaceConfig.address)
        assertEquals(51820, config.interfaceConfig.listenPort)
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), config.interfaceConfig.dns)

        // Peer
        assertEquals(1, config.peers.size)
        val peer = config.peers[0]
        assertEquals("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", peer.publicKey)
        assertEquals("AABBCCDD==", peer.presharedKey)
        assertEquals("demo.wireguard.com:51820", peer.endpoint)
        assertEquals(listOf("0.0.0.0/0", "::/0"), peer.allowedIPs)
        assertEquals(25, peer.persistentKeepalive)
    }

    @Test
    fun `parse multi-peer config`() {
        val raw = """
            [Interface]
            PrivateKey = abc123=
            Address = 10.0.0.1/24

            [Peer]
            PublicKey = peer1key=
            Endpoint = 1.2.3.4:51820
            AllowedIPs = 10.0.0.0/24

            [Peer]
            PublicKey = peer2key=
            Endpoint = 5.6.7.8:51820
            AllowedIPs = 10.0.1.0/24
        """.trimIndent()

        val config = WireGuardConfigParser.parse(raw)
        assertEquals(2, config.peers.size)
        assertEquals("peer1key=", config.peers[0].publicKey)
        assertEquals("peer2key=", config.peers[1].publicKey)
    }

    @Test
    fun `parse skips comments and blank lines`() {
        val raw = """
            # This is a comment
            [Interface]
            # Another comment
            PrivateKey = mykey=
            Address = 10.0.0.1/24
            
            
            [Peer]
            # Peer comment
            PublicKey = peerkey=
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()

        val config = WireGuardConfigParser.parse(raw)
        assertEquals("mykey=", config.interfaceConfig.privateKey)
        assertEquals(1, config.peers.size)
        assertEquals("peerkey=", config.peers[0].publicKey)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parse throws on missing PrivateKey`() {
        val raw = """
            [Interface]
            Address = 10.0.0.1/24

            [Peer]
            PublicKey = peerkey=
        """.trimIndent()

        WireGuardConfigParser.parse(raw)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parse throws on missing Address`() {
        val raw = """
            [Interface]
            PrivateKey = mykey=

            [Peer]
            PublicKey = peerkey=
        """.trimIndent()

        WireGuardConfigParser.parse(raw)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parse throws on missing PublicKey in peer`() {
        val raw = """
            [Interface]
            PrivateKey = mykey=
            Address = 10.0.0.1/24

            [Peer]
            Endpoint = 1.2.3.4:51820
        """.trimIndent()

        WireGuardConfigParser.parse(raw)
    }

    @Test
    fun `parse handles optional fields absent`() {
        val raw = """
            [Interface]
            PrivateKey = mykey=
            Address = 10.0.0.1/24

            [Peer]
            PublicKey = peerkey=
        """.trimIndent()

        val config = WireGuardConfigParser.parse(raw)

        // Optional interface fields
        assertNull(config.interfaceConfig.listenPort)
        assertEquals(emptyList<String>(), config.interfaceConfig.dns)

        // Optional peer fields
        val peer = config.peers[0]
        assertNull(peer.presharedKey)
        assertNull(peer.endpoint)
        assertNull(peer.persistentKeepalive)
        assertEquals(emptyList<String>(), peer.allowedIPs)
    }

    @Test
    fun `parse handles extra whitespace around keys and values`() {
        val raw = """
            [Interface]
              PrivateKey  =  mykey=  
              Address  =  10.0.0.1/24 , 10.0.0.2/24  
            
            [Peer]
              PublicKey  =  peerkey=  
              AllowedIPs  =  0.0.0.0/0  
        """.trimIndent()

        val config = WireGuardConfigParser.parse(raw)
        assertEquals("mykey=", config.interfaceConfig.privateKey)
        assertEquals(listOf("10.0.0.1/24", "10.0.0.2/24"), config.interfaceConfig.address)
        assertEquals("peerkey=", config.peers[0].publicKey)
    }

    @Test
    fun `parse handles case-insensitive section headers`() {
        val raw = """
            [interface]
            PrivateKey = mykey=
            Address = 10.0.0.1/24

            [PEER]
            PublicKey = peerkey=
        """.trimIndent()

        val config = WireGuardConfigParser.parse(raw)
        assertNotNull(config)
        assertEquals("mykey=", config.interfaceConfig.privateKey)
        assertEquals(1, config.peers.size)
    }
}
