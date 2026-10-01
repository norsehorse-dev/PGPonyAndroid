// SocksBridgeTest.kt
// SUPPLY-1 and SUPPLY-6: the loopback bridge HttpClientFactory uses for a SOCKS
// proxy must hand the proxy the host NAME (SOCKS5 address type 3), never an
// address looked up here, and must never offer user/password sign-in (where a
// JVM would fall back to the OS login name) unless the user set a pair.
// "localhost" is the probe: it resolves locally, so a lookup before the SOCKS
// handshake would show up as address type 1.

package com.pgpony.android.network

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

class SocksBridgeTest {

    private class Seen(val methods: List<Int>, val user: String?, val atyp: Int, val host: String, val port: Int)

    // Picks user/password whenever it is offered (as a hostile listener would), else no-auth.
    private class FakeSocks : AutoCloseable {
        val server = ServerSocket(0, 50, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
        val seen = CopyOnWriteArrayList<Seen>()

        init {
            val t = Thread {
                while (!server.isClosed) {
                    val s = try { server.accept() } catch (e: IOException) { break }
                    val w = Thread { try { serve(s) } catch (e: IOException) { } finally { s.close() } }
                    w.isDaemon = true
                    w.start()
                }
            }
            t.isDaemon = true
            t.start()
        }

        private fun serve(s: Socket) {
            s.soTimeout = 5_000
            val input = DataInputStream(s.getInputStream())
            val out = s.getOutputStream()
            input.readUnsignedByte()
            val methods = (0 until input.readUnsignedByte()).map { input.readUnsignedByte() }
            var user: String? = null
            if (2 in methods) {
                out.write(byteArrayOf(5, 2))
                input.readUnsignedByte()
                user = String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) })
                input.readFully(ByteArray(input.readUnsignedByte()))
                out.write(byteArrayOf(1, 0))
            } else {
                out.write(byteArrayOf(5, 0))
            }
            input.readUnsignedByte(); input.readUnsignedByte(); input.readUnsignedByte()
            val atyp = input.readUnsignedByte()
            val host = when (atyp) {
                1 -> ByteArray(4).also { input.readFully(it) }.joinToString(".") { (it.toInt() and 0xff).toString() }
                3 -> String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) })
                else -> return
            }
            val port = (input.readUnsignedByte() shl 8) or input.readUnsignedByte()
            seen.add(Seen(methods, user, atyp, host, port))
            out.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            out.flush()
            if (SocksBridge.readHead(input, 64 * 1024) != null) {
                out.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toByteArray())
                out.flush()
            }
        }

        override fun close() = server.close()
    }

    private val fake = FakeSocks()
    private val bridges = ArrayList<SocksBridge>()

    @After
    fun tearDown() {
        bridges.forEach { it.close() }
        fake.close()
    }

    private fun bridge(user: String? = null, pass: String? = null): SocksBridge =
        SocksBridge("127.0.0.1", fake.server.localPort, user, pass, 5_000).also { bridges.add(it) }

    /** Send [request] to the bridge and return everything it answers. */
    private fun exchange(b: SocksBridge, request: String): String {
        Socket(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), b.port).use { s ->
            s.soTimeout = 5_000
            s.getOutputStream().write(request.toByteArray(Charsets.ISO_8859_1))
            s.getOutputStream().flush()
            val out = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            try {
                while (true) {
                    val n = s.getInputStream().read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (request.startsWith("CONNECT") && out.toString("ISO-8859-1").contains("\r\n\r\n")) break
                }
            } catch (e: IOException) {
            }
            return out.toString("ISO-8859-1")
        }
    }

    @Test
    fun `SUPPLY-1 CONNECT reaches the proxy by name`() {
        val reply = exchange(bridge(), "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
        assertTrue(reply, reply.startsWith("HTTP/1.1 200"))
        val s = fake.seen.single()
        assertEquals(3, s.atyp)
        assertEquals("localhost", s.host)
        assertEquals(443, s.port)
    }

    @Test
    fun `SUPPLY-1 plain http reaches the proxy by name and is closed after one answer`() {
        val reply = exchange(
            bridge(),
            "GET http://localhost:8080/pks/lookup?op=get HTTP/1.1\r\nHost: localhost:8080\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        assertTrue(reply, reply.startsWith("HTTP/1.1 200 OK"))
        assertTrue(reply, reply.contains("\r\nConnection: close\r\n"))
        assertTrue(reply, reply.endsWith("ok"))
        val s = fake.seen.single()
        assertEquals(3, s.atyp)
        assertEquals("localhost", s.host)
        assertEquals(8080, s.port)
    }

    @Test
    fun `SUPPLY-1 a dead proxy answers 502`() {
        val dead = ServerSocket(0).use { it.localPort }
        val b = SocksBridge("127.0.0.1", dead, null, null, 2_000).also { bridges.add(it) }
        assertTrue(exchange(b, "CONNECT localhost:443 HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 502"))
    }

    @Test
    fun `SUPPLY-1 onion links need a proxy`() {
        val link = "http://abcdefghij234567.onion/key.asc"
        assertNotNull(UrlKeyFetcher.allowedUri(link, onionReachable = true))
        assertNull(UrlKeyFetcher.allowedUri(link, onionReachable = false))
        assertNotNull(UrlKeyFetcher.allowedUri("https://example.org/key.asc", onionReachable = false))
    }

    @Test
    fun `SUPPLY-6 without a pair only no-auth is offered`() {
        exchange(bridge(), "CONNECT localhost:443 HTTP/1.1\r\n\r\n")
        val s = fake.seen.single()
        assertEquals(listOf(0), s.methods)
        assertNull(s.user)
    }

    @Test
    fun `SUPPLY-6 a set pair is used`() {
        exchange(bridge("isolation-id", "secret"), "CONNECT localhost:443 HTTP/1.1\r\n\r\n")
        assertEquals("isolation-id", fake.seen.single().user)
    }

    @Test
    fun `address types`() {
        fun enc(host: String) = ByteArrayOutputStream().also { SocksBridge.writeAddress(it, host) }.toByteArray()
        assertEquals(1, enc("192.0.2.1")[0].toInt())
        assertEquals(4, enc("[2001:db8::1]")[0].toInt())
        assertEquals(3, enc("keys.openpgp.org")[0].toInt())
        assertEquals(17, enc("::1").size)
    }

    @Test
    fun `IPv6 literals are parsed by hand and look-alikes are refused`() {
        val loop = SocksBridge.parseIpv6("::1")!!
        assertEquals(16, loop.size)
        assertEquals(1, loop[15].toInt())
        val mapped = SocksBridge.parseIpv6("::ffff:192.0.2.1")!!
        assertEquals(-1, mapped[10].toInt())
        assertEquals(192, mapped[12].toInt() and 0xff)
        assertEquals(0x20, SocksBridge.parseIpv6("2001:db8::1")!![0].toInt())
        for (bad in listOf("", ":::", "abc:def", "1::2::3", "1:2:3:4:5:6:7:8:9", "12345::", "1.2.3.4::", "fe80::1%eth0")) {
            assertNull(bad, SocksBridge.parseIpv6(bad))
        }
        try {
            SocksBridge.writeAddress(ByteArrayOutputStream(), "[abc:def]")
            org.junit.Assert.fail("a look-alike IPv6 literal must be refused")
        } catch (e: IOException) {
        }
    }
}
