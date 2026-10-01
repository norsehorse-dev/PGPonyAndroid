// SocksBridge.kt
// PGPony: carry HTTP and HTTPS over a SOCKS5 proxy with the host name resolved
// by the proxy, never on this device.
//
// The platform HTTP stack under ktor's Android engine (HttpURLConnection)
// looks a target host up on the local resolver before it opens a SOCKS
// connection, so with a plain SOCKS proxy setting every host name would leave
// in a local DNS query, and the proxy would be asked for an address the local
// network picked. Instead, HttpClientFactory points the client at this bridge
// as an HTTP proxy on the loopback interface. The client then names the host
// inside the request (CONNECT host:port for https, the absolute URL for plain
// http), and the bridge opens the SOCKS5 connection with that name as a domain
// address, so only the proxy resolves it. TLS stays end to end between the
// client and the server; the bridge only copies bytes.
//
// The bridge also runs the SOCKS5 handshake itself. It offers user/password
// only when the user set a pair (stream isolation) and otherwise offers no
// authentication at all, so the platform's fallback of sending the OS login
// name as the SOCKS user name can never happen.
//
// Plain JVM code (java.net only), shared by the Android app and the desktop
// build. A dead proxy fails the request; there is no direct fallback.

package com.pgpony.android.network

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

class SocksBridge(
    private val socksHost: String,
    private val socksPort: Int,
    private val username: String? = null,
    private val password: String? = null,
    private val connectTimeoutMs: Int = DEFAULT_CONNECT_TIMEOUT_MS,
    private val idleTimeoutMs: Int = DEFAULT_IDLE_TIMEOUT_MS
) : Closeable {

    // 127.0.0.1 built from its bytes, so neither binding nor the client's
    // connection to the bridge needs a name lookup (not even "localhost").
    private val loopback: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val server = ServerSocket(0, 50, loopback)
    private val active = AtomicInteger(0)
    @Volatile private var closed = false

    /** The local port the bridge listens on. */
    val port: Int get() = server.localPort

    /** The proxy to hand the HTTP engine: an HTTP proxy at the bridge. */
    val proxy: Proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress(loopback, server.localPort))

    init {
        val t = Thread({ acceptLoop() }, "pgpony-socks-bridge")
        t.isDaemon = true
        t.start()
    }

    /** Stop accepting new connections. Connections already open finish on their own. */
    override fun close() {
        closed = true
        closeQuietly(server)
    }

    private fun acceptLoop() {
        while (!closed) {
            val client = try {
                server.accept()
            } catch (e: IOException) {
                if (closed) return
                try { Thread.sleep(50) } catch (ie: InterruptedException) { return }
                continue
            }
            if (active.incrementAndGet() > MAX_CONNECTIONS) {
                active.decrementAndGet()
                closeQuietly(client)
                continue
            }
            val worker = Thread({
                try {
                    handle(client)
                } catch (e: Exception) {
                    // A broken connection only ends that connection.
                } finally {
                    active.decrementAndGet()
                    closeQuietly(client)
                }
            }, "pgpony-socks-bridge-conn")
            worker.isDaemon = true
            worker.start()
        }
    }

    private fun handle(client: Socket) {
        client.soTimeout = idleTimeoutMs
        client.tcpNoDelay = true
        val clientIn = BufferedInputStream(client.getInputStream(), BUFFER_BYTES)
        val clientOut = client.getOutputStream()
        val head = readHead(clientIn, MAX_HEAD_BYTES) ?: return reply(clientOut, 400, "Bad Request")
        val lines = head.split("\r\n")
        val requestLine = lines[0].split(' ')
        if (requestLine.size != 3) return reply(clientOut, 400, "Bad Request")
        val method = requestLine[0]
        val target = requestLine[1]
        val version = requestLine[2]

        if (method.equals("CONNECT", ignoreCase = true)) {
            val hostPort = splitHostPort(target, -1) ?: return reply(clientOut, 400, "Bad Request")
            val upstream = try {
                openSocks(hostPort.first, hostPort.second)
            } catch (e: IOException) {
                return reply(clientOut, 502, "Bad Gateway")
            }
            try {
                clientOut.write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                clientOut.flush()
                relay(client, clientIn, upstream, BufferedInputStream(upstream.getInputStream(), BUFFER_BYTES), false)
            } finally {
                closeQuietly(upstream)
            }
            return
        }

        // Plain http through a proxy: the request line carries the absolute URL.
        val absolute = parseAbsoluteHttp(target) ?: return reply(clientOut, 400, "Bad Request")
        val upstream = try {
            openSocks(absolute.host, absolute.port)
        } catch (e: IOException) {
            return reply(clientOut, 502, "Bad Gateway")
        }
        try {
            val out = StringBuilder()
            out.append(method).append(' ').append(absolute.path).append(' ').append(version).append("\r\n")
            var hasHost = false
            for (i in 1 until lines.size) {
                val line = lines[i]
                if (line.isEmpty()) continue
                val name = line.substringBefore(':').trim().lowercase()
                if (name in HOP_HEADERS) continue
                if (name == "host") hasHost = true
                out.append(line).append("\r\n")
            }
            if (!hasHost) out.append("Host: ").append(absolute.authority).append("\r\n")
            // One request per connection: the client may not reuse it for another host.
            out.append("Connection: close\r\n\r\n")
            val upOut = upstream.getOutputStream()
            upOut.write(out.toString().toByteArray(Charsets.ISO_8859_1))
            upOut.flush()
            relay(client, clientIn, upstream, BufferedInputStream(upstream.getInputStream(), BUFFER_BYTES), true)
        } finally {
            closeQuietly(upstream)
        }
    }

    /**
     * Copy bytes both ways until the server side ends. With [rewriteResponse]
     * the response head is passed through with "Connection: close" so the
     * client never sends a second request down this connection.
     */
    private fun relay(client: Socket, clientIn: InputStream, upstream: Socket, upstreamIn: InputStream, rewriteResponse: Boolean) {
        // The server side carries the idle limit; the client may wait as long
        // as the server takes to answer.
        client.soTimeout = 0
        upstream.soTimeout = idleTimeoutMs
        val up = Thread({
            try {
                pump(clientIn, upstream.getOutputStream())
            } catch (e: IOException) {
                // The server side is already closed.
            }
            shutdownOutput(upstream)
        }, "pgpony-socks-bridge-up")
        up.isDaemon = true
        up.start()
        try {
            val clientOut = client.getOutputStream()
            if (rewriteResponse) {
                val head = readHead(upstreamIn, MAX_HEAD_BYTES) ?: return
                clientOut.write(closingResponseHead(head).toByteArray(Charsets.ISO_8859_1))
                clientOut.flush()
            }
            pump(upstreamIn, clientOut)
        } catch (e: IOException) {
            // Either side went away: the connection is over.
        } finally {
            shutdownOutput(client)
        }
    }

    /**
     * Open a connection to [host]:[port] through the SOCKS5 proxy. A host
     * name is sent to the proxy as a name (address type 3) and never looked
     * up here; an IP literal is sent as an address.
     */
    internal fun openSocks(host: String, port: Int): Socket {
        val s = Socket(Proxy.NO_PROXY)
        try {
            s.connect(InetSocketAddress(socksHost, socksPort), connectTimeoutMs)
            s.soTimeout = connectTimeoutMs
            s.tcpNoDelay = true
            val out = s.getOutputStream()
            val input = DataInputStream(s.getInputStream())
            val user = username
            val pass = password
            val withAuth = !user.isNullOrEmpty() && !pass.isNullOrEmpty()

            // Greeting: no-auth only, or no-auth and user/password when a pair is set.
            out.write(if (withAuth) byteArrayOf(5, 2, 0, 2) else byteArrayOf(5, 1, 0))
            out.flush()
            if (input.readUnsignedByte() != 5) throw IOException("The proxy is not a SOCKS5 proxy")
            when (input.readUnsignedByte()) {
                0 -> Unit
                2 -> {
                    if (!withAuth) throw IOException("The SOCKS proxy asks for a user name and password, and none is set")
                    val u = user!!.toByteArray(Charsets.UTF_8)
                    val p = pass!!.toByteArray(Charsets.UTF_8)
                    if (u.size > 255 || p.size > 255) throw IOException("The SOCKS user name or password is too long")
                    val auth = ByteArrayOutputStream()
                    auth.write(1)
                    auth.write(u.size)
                    auth.write(u)
                    auth.write(p.size)
                    auth.write(p)
                    out.write(auth.toByteArray())
                    out.flush()
                    input.readUnsignedByte()
                    if (input.readUnsignedByte() != 0) throw IOException("The SOCKS proxy did not accept the user name and password")
                }
                else -> throw IOException("The SOCKS proxy did not accept any sign-in method offered")
            }

            val request = ByteArrayOutputStream()
            request.write(5)
            request.write(1) // CONNECT
            request.write(0)
            writeAddress(request, host)
            request.write((port shr 8) and 0xff)
            request.write(port and 0xff)
            out.write(request.toByteArray())
            out.flush()

            if (input.readUnsignedByte() != 5) throw IOException("The proxy is not a SOCKS5 proxy")
            val rep = input.readUnsignedByte()
            input.readUnsignedByte()
            val atyp = input.readUnsignedByte()
            if (rep != 0) throw IOException("The SOCKS proxy could not connect (${replyText(rep)})")
            val boundLength = when (atyp) {
                1 -> 4
                4 -> 16
                3 -> input.readUnsignedByte()
                else -> throw IOException("The SOCKS proxy sent an unknown address type")
            }
            input.readFully(ByteArray(boundLength + 2))
            s.soTimeout = idleTimeoutMs
            return s
        } catch (e: IOException) {
            closeQuietly(s)
            throw e
        }
    }

    internal class AbsoluteHttp(val host: String, val port: Int, val authority: String, val path: String)

    companion object {
        const val DEFAULT_CONNECT_TIMEOUT_MS = 30_000
        const val DEFAULT_IDLE_TIMEOUT_MS = 120_000
        private const val MAX_CONNECTIONS = 64
        private const val MAX_HEAD_BYTES = 64 * 1024
        private const val BUFFER_BYTES = 16 * 1024
        private val HOP_HEADERS = setOf("connection", "keep-alive", "proxy-connection", "proxy-authorization")
        private val IPV4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")
        private val IPV6_CHARS = Regex("^[0-9A-Fa-f:.]+$")

        /** Address type and bytes for [host]: IPv4 (1), IPv6 (4) or a name (3). */
        internal fun writeAddress(out: ByteArrayOutputStream, host: String) {
            val bare = host.removePrefix("[").removeSuffix("]")
            if (bare.isEmpty()) throw IOException("No host name to connect to")
            val v4 = IPV4.matchEntire(bare)
            if (v4 != null) {
                val parts = v4.groupValues.drop(1).map { it.toInt() }
                if (parts.all { it in 0..255 }) {
                    out.write(1)
                    for (b in parts) out.write(b)
                    return
                }
                throw IOException("Not a valid IPv4 address")
            }
            if (bare.contains(':')) {
                // Parsed here by hand: a platform parser may fall back to a name
                // lookup for text it does not accept as an address.
                val bytes = parseIpv6(bare) ?: throw IOException("Not a valid IPv6 address")
                out.write(4)
                out.write(bytes)
                return
            }
            val ascii = try {
                IDN.toASCII(bare)
            } catch (e: IllegalArgumentException) {
                throw IOException("Not a valid host name")
            }
            val name = ascii.toByteArray(Charsets.US_ASCII)
            if (name.isEmpty() || name.size > 255) throw IOException("The host name is too long")
            out.write(3)
            out.write(name.size)
            out.write(name)
        }

        /**
         * The 16 bytes of an IPv6 literal (no brackets, no zone), or null when
         * [text] is not one. Accepts "::" compression and a dotted IPv4 tail.
         */
        internal fun parseIpv6(text: String): ByteArray? {
            if (text.isEmpty() || !IPV6_CHARS.matches(text)) return null
            val gap = text.indexOf("::")
            if (gap >= 0 && text.indexOf("::", gap + 1) >= 0) return null
            val head = if (gap >= 0) text.substring(0, gap) else text
            val tail = if (gap >= 0) text.substring(gap + 2) else ""
            val headWords = ipv6Words(head, gap < 0) ?: return null
            val tailWords = if (gap >= 0) (ipv6Words(tail, true) ?: return null) else emptyList()
            val count = headWords.size + tailWords.size
            if (gap < 0 && count != 8) return null
            if (gap >= 0 && count > 7) return null
            val words = IntArray(8)
            for (i in headWords.indices) words[i] = headWords[i]
            for (i in tailWords.indices) words[8 - tailWords.size + i] = tailWords[i]
            val out = ByteArray(16)
            for (i in 0 until 8) {
                out[2 * i] = (words[i] shr 8).toByte()
                out[2 * i + 1] = words[i].toByte()
            }
            return out
        }

        // 16-bit groups of one side of an IPv6 literal; a dotted IPv4 part is
        // allowed only as the last group of the whole address ([mayEndInV4]).
        private fun ipv6Words(part: String, mayEndInV4: Boolean): List<Int>? {
            if (part.isEmpty()) return emptyList()
            val groups = part.split(':')
            val words = ArrayList<Int>()
            for (i in groups.indices) {
                val g = groups[i]
                if (g.contains('.')) {
                    if (i != groups.size - 1 || !mayEndInV4) return null
                    val v4 = IPV4.matchEntire(g) ?: return null
                    val b = v4.groupValues.drop(1).map { it.toInt() }
                    if (b.any { it > 255 }) return null
                    words.add((b[0] shl 8) or b[1])
                    words.add((b[2] shl 8) or b[3])
                } else {
                    if (g.isEmpty() || g.length > 4) return null
                    words.add(g.toIntOrNull(16) ?: return null)
                }
            }
            return words
        }

        /** "host:port" or "[v6]:port" (CONNECT target or URL authority). */
        internal fun splitHostPort(authority: String, defaultPort: Int): Pair<String, Int>? {
            if (authority.isEmpty() || authority.contains('@')) return null
            val host: String
            val portText: String?
            if (authority.startsWith("[")) {
                val end = authority.indexOf(']')
                if (end < 0) return null
                host = authority.substring(1, end)
                val rest = authority.substring(end + 1)
                portText = when {
                    rest.isEmpty() -> null
                    rest.startsWith(":") -> rest.substring(1)
                    else -> return null
                }
            } else {
                val colon = authority.lastIndexOf(':')
                if (colon >= 0) {
                    host = authority.substring(0, colon)
                    portText = authority.substring(colon + 1)
                } else {
                    host = authority
                    portText = null
                }
                if (host.contains(':')) return null
            }
            val port = if (portText == null) defaultPort else (portText.toIntOrNull() ?: return null)
            if (host.isEmpty() || port !in 1..65535) return null
            return Pair(host, port)
        }

        /** The parts of an absolute "http://host[:port]/path" request target. */
        internal fun parseAbsoluteHttp(target: String): AbsoluteHttp? {
            if (!target.regionMatches(0, "http://", 0, 7, ignoreCase = true)) return null
            val rest = target.substring(7)
            var cut = rest.length
            for (i in rest.indices) {
                val c = rest[i]
                if (c == '/' || c == '?' || c == '#') {
                    cut = i
                    break
                }
            }
            val authority = rest.substring(0, cut)
            var path = rest.substring(cut).substringBefore('#')
            if (path.isEmpty()) path = "/"
            if (path.startsWith("?")) path = "/$path"
            val hostPort = splitHostPort(authority, 80) ?: return null
            return AbsoluteHttp(hostPort.first, hostPort.second, authority, path)
        }

        /** Read a header block up to the blank line; null on EOF or when it is too large. */
        internal fun readHead(input: InputStream, max: Int): String? {
            val buf = ByteArrayOutputStream(512)
            var state = 0
            while (buf.size() < max) {
                val b = input.read()
                if (b < 0) return null
                buf.write(b)
                state = when (b) {
                    '\r'.code -> if (state == 2) 3 else 1
                    '\n'.code -> if (state == 1) 2 else if (state == 3) 4 else 0
                    else -> 0
                }
                if (state == 4) {
                    val bytes = buf.toByteArray()
                    return String(bytes, 0, bytes.size - 4, Charsets.ISO_8859_1)
                }
            }
            return null
        }

        /** [head] with its connection headers replaced by "Connection: close". */
        internal fun closingResponseHead(head: String): String {
            val out = StringBuilder()
            val lines = head.split("\r\n")
            out.append(lines[0]).append("\r\n")
            for (i in 1 until lines.size) {
                val line = lines[i]
                if (line.isEmpty()) continue
                val name = line.substringBefore(':').trim().lowercase()
                if (name == "connection" || name == "keep-alive" || name == "proxy-connection") continue
                out.append(line).append("\r\n")
            }
            out.append("Connection: close\r\nProxy-Connection: close\r\n\r\n")
            return out.toString()
        }

        private fun replyText(rep: Int): String = when (rep) {
            1 -> "general failure"
            2 -> "not allowed by the proxy"
            3 -> "network unreachable"
            4 -> "host unreachable"
            5 -> "connection refused"
            6 -> "timed out"
            7 -> "command not supported"
            8 -> "address type not supported"
            else -> "error $rep"
        }

        private fun reply(out: OutputStream, code: Int, reason: String) {
            try {
                out.write(
                    "HTTP/1.1 $code $reason\r\nContent-Length: 0\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n"
                        .toByteArray(Charsets.ISO_8859_1)
                )
                out.flush()
            } catch (e: IOException) {
                // The client already left.
            }
        }

        private fun pump(input: InputStream, output: OutputStream) {
            val buf = ByteArray(BUFFER_BYTES)
            try {
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    output.write(buf, 0, n)
                    output.flush()
                }
            } catch (e: IOException) {
                // Either side went away.
            }
        }

        private fun shutdownOutput(s: Socket) {
            try {
                if (!s.isClosed && !s.isOutputShutdown) s.shutdownOutput()
            } catch (e: IOException) {
                // Already closed.
            }
        }

        private fun closeQuietly(c: Closeable) {
            try {
                c.close()
            } catch (e: IOException) {
                // Nothing to do.
            }
        }
    }
}
