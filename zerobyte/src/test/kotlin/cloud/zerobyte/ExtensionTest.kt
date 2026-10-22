package cloud.zerobyte

import com.sun.net.httpserver.HttpServer
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.CompletionStage
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

// The relay's extensions: push, rate limits, ICE and signal frames. Signal
// known answers come from the independent reference (relay-v1.json).
class ExtensionTest {
    private val v = JSONObject(javaClass.getResource("/relay-v1.json")!!.readText())
    private val s = v.getJSONObject("signal")

    private fun hex(text: String): ByteArray = ByteArray(text.length / 2) {
        text.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }

    private fun creds(i: Int): Credentials {
        val c = v.getJSONArray("credentials").getJSONObject(i)
        return Credentials(hex(c.getString("linkKey")), hex(c.getString("linkId")))
    }

    private fun JSONArray.objects() = (0 until length()).map { getJSONObject(it) }
    private fun direction(o: JSONObject) = Direction.of(o.getInt("direction").toByte())!!

    @Test
    fun signalKeysMatchTheVectors() {
        assertEquals(SignalFrame.WINDOW_MILLISECONDS, s.getLong("windowMilliseconds"))
        assertEquals(SignalFrame.MAX_FRAME_BYTES, s.getInt("maximumFrameBytes"))
        for ((i, keys) in s.getJSONArray("keys").objects().withIndex()) {
            assertEquals(keys.getString("p2cKey"), creds(i).signalKey(Direction.P2C).toHex())
            assertEquals(keys.getString("c2pKey"), creds(i).signalKey(Direction.C2P).toHex())
        }
    }

    @Test
    fun signalFramesSealAndOpenAsTheVectorsSay() {
        for (f in s.getJSONArray("frames").objects()) {
            val c = creds(f.getInt("credentials"))
            val counter = f.getString("counter").toULong()
            val frame = SignalFrame.seal(hex(f.getString("plaintext")), direction(f), counter, c, hex(f.getString("nonce")))
            assertEquals(f.getString("frame"), frame.toHex())
            val opened = SignalFrame.open(frame, direction(f), null, f.getString("now").toULong(), c)
            assertEquals(counter, opened.sequence)
            assertEquals(f.getString("plaintext"), opened.plaintext.toHex())
        }
    }

    @Test
    fun everySignalRejectionIsRefusedWithItsError() {
        for (r in s.getJSONArray("rejections").objects()) {
            val after = if (r.isNull("after")) null else r.getString("after").toULong()
            val error = assertFailsWith<ZeroByteException>(r.getString("why")) {
                SignalFrame.open(
                    hex(r.getString("frame")), direction(r), after, r.getString("now").toULong(),
                    creds(r.getInt("credentials")),
                )
            }
            assertEquals(r.getString("error"), error.code)
        }
    }

    @Test
    fun aSignalSessionOpensOnlyNewFramesFromTheOtherSide() {
        val c = creds(0)
        val primary = SignalSession(c, Direction.P2C)
        val companion = SignalSession(c, Direction.C2P)
        val first = primary.seal("offer".toByteArray())
        val second = primary.seal("candidate".toByteArray())
        assertEquals("offer", String((companion.onBinary(first) as SignalEvent.Message).data))
        assertEquals("candidate", String((companion.onBinary(second) as SignalEvent.Message).data))
        assertNull(companion.onBinary(first), "replayed")
        assertNull(primary.onBinary(second), "own direction")
        assertEquals(SignalEvent.Peer(true), companion.onText("peer 1"))
        assertEquals(SignalEvent.Peer(false), companion.onText("peer 0"))
        assertNull(companion.onText("pong"))
    }

    @Test
    fun pushRegistrationsAreGeneric() {
        val tag = PushRegistration.randomTag()
        assertTrue(Regex("^[A-Za-z0-9_-]{22}$").matches(tag))
        val json = JSONObject(
            PushRegistration("example", mapOf("endpoint" to "https://x/\"y\"", "service" to "nope"), tag, "Hi").toJson(),
        )
        assertEquals("example", json.getString("service"))
        assertEquals("https://x/\"y\"", json.getString("endpoint"))
        assertEquals(tag, json.getString("tag"))
        assertEquals("Hi", json.getString("alert"))
        assertTrue(!JSONObject(PushRegistration("a", emptyMap(), "t").toJson()).has("alert"))
    }

    @Test
    fun fcmRegistrationsAndPushesAreReadAsTheRelaySendsThem() {
        val token = "cX9" + "a".repeat(60) + ":APA91b" + "B_-".repeat(30)
        val json = JSONObject(Fcm.registration(token, "team-3", "New data").toJson())
        assertEquals("fcm", json.getString("service"))
        assertEquals(token, json.getString("token"))
        assertEquals("team-3", json.getString("tag"))
        assertEquals("New data", json.getString("alert"))
        assertFailsWith<IllegalArgumentException> { Fcm.registration("short", "t") }

        val alert = mapOf("zerobyte_tag" to "team-3", "zerobyte_notify" to "alert", "zerobyte_alert" to "New data")
        assertEquals(FcmPush("team-3", Notify.ALERT, "New data"), Fcm.parse(alert))
        assertEquals(
            FcmPush("team-3", Notify.SILENT, null),
            Fcm.parse(mapOf("zerobyte_tag" to "team-3", "zerobyte_notify" to "silent", "zerobyte_alert" to "x")),
        )
        assertNull(Fcm.parse(mapOf("zerobyte_tag" to "a/b", "zerobyte_notify" to "alert")))
        assertNull(Fcm.parse(mapOf("zerobyte_tag" to "t", "zerobyte_notify" to "loud")))
        assertNull(Fcm.parse(mapOf("title" to "from another sender")))
    }

    @Test
    fun theRelaySendsNotifyPushAndIceRequestsAndReportsRateLimits() {
        val seen = mutableListOf<Triple<String, String, Map<String, String>>>()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { exchange ->
            val body = exchange.requestBody.readBytes()
            seen.add(
                Triple(
                    exchange.requestMethod + " " + exchange.requestURI.path,
                    String(body),
                    exchange.requestHeaders.entries.associate { (k, v) -> k.lowercase() to v.first() },
                ),
            )
            when {
                exchange.requestURI.path.startsWith("/limited/") -> {
                    exchange.responseHeaders.add("Retry-After", "7")
                    exchange.sendResponseHeaders(429, -1)
                }
                exchange.requestURI.path.endsWith("/ice") -> {
                    val answer = """{"iceServers":[{"urls":"stun:stun.example.com"},""" +
                        """{"urls":["turn:t.example.com"],"username":"u","credential":"p"}],"ttl":3600}"""
                    exchange.sendResponseHeaders(200, answer.length.toLong())
                    exchange.responseBody.use { it.write(answer.toByteArray()) }
                }
                else -> exchange.sendResponseHeaders(204, -1)
            }
            exchange.close()
        }
        server.start()
        try {
            val base = "http://127.0.0.1:${server.address.port}/v1/"
            val relay = Relay("app", creds(0), base)
            relay.put(byteArrayOf(1), Direction.P2C, 3uL, Notify.ALERT)
            relay.put(byteArrayOf(1), Direction.P2C, 4uL)
            relay.registerPush(PushRegistration("apns", mapOf("token" to "01"), "t"), Direction.C2P)
            relay.unregisterPush(Direction.C2P)
            val ice = relay.iceServers()

            assertEquals("alert", seen[0].third["x-relay-notify"])
            assertNull(seen[1].third["x-relay-notify"])
            assertTrue(seen[2].first.startsWith("PUT ") && seen[2].first.endsWith("/c2p/push"))
            assertEquals("01", JSONObject(seen[2].second).getString("token"))
            assertTrue(seen[3].first.startsWith("DELETE "))
            assertEquals(3600, ice.ttl)
            assertEquals(listOf("stun:stun.example.com"), ice.iceServers[0].urls)
            assertEquals("p", ice.iceServers[1].credential)

            val limited = Relay("app", creds(0), "http://127.0.0.1:${server.address.port}/limited/")
            val error = assertFailsWith<RelayException> { limited.iceServers() }
            assertEquals("rate_limited", error.code)
            assertEquals(7L, error.retryAfterSeconds)
        } finally {
            server.stop(0)
        }
    }

    /** A signal socket for the end-to-end test, on the JDK's WebSocket client. */
    private class Socket(relay: Relay, credentials: Credentials, sends: Direction) : WebSocket.Listener {
        val session = relay.signalSession(sends)
        val events = LinkedBlockingQueue<SignalEvent>()
        private val text = StringBuilder()
        private val binary = java.io.ByteArrayOutputStream()
        val socket: WebSocket = HttpClient.newHttpClient().newWebSocketBuilder()
            .subprotocols("zerobyte.v1", "zerobyte.bearer.${credentials.bearerToken}")
            .buildAsync(URI(relay.signalURL(sends)), this)
            .get(10, TimeUnit.SECONDS)

        override fun onText(webSocket: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
            text.append(data)
            if (last) {
                session.onText(text.toString())?.let(events::add)
                text.setLength(0)
            }
            webSocket.request(1)
            return null
        }

        override fun onBinary(webSocket: WebSocket, data: ByteBuffer, last: Boolean): CompletionStage<*>? {
            binary.write(ByteArray(data.remaining()).also(data::get))
            if (last) {
                session.onBinary(binary.toByteArray())?.let(events::add)
                binary.reset()
            }
            webSocket.request(1)
            return null
        }

        fun send(plaintext: ByteArray) {
            socket.sendBinary(ByteBuffer.wrap(session.seal(plaintext)), true).get(10, TimeUnit.SECONDS)
        }

        fun next(): SignalEvent = events.poll(10, TimeUnit.SECONDS) ?: error("no event")
    }

    /** Against a relay whose app enables signal and push: RELAY_BASE=… RELAY_SIGNAL_APP=<id> */
    @Test
    fun extensionsAgainstARealRelay() {
        val base = System.getenv("RELAY_BASE")
        val app = System.getenv("RELAY_SIGNAL_APP")
        assumeTrue(!base.isNullOrEmpty() && !app.isNullOrEmpty(), "RELAY_BASE and RELAY_SIGNAL_APP not set")
        val random = SecureRandom()
        val c = Credentials(ByteArray(32).also(random::nextBytes), ByteArray(16).also(random::nextBytes))
        val relay = Relay(app!!, c, base!!)
        val phone = Link(c, Direction.P2C, relay)
        phone.send("claim".toByteArray(), Notify.ALERT)
        val token = ByteArray(32).also(random::nextBytes).toHex()
        relay.registerPush(
            PushRegistration("apns", mapOf("token" to token, "environment" to "development"), PushRegistration.randomTag()),
            Direction.C2P,
        )
        try {
            relay.iceServers()
        } catch (e: RelayException) {
            if (e.status != 404) throw e // 404: this relay has no STUN/TURN configured.
        }

        val primary = Socket(relay, c, Direction.P2C)
        val companion = Socket(relay, c, Direction.C2P)
        assertEquals(SignalEvent.Peer(true), primary.next())
        assertEquals(SignalEvent.Peer(true), companion.next())
        companion.send("offer".toByteArray())
        assertContentEquals("offer".toByteArray(), (primary.next() as SignalEvent.Message).data)
        companion.socket.sendClose(WebSocket.NORMAL_CLOSURE, "").get(10, TimeUnit.SECONDS)
        assertEquals(SignalEvent.Peer(false), primary.next())
        primary.socket.sendClose(WebSocket.NORMAL_CLOSURE, "").get(10, TimeUnit.SECONDS)
        phone.erase()
    }
}
