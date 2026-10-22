package cloud.zerobyte

import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.Assumptions.assumeTrue

// Known answers from the independent reference (zerobyte-protocol, spec/vectors.py),
// copied as relay-v1.json. Never regenerate them from this library.
class VectorTest {
    private val v = JSONObject(javaClass.getResource("/relay-v1.json")!!.readText())

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
    fun credentialsMatchEveryVectorSet() {
        for ((i, set) in v.getJSONArray("credentials").objects().withIndex()) {
            val c = creds(i)
            assertEquals(set.getString("mailbox"), c.mailboxName)
            assertEquals(set.getString("bearer"), c.bearerToken)
            assertEquals(set.getString("tokenDigest"), c.tokenDigest)
            assertEquals(set.getString("p2cKey"), c.key(Direction.P2C).toHex())
            assertEquals(set.getString("c2pKey"), c.key(Direction.C2P).toHex())
        }
        val first = v.getJSONArray("credentials").getJSONObject(0)
        val fromUUID = Credentials(
            hex(first.getString("linkKey")),
            UUID.fromString("6F1C2A3B-4D5E-4F60-8172-93A4B5C6D7E8"),
        )
        assertEquals(first.getString("mailbox"), fromUUID.mailboxName)
    }

    @Test
    fun sealingWithTheVectorNonceGivesTheVectorEnvelope() {
        for (e in v.getJSONArray("envelopes").objects()) {
            val c = creds(e.getInt("credentials"))
            val sequence = e.getString("sequence").toULong()
            val sealed = Envelope.seal(
                hex(e.getString("plaintext")), direction(e), sequence, c, hex(e.getString("nonce")),
            )
            assertEquals(e.getString("envelope"), sealed.toHex())
            val opened = Envelope.open(hex(e.getString("envelope")), direction(e), null, c)
            assertEquals(sequence, opened.sequence)
            assertEquals(e.getString("plaintext"), opened.plaintext.toHex())
        }
    }

    @Test
    fun everyRejectionVectorIsRefusedWithItsError() {
        for (r in v.getJSONArray("rejections").objects()) {
            val after = if (r.isNull("after")) null else r.getString("after").toULong()
            val error = assertFailsWith<ZeroByteException>(r.getString("why")) {
                Envelope.open(hex(r.getString("envelope")), direction(r), after, creds(r.getInt("credentials")))
            }
            assertEquals(r.getString("error"), error.code, r.getString("why"))
        }
    }

    @Test
    fun fetchBodiesJoinAndSplitAsTheVectorsSay() {
        for (w in v.getJSONArray("wire").objects()) {
            val envelopes = w.getJSONArray("envelopes").let { a -> (0 until a.length()).map { hex(a.getString(it)) } }
            assertEquals(w.getString("body"), Wire.join(envelopes).toHex())
            val split = Wire.split(hex(w.getString("body")))
            assertEquals(envelopes.size, split.size)
            envelopes.zip(split).forEach { (a, b) -> assertContentEquals(a, b) }
        }
        for (w in v.getJSONArray("wireRejections").objects()) {
            assertFailsWith<RelayException>(w.getString("why")) { Wire.split(hex(w.getString("body"))) }
        }
    }

    @Test
    fun wrongKeySizesAndOversizedPlaintextAreRefused() {
        assertEquals("invalid_key", assertFailsWith<ZeroByteException> { Credentials(ByteArray(31), ByteArray(16)) }.code)
        val error = assertFailsWith<ZeroByteException> {
            Envelope.seal(ByteArray(Envelope.MAX_PLAINTEXT_BYTES + 1), Direction.P2C, 1uL, creds(0))
        }
        assertEquals("too_large", error.code)
    }

    /** A relay in memory with the server's rules. */
    private class MemoryRelay : RelayTransport {
        val boxes = mutableMapOf(Direction.P2C to sortedMapOf<ULong, ByteArray>(), Direction.C2P to sortedMapOf())
        val prunes = mutableListOf<ULong>()
        // Like the server: the last sequence survives a prune.
        val last = mutableMapOf<Direction, ULong>()
        override fun claim() {}
        override fun put(envelope: ByteArray, direction: Direction, sequence: ULong) {
            val last = lastSequence(direction)
            if (last != null && sequence <= last) throw RelayException("sequence_conflict", 409, last)
            boxes[direction]!![sequence] = envelope
            this.last[direction] = sequence
        }
        override fun fetch(direction: Direction, after: ULong?): Page {
            val waiting = boxes[direction]!!.filterKeys { it > (after ?: 0uL) }.values.toList()
            return Page(waiting.take(16), waiting.size > 16)
        }
        override fun lastSequence(direction: Direction) = last[direction]
        override fun prune(direction: Direction, through: ULong) {
            prunes.add(through)
            boxes[direction]!!.keys.removeIf { it <= through }
        }
        override fun erase() {
            boxes.values.forEach { it.clear() }
            last.clear()
        }
    }

    @Test
    fun aLinkDeliversInOrderOncePrunesAndDropsForgeries() {
        val c = creds(1)
        val relay = MemoryRelay()
        val phone = Link(c, Direction.P2C, relay)
        val laptop = Link(c, Direction.C2P, relay)
        val threads = (1..20).map { i -> Thread { phone.send("m$i".toByteArray()) } }
        threads.forEach(Thread::start)
        threads.forEach(Thread::join)
        relay.boxes[Direction.P2C]!![21uL] = Envelope.seal(byteArrayOf(1), Direction.P2C, 21uL, creds(0))
        relay.last[Direction.P2C] = 21uL

        val got = laptop.receive()
        assertEquals((1..20).map { it.toULong() }, got.map { it.sequence })
        assertEquals(20, got.map { String(it.plaintext) }.toSet().size)
        assertEquals(20uL, laptop.lastReceived)
        assertEquals(listOf(21uL), relay.prunes)
        assertEquals(emptyList(), laptop.receive())
        assertEquals(listOf(21uL), relay.prunes)

        assertEquals(22uL, Link(c, Direction.P2C, relay).send(byteArrayOf(9)))
    }

    @Test
    fun theEndpointIsBuiltFromTheBaseURL() {
        val c = creds(0)
        val relay = Relay("01a1601b-fa85-7d58-b2a2-1416e0a6b054", c, "https://relay.example.com/v1/")
        assertEquals(
            "https://relay.example.com/v1/01a1601b-fa85-7d58-b2a2-1416e0a6b054/mailbox/${c.mailboxName}",
            relay.mailbox,
        )
        assertEquals("${relay.mailbox.replace("https://", "wss://")}/c2p/watch", relay.watchURL(Direction.C2P))
    }

    /** Against a running relay: RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=<id> gradle test */
    @Test
    fun endToEndAgainstARealRelay() {
        val base = System.getenv("RELAY_BASE")
        val app = System.getenv("RELAY_APP")
        assumeTrue(base != null && app != null)
        val random = SecureRandom()
        val c = Credentials(ByteArray(32).also(random::nextBytes), ByteArray(16).also(random::nextBytes))
        val phone = Link(c, Direction.P2C, Relay(app!!, c, base!!))
        val laptop = Link(c, Direction.C2P, Relay(app, c, base))
        assertEquals(1uL, phone.send("hello".toByteArray()))
        assertEquals(2uL, phone.send("again".toByteArray()))
        assertEquals(listOf("hello", "again"), laptop.receive().map { String(it.plaintext) })
        assertEquals(emptyList(), laptop.receive())
        laptop.send("ack".toByteArray())
        assertEquals(listOf("ack"), phone.receive().map { String(it.plaintext) })
        phone.erase()
    }
}
