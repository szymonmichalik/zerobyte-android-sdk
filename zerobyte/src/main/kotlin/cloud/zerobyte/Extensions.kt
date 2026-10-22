package cloud.zerobyte

import java.security.SecureRandom
import java.util.Base64

/** Whether a write should wake the reader with a push (the relay's push extension). */
enum class Notify(internal val header: String?) {
    NONE(null),

    /** A visible notification the app replaces with the decrypted message. */
    ALERT("alert"),

    /** A background push. */
    SILENT("silent"),
}

/**
 * Where the relay sends pushes for one direction. The relay knows push
 * services as separate modules; [fields] are the service's own (for the APNs
 * module, `token` and `environment`).
 */
class PushRegistration @JvmOverloads constructor(
    val service: String,
    val fields: Map<String, String>,
    val tag: String,
    val alert: String? = null,
) {
    /** The body of `PUT …/push`. The common keys win over [fields]. */
    fun toJson(): String {
        val body = sortedMapOf<String, String>()
        body.putAll(fields)
        body["service"] = service
        body["tag"] = tag
        alert?.let { body["alert"] = it }
        return body.entries.joinToString(",", "{", "}") { (k, v) -> "${Json.quote(k)}:${Json.quote(v)}" }
    }

    companion object {
        private val random = SecureRandom()

        /** A fresh random tag: 22 base64url characters. */
        @JvmStatic
        fun randomTag(): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16).also(random::nextBytes))
    }
}

/** One STUN or TURN server, in the shape of WebRTC's `IceServer`. */
class IceServer(val urls: List<String>, val username: String?, val credential: String?)

/** STUN/TURN servers and how many seconds their credentials last. */
class IceConfiguration(val iceServers: List<IceServer>, val ttl: Int)

/**
 * Signal frames (the relay's signal extension): the envelope layout under the
 * signal keys, with a counter (milliseconds since 1970, always increasing) in
 * place of the sequence.
 */
object SignalFrame {
    const val MAX_FRAME_BYTES = 65_536
    const val MAX_PLAINTEXT_BYTES = MAX_FRAME_BYTES - Envelope.OVERHEAD

    /** How far a frame's counter may be from the receiver's clock. */
    const val WINDOW_MILLISECONDS = 5L * 60 * 1000

    /** Seals a frame. `nonce` is for known-answer tests only; leave it out. */
    @JvmOverloads
    fun seal(
        plaintext: ByteArray,
        direction: Direction,
        counter: ULong,
        credentials: Credentials,
        nonce: ByteArray? = null,
    ): ByteArray {
        if (plaintext.size > MAX_PLAINTEXT_BYTES) throw ZeroByteException("too_large")
        return Envelope.sealWith(credentials.signalKey(direction), plaintext, direction, counter, credentials, nonce)
    }

    /**
     * Opens a frame the other side sent. Refuses one at or below `after` or
     * more than five minutes from `now` (milliseconds since 1970).
     */
    fun open(frame: ByteArray, direction: Direction, after: ULong?, now: ULong, credentials: Credentials): Opened {
        if (frame.size > MAX_FRAME_BYTES) throw ZeroByteException("too_large")
        val (written, counter) = Envelope.readHeader(frame)
        if (written != direction) throw ZeroByteException("wrong_direction")
        if (after != null && counter <= after) throw ZeroByteException("replayed")
        val distance = if (counter > now) counter - now else now - counter
        if (distance > WINDOW_MILLISECONDS.toULong()) throw ZeroByteException("replayed")
        return Envelope.openWith(credentials.signalKey(direction), frame, counter, credentials)
    }
}

/** What a [SignalSession] reports. */
sealed class SignalEvent {
    /** The other device connected (`true`) or left (`false`). */
    data class Peer(val present: Boolean) : SignalEvent()

    /** An opened message from the other device: an offer, answer or candidate. */
    class Message(val data: ByteArray) : SignalEvent()
}

/**
 * One signal connection's state, for any WebSocket client (Android has none
 * in the platform; OkHttp works). Open [Relay.signalURL] with the subprotocols
 * `zerobyte.v1` and `"zerobyte.bearer." + bearerToken`, send `ping` every
 * [Relay.KEEP_ALIVE_MILLISECONDS], pass every incoming message here and send
 * what [seal] returns as a binary message. Use a new session per connection.
 */
class SignalSession(private val credentials: Credentials, val sends: Direction) {
    val receives: Direction = sends.reversed
    private var lastSent = 0uL
    private var lastReceived: ULong? = null

    /** A text message: `peer 1`, `peer 0`, or `pong` (null). */
    fun onText(text: String): SignalEvent? = when (text) {
        "peer 1" -> SignalEvent.Peer(true)
        "peer 0" -> SignalEvent.Peer(false)
        else -> null
    }

    /** A binary message: an opened [SignalEvent.Message], or null when it does not open. */
    @JvmOverloads
    fun onBinary(frame: ByteArray, now: Long = System.currentTimeMillis()): SignalEvent? = synchronized(this) {
        try {
            val opened = SignalFrame.open(frame, receives, lastReceived, now.toULong(), credentials)
            lastReceived = opened.sequence
            SignalEvent.Message(opened.plaintext)
        } catch (_: ZeroByteException) {
            null // Forged, replayed, stale or for the other side.
        }
    }

    /** A frame to send, for at most [SignalFrame.MAX_PLAINTEXT_BYTES]. */
    fun seal(plaintext: ByteArray): ByteArray = synchronized(this) {
        val now = System.currentTimeMillis().toULong()
        val counter = if (now > lastSent) now else lastSent + 1uL
        val frame = SignalFrame.seal(plaintext, sends, counter, credentials)
        lastSent = counter
        frame
    }
}

/** Just enough JSON for the relay's answers: objects, arrays, strings, numbers, literals. */
internal object Json {
    fun quote(s: String): String = buildString {
        append('"')
        for (c in s) when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c < ' ' -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
        append('"')
    }

    fun parse(text: String): Any? {
        val p = Parser(text)
        val value = p.value()
        p.space()
        if (p.i != text.length) throw IllegalArgumentException("trailing data")
        return value
    }

    private class Parser(val s: String) {
        var i = 0

        fun space() {
            while (i < s.length && s[i] in " \t\r\n") i++
        }

        fun value(): Any? {
            space()
            if (i >= s.length) throw IllegalArgumentException("end of input")
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> num()
            }
        }

        fun literal(word: String, value: Any?): Any? {
            if (!s.startsWith(word, i)) throw IllegalArgumentException("bad literal")
            i += word.length
            return value
        }

        fun num(): Double {
            val start = i
            while (i < s.length && s[i] in "+-0123456789.eE") i++
            return s.substring(start, i).toDoubleOrNull() ?: throw IllegalArgumentException("bad number")
        }

        fun str(): String {
            val out = StringBuilder()
            i++
            while (true) {
                if (i >= s.length) throw IllegalArgumentException("open string")
                val c = s[i++]
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> {
                        when (val e = s[i++]) {
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000c')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                out.append(s.substring(i, i + 4).toInt(16).toChar())
                                i += 4
                            }
                            else -> out.append(e)
                        }
                    }
                    else -> out.append(c)
                }
            }
        }

        fun arr(): List<Any?> {
            val out = ArrayList<Any?>()
            i++
            space()
            if (s.getOrNull(i) == ']') return out.also { i++ }
            while (true) {
                out.add(value())
                space()
                when (s.getOrNull(i++)) {
                    ',' -> continue
                    ']' -> return out
                    else -> throw IllegalArgumentException("bad array")
                }
            }
        }

        fun obj(): Map<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            i++
            space()
            if (s.getOrNull(i) == '}') return out.also { i++ }
            while (true) {
                space()
                if (s.getOrNull(i) != '"') throw IllegalArgumentException("bad key")
                val key = str()
                space()
                if (s.getOrNull(i++) != ':') throw IllegalArgumentException("bad object")
                out[key] = value()
                space()
                when (s.getOrNull(i++)) {
                    ',' -> continue
                    '}' -> return out
                    else -> throw IllegalArgumentException("bad object")
                }
            }
        }
    }
}
