package cloud.zerobyte

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI

/**
 * Relay errors. `last` is the relay's highest sequence on a 409;
 * `retryAfterSeconds` how long to wait on a 429 (`rate_limited`).
 */
class RelayException @JvmOverloads constructor(
    val code: String,
    val status: Int,
    val last: ULong? = null,
    val retryAfterSeconds: Long? = null,
) : IOException("$code ($status)")

/** One page of a fetch. */
class Page(val envelopes: List<ByteArray>, val more: Boolean)

/** What a [Link] needs from a relay. [Relay] is the HTTPS one; tests use a memory one. */
interface RelayTransport {
    fun claim()
    fun put(envelope: ByteArray, direction: Direction, sequence: ULong)

    /** Stores one envelope and asks the relay to wake the reader. Without push, a plain put. */
    fun put(envelope: ByteArray, direction: Direction, sequence: ULong, notify: Notify) =
        put(envelope, direction, sequence)

    fun fetch(direction: Direction, after: ULong?): Page
    fun lastSequence(direction: Direction): ULong?
    fun prune(direction: Direction, through: ULong)
    fun erase()
}

/**
 * The HTTPS side of the protocol, with no dependencies beyond the platform.
 * Blocking: call it off the main thread (on Android, e.g. `Dispatchers.IO`).
 *
 * The WebSockets are not wrapped here, because Android has no platform
 * WebSocket client. The `zerobyte-okhttp` artifact wraps them with OkHttp.
 * With another client, open `watchURL(direction)` or `signalURL(sends)`
 * sending [authorization] as the `Authorization` header and offering the
 * subprotocol `zerobyte.v1`, and send `ping` every [KEEP_ALIVE_MILLISECONDS].
 * On a watch socket each other text message is a sequence; for signal use a
 * [SignalSession].
 */
class Relay @JvmOverloads constructor(
    appID: String,
    private val credentials: Credentials,
    base: String,
    private val timeoutMillis: Int = 30_000,
) : RelayTransport {
    val mailbox: String = URI(base).resolve("$appID/mailbox/${credentials.mailboxName}").toString()

    fun watchURL(direction: Direction): String = socketURL("/${direction.path}/watch")

    /** The signal rendezvous for the side that sends `sends` (the relay's signal extension). */
    fun signalURL(sends: Direction): String =
        socketURL(if (sends == Direction.P2C) "/signal/primary" else "/signal/companion")

    /** A [SignalSession] for one connection to [signalURL]. */
    fun signalSession(sends: Direction): SignalSession = SignalSession(credentials, sends)

    /** The `Authorization` header value for a WebSocket upgrade to [watchURL] or [signalURL]. */
    fun authorization(): String = "Bearer ${credentials.bearerToken}"

    private fun socketURL(path: String): String =
        "$mailbox$path".replaceFirst("https://", "wss://").replaceFirst("http://", "ws://")

    override fun claim() {
        val body = """{"tokenDigest":"${credentials.tokenDigest}"}""".toByteArray()
        call("PUT", "", body, "application/json")
    }

    override fun put(envelope: ByteArray, direction: Direction, sequence: ULong) =
        put(envelope, direction, sequence, Notify.NONE)

    override fun put(envelope: ByteArray, direction: Direction, sequence: ULong, notify: Notify) {
        call("PUT", "/${direction.path}/$sequence", envelope, "application/octet-stream", notify.header)
    }

    /**
     * Asks the relay to wake this device when the other side writes to
     * `direction` with a notify. Register on the direction you read.
     */
    fun registerPush(registration: PushRegistration, direction: Direction) {
        call("PUT", "/${direction.path}/push", registration.toJson().toByteArray(), "application/json")
    }

    fun unregisterPush(direction: Direction) {
        call("DELETE", "/${direction.path}/push")
    }

    /** STUN/TURN servers for a direct connection (the relay's ice extension). */
    fun iceServers(): IceConfiguration {
        val (connection, body) = call("GET", "/ice")
        val bad = { RelayException("malformed_response", connection.responseCode) }
        val root = try {
            Json.parse(String(body, Charsets.UTF_8)) as? Map<*, *>
        } catch (_: IllegalArgumentException) {
            null
        } ?: throw bad()
        val servers = (root["iceServers"] as? List<*>)?.map { item ->
            val server = item as? Map<*, *> ?: throw bad()
            val urls = when (val u = server["urls"]) {
                is String -> listOf(u)
                is List<*> -> u.map { it as? String ?: throw bad() }
                else -> throw bad()
            }
            IceServer(urls, server["username"] as? String, server["credential"] as? String)
        } ?: throw bad()
        return IceConfiguration(servers, (root["ttl"] as? Double)?.toInt() ?: 0)
    }

    override fun fetch(direction: Direction, after: ULong?): Page {
        val (connection, body) = call("GET", "/${direction.path}?after=${after ?: 0uL}&limit=16")
        return Page(Wire.split(body), connection.getHeaderField("X-Relay-More") == "1")
    }

    override fun lastSequence(direction: Direction): ULong? =
        call("HEAD", "/${direction.path}").first.getHeaderField("X-Relay-Last")?.toULongOrNull()

    override fun prune(direction: Direction, through: ULong) {
        call("DELETE", "/${direction.path}?through=$through")
    }

    override fun erase() {
        call("DELETE", "")
    }

    private fun call(
        method: String,
        path: String,
        body: ByteArray? = null,
        type: String? = null,
        notify: String? = null,
    ): Pair<HttpURLConnection, ByteArray> {
        val connection = URI(mailbox + path).toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = timeoutMillis
            connection.readTimeout = timeoutMillis
            connection.useCaches = false
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Authorization", "Bearer ${credentials.bearerToken}")
            if (notify != null) connection.setRequestProperty("X-Relay-Notify", notify)
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", type)
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            if (status !in 200..299) {
                connection.errorStream?.use { it.readBytes() }
                val code = when (status) {
                    401, 403 -> "unauthorized"
                    409 -> "sequence_conflict"
                    402, 413, 507 -> "quota_exceeded"
                    429 -> "rate_limited"
                    else -> "unavailable"
                }
                throw RelayException(
                    code, status,
                    connection.getHeaderField("X-Relay-Last")?.toULongOrNull(),
                    connection.getHeaderField("Retry-After")?.trim()?.toLongOrNull(),
                )
            }
            val bytes = if (method == "HEAD" || status == 204) ByteArray(0)
            else connection.inputStream.use { it.readBytes() }
            return connection to bytes
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        /** How often watch and signal sockets should send `ping`. */
        const val KEEP_ALIVE_MILLISECONDS = 30_000L
    }
}
