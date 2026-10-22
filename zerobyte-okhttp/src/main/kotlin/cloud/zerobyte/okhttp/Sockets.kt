package cloud.zerobyte.okhttp

import cloud.zerobyte.Direction
import cloud.zerobyte.Relay
import cloud.zerobyte.SignalEvent
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.Closeable
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** What a watch socket reports. Callbacks run on OkHttp's thread. */
interface WatchListener {
    /** The socket is open: fetch now, and again after every reconnect. */
    fun onOpen() {}

    /** An envelope was stored in the watched direction: fetch after your last sequence. */
    fun onSequence(sequence: ULong)

    /** The relay closed the socket: 1000 when the mailbox was erased. */
    fun onClosed(code: Int, reason: String) {}

    /** The connection failed or dropped. Reconnect with a backoff. */
    fun onFailure(error: Throwable) {}
}

/** What a signal socket reports. Callbacks run on OkHttp's thread. */
interface SignalListener {
    /** The other device connected (`true`) or left (`false`). */
    fun onPeer(present: Boolean)

    /** An opened message from the other device. Frames that do not open never get here. */
    fun onMessage(data: ByteArray)

    /** The relay closed the socket: 4000 when another connection for this side replaced it. */
    fun onClosed(code: Int, reason: String) {}

    fun onFailure(error: Throwable) {}
}

/** An open watch socket. [close] it when the app goes to the background. */
class Watch internal constructor(private val socket: WebSocket, private val keepAlive: ScheduledFuture<*>) :
    Closeable {
    override fun close() {
        keepAlive.cancel(false)
        socket.close(1000, null)
    }
}

/** An open signal socket. */
class SignalSocket internal constructor(
    private val socket: WebSocket,
    private val keepAlive: ScheduledFuture<*>,
    private val seal: (ByteArray) -> ByteArray,
) : Closeable {
    /**
     * Seals and sends one message of at most `SignalFrame.MAX_PLAINTEXT_BYTES`.
     * The relay drops it if the other side is not connected, so wait for
     * `onPeer(true)`. False when the socket is closing.
     */
    fun send(plaintext: ByteArray): Boolean = socket.send(seal(plaintext).toByteString())

    override fun close() {
        keepAlive.cancel(false)
        socket.close(1000, null)
    }
}

private val pinger = Executors.newSingleThreadScheduledExecutor { task ->
    Thread(task, "zerobyte-keepalive").apply { isDaemon = true }
}

private fun keepAlive(socket: WebSocket): ScheduledFuture<*> =
    pinger.scheduleAtFixedRate(
        { socket.send("ping") },
        Relay.KEEP_ALIVE_MILLISECONDS,
        Relay.KEEP_ALIVE_MILLISECONDS,
        TimeUnit.MILLISECONDS,
    )

private fun Relay.upgrade(url: String): Request =
    Request.Builder()
        .url(url)
        .header("Authorization", authorization())
        .header("Sec-WebSocket-Protocol", "zerobyte.v1")
        .build()

/**
 * Opens the watch socket for [direction] (the one this device reads). It
 * sends `ping` every 30 seconds, which also tells the relay not to push.
 */
fun Relay.watch(client: OkHttpClient, direction: Direction, listener: WatchListener): Watch {
    val socket = client.newWebSocket(
        upgrade(watchURL(direction)),
        object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) = listener.onOpen()

            override fun onMessage(webSocket: WebSocket, text: String) {
                text.toULongOrNull()?.let(listener::onSequence)
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(code, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) =
                listener.onClosed(code, reason)

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) =
                listener.onFailure(t)
        },
    )
    return Watch(socket, keepAlive(socket))
}

/**
 * Opens the signal socket for the side that sends [sends]
 * (`Direction.P2C` is the primary). Messages are sealed and opened with the
 * link's signal keys; the relay forwards them without reading them.
 */
fun Relay.signal(client: OkHttpClient, sends: Direction, listener: SignalListener): SignalSocket {
    val session = signalSession(sends)
    val socket = client.newWebSocket(
        upgrade(signalURL(sends)),
        object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                (session.onText(text) as? SignalEvent.Peer)?.let { listener.onPeer(it.present) }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                (session.onBinary(bytes.toByteArray()) as? SignalEvent.Message)?.let { listener.onMessage(it.data) }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(code, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) =
                listener.onClosed(code, reason)

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) =
                listener.onFailure(t)
        },
    )
    return SignalSocket(socket, keepAlive(socket), session::seal)
}
