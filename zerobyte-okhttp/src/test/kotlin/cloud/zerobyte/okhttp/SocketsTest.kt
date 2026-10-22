package cloud.zerobyte.okhttp

import cloud.zerobyte.Credentials
import cloud.zerobyte.Direction
import cloud.zerobyte.Link
import cloud.zerobyte.Relay
import okhttp3.OkHttpClient
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Against a running relay:
 * RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=<id> RELAY_SIGNAL_APP=<id with signal> gradle test
 */
class SocketsTest {
    private val client = OkHttpClient()
    private val random = SecureRandom()

    private fun credentials() = Credentials(ByteArray(32).also(random::nextBytes), ByteArray(16).also(random::nextBytes))

    private fun <T> LinkedBlockingQueue<T>.next(): T =
        poll(10, TimeUnit.SECONDS) ?: throw AssertionError("nothing arrived in 10 seconds")

    @Test
    fun aWatcherHearsEachWriteInItsDirection() {
        val base = System.getenv("RELAY_BASE")
        val app = System.getenv("RELAY_APP")
        assumeTrue(!base.isNullOrEmpty() && !app.isNullOrEmpty(), "RELAY_BASE and RELAY_APP not set")
        val c = credentials()
        val phone = Link(c, Direction.P2C, Relay(app!!, c, base!!))
        val laptop = Relay(app, c, base)
        laptop.claim()

        val events = LinkedBlockingQueue<String>()
        val watch = laptop.watch(
            client,
            Direction.P2C,
            object : WatchListener {
                override fun onOpen() {
                    events.add("open")
                }

                override fun onSequence(sequence: ULong) {
                    events.add("sequence $sequence")
                }
            },
        )
        assertEquals("open", events.next())
        phone.send("hello".toByteArray())
        assertEquals("sequence 1", events.next())
        watch.close()
        phone.erase()
    }

    @Test
    fun bothSidesOfASignalSocketMeetAndTalkSealed() {
        val base = System.getenv("RELAY_BASE")
        val app = System.getenv("RELAY_SIGNAL_APP")
        assumeTrue(!base.isNullOrEmpty() && !app.isNullOrEmpty(), "RELAY_BASE and RELAY_SIGNAL_APP not set")
        val c = credentials()
        val primary = Relay(app!!, c, base!!)
        val companion = Relay(app, c, base)
        primary.claim()

        val heard = LinkedBlockingQueue<String>()
        fun listener(name: String) = object : SignalListener {
            override fun onPeer(present: Boolean) {
                heard.add("$name peer $present")
            }

            override fun onMessage(data: ByteArray) {
                heard.add("$name got ${String(data)}")
            }
        }

        val a = primary.signal(client, Direction.P2C, listener("primary"))
        val b = companion.signal(client, Direction.C2P, listener("companion"))
        assertEquals(setOf("primary peer true", "companion peer true"), setOf(heard.next(), heard.next()))
        a.send("offer".toByteArray())
        assertEquals("companion got offer", heard.next())
        b.send("answer".toByteArray())
        assertEquals("primary got answer", heard.next())
        a.close()
        assertEquals("companion peer false", heard.next())
        b.close()
        primary.erase()
    }
}
