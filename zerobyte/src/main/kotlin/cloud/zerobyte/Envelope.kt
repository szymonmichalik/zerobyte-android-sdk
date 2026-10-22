package cloud.zerobyte

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** An opened message. `sequence` is a UInt64 on the wire. */
class Opened(val sequence: ULong, val plaintext: ByteArray)

/**
 * `version(1) ‖ direction(1) ‖ sequence(UInt64 BE) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`,
 * sealed with ChaCha20-Poly1305 over AAD = header ‖ mailboxID.
 */
object Envelope {
    const val VERSION: Byte = 1
    const val HEADER_LENGTH = 10
    const val NONCE_LENGTH = 12
    const val TAG_LENGTH = 16
    const val OVERHEAD = HEADER_LENGTH + NONCE_LENGTH + TAG_LENGTH
    const val MAX_PLAINTEXT_BYTES = 1_048_576
    const val MAX_ENVELOPE_BYTES = MAX_PLAINTEXT_BYTES + OVERHEAD

    private val random = SecureRandom()

    private fun header(direction: Direction, sequence: ULong): ByteArray =
        ByteBuffer.allocate(HEADER_LENGTH).put(VERSION).put(direction.wire).putLong(sequence.toLong()).array()

    /** The clear header, without opening. */
    fun readHeader(envelope: ByteArray): Pair<Direction, ULong> {
        if (envelope.size < OVERHEAD) throw ZeroByteException("malformed")
        if (envelope[0] != VERSION) throw ZeroByteException("unsupported_version")
        val direction = Direction.of(envelope[1]) ?: throw ZeroByteException("malformed")
        val sequence = ByteBuffer.wrap(envelope, 2, 8).long.toULong()
        if (sequence == 0uL) throw ZeroByteException("malformed")
        return direction to sequence
    }

    /** Seals a message. `nonce` is for known-answer tests only; leave it out. */
    @JvmOverloads
    fun seal(
        plaintext: ByteArray,
        direction: Direction,
        sequence: ULong,
        credentials: Credentials,
        nonce: ByteArray? = null,
    ): ByteArray {
        if (plaintext.size > MAX_PLAINTEXT_BYTES) throw ZeroByteException("too_large")
        return sealWith(credentials.key(direction), plaintext, direction, sequence, credentials, nonce)
    }

    internal fun sealWith(
        key: ByteArray,
        plaintext: ByteArray,
        direction: Direction,
        sequence: ULong,
        credentials: Credentials,
        nonce: ByteArray?,
    ): ByteArray {
        if (sequence == 0uL) throw ZeroByteException("malformed")
        val h = header(direction, sequence)
        val n = nonce ?: ByteArray(NONCE_LENGTH).also(random::nextBytes)
        val cipher = cipher(Cipher.ENCRYPT_MODE, key, n)
        cipher.updateAAD(h)
        cipher.updateAAD(credentials.mailboxID)
        return h + n + cipher.doFinal(plaintext)
    }

    /**
     * Opens an envelope the other side wrote. `after` is the highest sequence
     * already accepted, or null.
     */
    fun open(envelope: ByteArray, direction: Direction, after: ULong?, credentials: Credentials): Opened {
        if (envelope.size > MAX_ENVELOPE_BYTES) throw ZeroByteException("too_large")
        val (written, sequence) = readHeader(envelope)
        if (written != direction) throw ZeroByteException("wrong_direction")
        if (after != null && sequence <= after) throw ZeroByteException("replayed")
        return openWith(credentials.key(direction), envelope, sequence, credentials)
    }

    internal fun openWith(key: ByteArray, envelope: ByteArray, sequence: ULong, credentials: Credentials): Opened {
        val nonce = envelope.copyOfRange(HEADER_LENGTH, HEADER_LENGTH + NONCE_LENGTH)
        return try {
            val cipher = cipher(Cipher.DECRYPT_MODE, key, nonce)
            cipher.updateAAD(envelope, 0, HEADER_LENGTH)
            cipher.updateAAD(credentials.mailboxID)
            val body = HEADER_LENGTH + NONCE_LENGTH
            Opened(sequence, cipher.doFinal(envelope, body, envelope.size - body))
        } catch (_: GeneralSecurityException) {
            throw ZeroByteException("authentication_failed")
        }
    }

    // ChaCha20-Poly1305 is in the JDK since 11 and in Android since API 28.
    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray): Cipher =
        Cipher.getInstance("ChaCha20-Poly1305").apply {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        }
}

/** A fetch body: `count(UInt32 BE)`, then `length(UInt32 BE) ‖ bytes` per envelope. */
object Wire {
    const val MAXIMUM_COUNT = 64

    fun join(envelopes: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(ByteBuffer.allocate(4).putInt(envelopes.size).array())
        for (e in envelopes) {
            out.write(ByteBuffer.allocate(4).putInt(e.size).array())
            out.write(e)
        }
        return out.toByteArray()
    }

    fun split(body: ByteArray): List<ByteArray> {
        val bad = { RelayException("malformed_response", 200) }
        if (body.size < 4) throw bad()
        val buffer = ByteBuffer.wrap(body)
        val count = buffer.int.toUInt().toLong()
        if (count > MAXIMUM_COUNT) throw bad()
        val out = ArrayList<ByteArray>(count.toInt())
        repeat(count.toInt()) {
            if (buffer.remaining() < 4) throw bad()
            val length = buffer.int.toUInt().toLong()
            if (length > Envelope.MAX_ENVELOPE_BYTES || length > buffer.remaining()) throw bad()
            out.add(ByteArray(length.toInt()).also { buffer.get(it) })
        }
        if (buffer.hasRemaining()) throw bad()
        return out
    }
}
