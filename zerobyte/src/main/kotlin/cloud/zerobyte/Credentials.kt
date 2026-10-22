package cloud.zerobyte

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Which side of a link wrote an envelope. */
enum class Direction(val wire: Byte, val path: String) {
    P2C(1, "p2c"),
    C2P(2, "c2p");

    val reversed: Direction get() = if (this == P2C) C2P else P2C

    companion object {
        fun of(wire: Byte): Direction? = entries.firstOrNull { it.wire == wire }
    }
}

/** Envelope errors. `code` is the same string in every ZeroByte SDK. */
class ZeroByteException(val code: String) : Exception(code)

/**
 * Everything one paired link needs, derived from the 32-byte link key both
 * devices agreed when they paired, salted with 16 bytes naming the link.
 */
class Credentials(linkKey: ByteArray, linkID: ByteArray) {
    constructor(linkKey: ByteArray, linkID: UUID) : this(linkKey, uuidBytes(linkID))

    val mailboxID: ByteArray
    val accessToken: ByteArray
    internal val p2cKey: ByteArray
    internal val c2pKey: ByteArray
    private val signalP2C: ByteArray
    private val signalC2P: ByteArray

    init {
        if (linkKey.size != 32 || linkID.size != 16) throw ZeroByteException("invalid_key")
        // The labels are part of the wire format: changing one is a new protocol version.
        mailboxID = hkdf(linkKey, linkID, "zerobyte-relay-mailbox-v1", 16)
        accessToken = hkdf(linkKey, linkID, "zerobyte-relay-token-v1", 32)
        p2cKey = hkdf(linkKey, linkID, "zerobyte-relay-p2c-v1", 32)
        c2pKey = hkdf(linkKey, linkID, "zerobyte-relay-c2p-v1", 32)
        signalP2C = hkdf(linkKey, linkID, "zerobyte-signal-p2c-v1", 32)
        signalC2P = hkdf(linkKey, linkID, "zerobyte-signal-c2p-v1", 32)
    }

    /** The mailbox's name in URLs: 32 lowercase hex characters. */
    val mailboxName: String get() = mailboxID.toHex()

    /** The bearer token: base64url without padding. */
    val bearerToken: String get() = Base64.getUrlEncoder().withoutPadding().encodeToString(accessToken)

    /** What the relay stores instead of the token: SHA-256, lowercase hex. */
    val tokenDigest: String get() = MessageDigest.getInstance("SHA-256").digest(accessToken).toHex()

    internal fun key(direction: Direction): ByteArray = if (direction == Direction.P2C) p2cKey else c2pKey

    /** The key for signal frames in one direction, separate from the envelope keys. */
    fun signalKey(direction: Direction): ByteArray =
        (if (direction == Direction.P2C) signalP2C else signalC2P).copyOf()

    companion object {
        fun uuidBytes(uuid: UUID): ByteArray =
            ByteBuffer.allocate(16).putLong(uuid.mostSignificantBits).putLong(uuid.leastSignificantBits).array()

        /** RFC 5869 with HMAC-SHA256. */
        internal fun hkdf(ikm: ByteArray, salt: ByteArray, info: String, length: Int): ByteArray {
            val extract = Mac.getInstance("HmacSHA256")
            extract.init(SecretKeySpec(salt, "HmacSHA256"))
            val prk = extract.doFinal(ikm)
            val expand = Mac.getInstance("HmacSHA256")
            expand.init(SecretKeySpec(prk, "HmacSHA256"))
            val out = ByteArray(length)
            var previous = ByteArray(0)
            var offset = 0
            var counter = 1
            while (offset < length) {
                expand.update(previous)
                expand.update(info.toByteArray(Charsets.UTF_8))
                expand.update(counter.toByte())
                previous = expand.doFinal()
                val n = minOf(previous.size, length - offset)
                System.arraycopy(previous, 0, out, offset, n)
                offset += n
                counter += 1
            }
            return out
        }
    }
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
