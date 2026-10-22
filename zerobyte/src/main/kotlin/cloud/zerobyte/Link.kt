package cloud.zerobyte

/**
 * One side of a paired link: sends in its own direction, receives, opens and
 * prunes in the other. Thread-safe; blocking. Persist [lastReceived].
 */
class Link @JvmOverloads constructor(
    private val credentials: Credentials,
    val sends: Direction,
    private val relay: RelayTransport,
    lastReceived: ULong? = null,
) {
    val receives: Direction = sends.reversed

    @Volatile
    var lastReceived: ULong? = lastReceived
        private set

    private val lock = Any()
    private var claimed = false
    private var nextSequence: ULong? = null

    private fun ensureClaimed() {
        if (!claimed) {
            relay.claim()
            claimed = true
        }
    }

    /**
     * Seals and stores one message; returns its sequence. [Notify.ALERT] or
     * [Notify.SILENT] asks the relay to wake the other device.
     */
    @JvmOverloads
    fun send(plaintext: ByteArray, notify: Notify = Notify.NONE): ULong = synchronized(lock) {
        ensureClaimed()
        var sequence = nextSequence ?: ((relay.lastSequence(sends) ?: 0uL) + 1uL)
        repeat(3) {
            val envelope = Envelope.seal(plaintext, sends, sequence, credentials)
            try {
                relay.put(envelope, sends, sequence, notify)
                nextSequence = sequence + 1uL
                return sequence
            } catch (e: RelayException) {
                if (e.code != "sequence_conflict") throw e
                sequence = (e.last ?: sequence) + 1uL
            }
        }
        throw RelayException("sequence_conflict", 409, sequence - 1uL)
    }

    /**
     * Fetches, opens and prunes everything the other side wrote since
     * [lastReceived]. Envelopes that do not open are skipped and pruned.
     */
    fun receive(): List<Opened> = synchronized(lock) {
        ensureClaimed()
        val received = ArrayList<Opened>()
        var cursor = lastReceived
        var seen: ULong? = null
        while (true) {
            val page = relay.fetch(receives, cursor)
            val before = cursor
            for (envelope in page.envelopes) {
                val sequence = try {
                    Envelope.readHeader(envelope).second
                } catch (_: ZeroByteException) {
                    continue
                }
                if (cursor == null || sequence > cursor) cursor = sequence
                if (seen == null || sequence > seen) seen = sequence
                try {
                    val opened = Envelope.open(envelope, receives, lastReceived, credentials)
                    received.add(opened)
                    lastReceived = opened.sequence
                } catch (_: ZeroByteException) {
                    // Forged, replayed or damaged: it can never open later.
                }
            }
            if (!page.more || cursor == before) break
        }
        seen?.let { relay.prune(receives, it) }
        received
    }

    /** Deletes the mailbox for both sides. Use when the devices unpair. */
    fun erase() = synchronized(lock) {
        relay.erase()
        claimed = false
        nextSequence = null
    }
}
