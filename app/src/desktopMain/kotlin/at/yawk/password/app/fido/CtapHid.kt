package at.yawk.password.app.fido

import java.nio.ByteBuffer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(CtapHid::class.java)

/**
 * The CTAPHID protocol of a FIDO security key on USB HID (CTAP 2.0, section 8.1): channels, the framing of messages
 * into 64-byte reports, and the commands around the CTAP2 messages, which [process] handles.
 *
 * One CBOR request runs at a time. While it waits for the user, the browser gets keepalives, and can cancel it. Other
 * channels are told that the key is busy.
 *
 * @param send Sends one input report (64 bytes) to the host. Called from any thread, but never concurrently.
 * @param scope Runs the CBOR requests
 * @param process Processes one CTAP2 request (command byte and CBOR), see [Ctap2.process]
 * @param wink Called for the WINK command: show the user which key this is
 */
class CtapHid(
    private val send: (ByteArray) -> Unit,
    private val scope: CoroutineScope,
    private val process: suspend (ByteArray) -> ByteArray,
    private val wink: () -> Unit = {},
    private val keepaliveIntervalMs: Long = KEEPALIVE_INTERVAL_MS,
    private val messageTimeoutMs: Long = MESSAGE_TIMEOUT_MS,
) {
    private val lock = Any()

    /** Channels handed out by INIT, oldest first */
    private val channels = LinkedHashSet<Int>()
    private var nextChannel = 1

    /** The message being received, if any */
    private var assembly: Assembly? = null

    /** The CBOR request being processed, if any */
    private var transaction: Transaction? = null

    private class Assembly(val channel: Int, val command: Int, val data: ByteArray) {
        var received = 0
        var nextSequence = 0
        var timeout: Job? = null
    }

    private class Transaction(val channel: Int) {
        lateinit var job: Job
    }

    /**
     * Handle an output report from the host. Must not be called concurrently.
     */
    fun onReport(report: ByteArray) {
        if (report.size != REPORT_SIZE) {
            log.debug("Ignoring a report of {} bytes", report.size)
            return
        }
        val buffer = ByteBuffer.wrap(report)
        val channel = buffer.int
        val first = buffer.get().toInt() and 0xff
        synchronized(lock) {
            if (first and 0x80 != 0) {
                val length = buffer.short.toInt() and 0xffff
                onInitPacket(channel, first, length, buffer)
            } else {
                onContinuationPacket(channel, first, buffer)
            }
        }
    }

    private fun onInitPacket(channel: Int, command: Int, length: Int, buffer: ByteBuffer) {
        if (command == CTAPHID_INIT) {
            init(channel, length, buffer)
            return
        }
        if (channel == 0 || channel == BROADCAST || channel !in channels) {
            sendError(channel, ERR_INVALID_CHANNEL)
            return
        }
        if (command == CTAPHID_CANCEL) {
            // no response; the cancelled request answers with CTAP2_ERR_KEEPALIVE_CANCEL
            transaction?.takeIf { it.channel == channel }?.job?.cancel()
            return
        }
        val current = assembly
        if (current != null) {
            if (current.channel != channel) {
                sendError(channel, ERR_CHANNEL_BUSY)
            } else {
                // a new message before the last one was complete
                abortAssembly()
                sendError(channel, ERR_INVALID_SEQ)
            }
            return
        }
        if (transaction != null) {
            sendError(channel, ERR_CHANNEL_BUSY)
            return
        }
        if (length > MAX_MESSAGE_SIZE) {
            sendError(channel, ERR_INVALID_LEN)
            return
        }
        val assembly = Assembly(channel, command, ByteArray(length))
        val count = minOf(length, INIT_DATA_SIZE)
        buffer.get(assembly.data, 0, count)
        assembly.received = count
        if (assembly.received == length) {
            dispatch(channel, command, assembly.data)
        } else {
            assembly.timeout = scope.launch {
                delay(messageTimeoutMs)
                synchronized(lock) {
                    if (this@CtapHid.assembly === assembly) {
                        this@CtapHid.assembly = null
                        sendError(channel, ERR_MSG_TIMEOUT)
                    }
                }
            }
            this.assembly = assembly
        }
    }

    private fun onContinuationPacket(channel: Int, sequence: Int, buffer: ByteBuffer) {
        val assembly = assembly
        if (assembly == null || assembly.channel != channel) {
            // spurious, e.g. the rest of a message that was aborted
            return
        }
        if (sequence != assembly.nextSequence) {
            abortAssembly()
            sendError(channel, ERR_INVALID_SEQ)
            return
        }
        assembly.nextSequence++
        val count = minOf(assembly.data.size - assembly.received, CONTINUATION_DATA_SIZE)
        buffer.get(assembly.data, assembly.received, count)
        assembly.received += count
        if (assembly.received == assembly.data.size) {
            abortAssembly()
            dispatch(channel, assembly.command, assembly.data)
        }
    }

    private fun abortAssembly() {
        assembly?.timeout?.cancel()
        assembly = null
    }

    private fun init(channel: Int, length: Int, buffer: ByteBuffer) {
        if (length != INIT_NONCE_SIZE) {
            sendError(channel, ERR_INVALID_LEN)
            return
        }
        val nonce = ByteArray(INIT_NONCE_SIZE)
        buffer.get(nonce)
        val assigned = when {
            channel == BROADCAST -> allocateChannel()
            channel in channels -> {
                // resynchronize: abandon what runs on this channel
                if (assembly?.channel == channel) abortAssembly()
                transaction?.takeIf { it.channel == channel }?.let {
                    transaction = null
                    it.job.cancel()
                }
                channel
            }
            else -> {
                sendError(channel, ERR_INVALID_CHANNEL)
                return
            }
        }
        val response = ByteBuffer.allocate(17)
        response.put(nonce)
        response.putInt(assigned)
        response.put(PROTOCOL_VERSION)
        response.put(VERSION_MAJOR)
        response.put(VERSION_MINOR)
        response.put(VERSION_BUILD)
        // CBOR, but no U2F messages (NMSG)
        response.put((CAPABILITY_WINK or CAPABILITY_CBOR or CAPABILITY_NMSG).toByte())
        sendMessage(channel, CTAPHID_INIT, response.array())
    }

    private fun allocateChannel(): Int {
        var channel: Int
        do {
            channel = nextChannel++
        } while (channel == 0 || channel == BROADCAST || channel in channels)
        channels += channel
        if (channels.size > MAX_CHANNELS) {
            channels.remove(channels.first())
        }
        return channel
    }

    private fun dispatch(channel: Int, command: Int, data: ByteArray) {
        when (command) {
            CTAPHID_PING -> sendMessage(channel, CTAPHID_PING, data)
            CTAPHID_WINK -> {
                wink()
                sendMessage(channel, CTAPHID_WINK, ByteArray(0))
            }
            CTAPHID_CBOR -> startTransaction(channel, data)
            else -> sendError(channel, ERR_INVALID_CMD)
        }
    }

    private fun startTransaction(channel: Int, request: ByteArray) {
        val transaction = Transaction(channel)
        this.transaction = transaction
        // started once the job is assigned, for a dispatcher that would run it right away
        transaction.job = scope.launch(start = CoroutineStart.LAZY) {
            val keepalive = launch {
                while (true) {
                    delay(keepaliveIntervalMs)
                    synchronized(lock) {
                        if (this@CtapHid.transaction === transaction) {
                            sendMessage(channel, CTAPHID_KEEPALIVE, byteArrayOf(KEEPALIVE_STATUS_UPNEEDED))
                        }
                    }
                }
            }
            val response = try {
                process(request)
            } catch (e: CancellationException) {
                byteArrayOf(CTAP2_ERR_KEEPALIVE_CANCEL)
            } catch (e: Exception) {
                log.warn("Processing a CTAP2 request failed", e)
                byteArrayOf(CTAP1_ERR_OTHER)
            } finally {
                keepalive.cancel()
            }
            synchronized(lock) {
                // not if the channel was resynchronized meanwhile
                if (this@CtapHid.transaction === transaction) {
                    this@CtapHid.transaction = null
                    sendMessage(channel, CTAPHID_CBOR, response)
                }
            }
        }
        transaction.job.start()
    }

    private fun sendError(channel: Int, error: Byte) {
        sendMessage(channel, CTAPHID_ERROR, byteArrayOf(error))
    }

    /**
     * Send a message, split into an initialization packet and continuation packets.
     */
    private fun sendMessage(channel: Int, command: Int, data: ByteArray) {
        val first = ByteBuffer.allocate(REPORT_SIZE)
        first.putInt(channel)
        first.put(command.toByte())
        first.putShort(data.size.toShort())
        var offset = minOf(data.size, INIT_DATA_SIZE)
        first.put(data, 0, offset)
        send(first.array())
        var sequence = 0
        while (offset < data.size) {
            val packet = ByteBuffer.allocate(REPORT_SIZE)
            packet.putInt(channel)
            packet.put(sequence++.toByte())
            val count = minOf(data.size - offset, CONTINUATION_DATA_SIZE)
            packet.put(data, offset, count)
            offset += count
            send(packet.array())
        }
    }

    companion object {
        const val REPORT_SIZE = 64
        private const val INIT_DATA_SIZE = REPORT_SIZE - 7
        private const val CONTINUATION_DATA_SIZE = REPORT_SIZE - 5

        /** The largest message that fits into the 128 continuation packets */
        const val MAX_MESSAGE_SIZE = INIT_DATA_SIZE + 128 * CONTINUATION_DATA_SIZE

        const val BROADCAST = -1
        private const val INIT_NONCE_SIZE = 8
        private const val MAX_CHANNELS = 128

        private const val KEEPALIVE_INTERVAL_MS = 100L
        private const val MESSAGE_TIMEOUT_MS = 3000L

        const val CTAPHID_PING = 0x81
        const val CTAPHID_MSG = 0x83
        const val CTAPHID_INIT = 0x86
        const val CTAPHID_WINK = 0x88
        const val CTAPHID_CBOR = 0x90
        const val CTAPHID_CANCEL = 0x91
        const val CTAPHID_KEEPALIVE = 0xbb
        const val CTAPHID_ERROR = 0xbf

        const val ERR_INVALID_CMD: Byte = 0x01
        const val ERR_INVALID_LEN: Byte = 0x03
        const val ERR_INVALID_SEQ: Byte = 0x04
        const val ERR_MSG_TIMEOUT: Byte = 0x05
        const val ERR_CHANNEL_BUSY: Byte = 0x06
        const val ERR_INVALID_CHANNEL: Byte = 0x0b
        private const val CTAP1_ERR_OTHER: Byte = 0x7f

        const val KEEPALIVE_STATUS_UPNEEDED: Byte = 2

        private const val PROTOCOL_VERSION: Byte = 2
        private const val VERSION_MAJOR: Byte = 1
        private const val VERSION_MINOR: Byte = 0
        private const val VERSION_BUILD: Byte = 0
        private const val CAPABILITY_WINK = 0x01
        private const val CAPABILITY_CBOR = 0x04
        private const val CAPABILITY_NMSG = 0x08
    }
}
