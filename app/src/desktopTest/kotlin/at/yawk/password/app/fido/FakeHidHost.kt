package at.yawk.password.app.fido

import java.nio.ByteBuffer
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.fail

/**
 * The host side of CTAPHID, as a browser would talk to [CtapHid]: frames requests into reports and puts the responses
 * back together.
 */
class FakeHidHost {
    /** Input reports the key sent */
    val reports = LinkedBlockingQueue<ByteArray>()

    lateinit var hid: CtapHid

    fun sendReport(report: ByteArray) {
        assertEquals(CtapHid.REPORT_SIZE, report.size)
        hid.onReport(report)
    }

    fun send(channel: Int, command: Int, data: ByteArray) {
        frame(channel, command, data).forEach(::sendReport)
    }

    /**
     * The next message, keepalives included.
     */
    fun receiveAny(timeoutMs: Long = 10_000): Message {
        val first = nextReport(timeoutMs)
        val buffer = ByteBuffer.wrap(first)
        val channel = buffer.int
        val command = buffer.get().toInt() and 0xff
        if (command and 0x80 == 0) fail("Expected an initialization packet, got sequence $command")
        val length = buffer.short.toInt() and 0xffff
        val data = ByteArray(length)
        var received = minOf(length, 57)
        buffer.get(data, 0, received)
        var sequence = 0
        while (received < length) {
            val next = ByteBuffer.wrap(nextReport(timeoutMs))
            assertEquals(channel, next.int)
            assertEquals(sequence++, next.get().toInt())
            val count = minOf(length - received, 59)
            next.get(data, received, count)
            received += count
        }
        return Message(channel, command, data)
    }

    /**
     * The next message other than a keepalive.
     */
    fun receive(timeoutMs: Long = 10_000): Message {
        while (true) {
            val message = receiveAny(timeoutMs)
            if (message.command != CtapHid.CTAPHID_KEEPALIVE) return message
        }
    }

    private fun nextReport(timeoutMs: Long): ByteArray =
        assertNotNull(reports.poll(timeoutMs, TimeUnit.MILLISECONDS), "No report from the key")

    /**
     * Allocate a channel with INIT.
     */
    fun init(): Int {
        val nonce = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        send(CtapHid.BROADCAST, CtapHid.CTAPHID_INIT, nonce)
        val response = receive()
        assertEquals(CtapHid.BROADCAST, response.channel)
        assertEquals(CtapHid.CTAPHID_INIT, response.command)
        assertEquals(17, response.data.size)
        assertEquals(nonce.toList(), response.data.copyOf(8).toList())
        return ByteBuffer.wrap(response.data, 8, 4).int
    }

    /**
     * A CTAP2 request and its response.
     */
    fun cbor(channel: Int, request: ByteArray): ByteArray {
        send(channel, CtapHid.CTAPHID_CBOR, request)
        val response = receive()
        assertEquals(channel, response.channel)
        assertEquals(CtapHid.CTAPHID_CBOR, response.command, "error ${response.data.toList()}")
        return response.data
    }

    class Message(val channel: Int, val command: Int, val data: ByteArray)

    companion object {
        fun frame(channel: Int, command: Int, data: ByteArray): List<ByteArray> {
            val reports = mutableListOf<ByteArray>()
            val first = ByteBuffer.allocate(CtapHid.REPORT_SIZE)
            first.putInt(channel)
            first.put(command.toByte())
            first.putShort(data.size.toShort())
            var offset = minOf(data.size, 57)
            first.put(data, 0, offset)
            reports += first.array()
            var sequence = 0
            while (offset < data.size) {
                val packet = ByteBuffer.allocate(CtapHid.REPORT_SIZE)
                packet.putInt(channel)
                packet.put(sequence++.toByte())
                val count = minOf(data.size - offset, 59)
                packet.put(data, offset, count)
                offset += count
                reports += packet.array()
            }
            return reports
        }
    }
}
