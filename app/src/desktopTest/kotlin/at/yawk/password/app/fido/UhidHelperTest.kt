package at.yawk.password.app.fido

import java.io.EOFException
import java.io.IOException
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ClosedChannelException
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.file.Path
import kotlin.concurrent.thread
import kotlin.io.path.createTempDirectory
import kotlin.io.path.deleteRecursively
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

class UhidHelperTest {
    private lateinit var dir: Path
    private lateinit var socket: Path

    @BeforeTest
    fun setup() {
        dir = createTempDirectory("uhid")
        socket = dir.resolve("helper.sock")
    }

    @AfterTest
    @OptIn(kotlin.io.path.ExperimentalPathApi::class)
    fun cleanup() {
        dir.deleteRecursively()
    }

    private fun readFully(channel: SocketChannel, size: Int): ByteArray? {
        val buffer = ByteBuffer.allocate(size)
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) < 0) return null
        }
        return buffer.array()
    }

    /**
     * A helper at [socket] that sends [status] (if any) and then runs [session] with the connection.
     */
    private fun fakeHelper(status: Int?, session: (SocketChannel) -> Unit = {}): Thread {
        val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX).bind(UnixDomainSocketAddress.of(socket))
        return thread {
            server.use {
                server.accept().use { channel ->
                    if (status != null) {
                        channel.write(ByteBuffer.wrap(byteArrayOf(status.toByte())))
                    }
                    session(channel)
                }
            }
        }
    }

    @Test
    fun reports() {
        var received: ByteArray? = null
        var end: ByteArray? = null
        val helper = fakeHelper(0) { channel ->
            // an output report from the host, in two pieces
            val report = ByteArray(64) { it.toByte() }
            channel.write(ByteBuffer.wrap(report, 0, 10))
            Thread.sleep(50)
            channel.write(ByteBuffer.wrap(report, 10, 54))
            received = readFully(channel, 64)
            // closing ends the connection
            end = readFully(channel, 1)
        }
        val uhid = UhidHelper.connect(socket)
        assertContentEquals(ByteArray(64) { it.toByte() }, uhid.read())
        uhid.sendInput(ByteArray(64) { 7 })
        uhid.close()
        helper.join()
        assertContentEquals(ByteArray(64) { 7 }, received)
        assertEquals(null, end)
        assertFailsWith<ClosedChannelException> { uhid.read() }
    }

    @Test
    fun onlyWholeReports() {
        val helper = fakeHelper(0)
        UhidHelper.connect(socket).use { uhid ->
            assertFailsWith<IllegalArgumentException> { uhid.sendInput(ByteArray(65)) }
            helper.join()
            // the helper ended the connection
            assertFailsWith<EOFException> { uhid.read() }
        }
    }

    @Test
    fun error() {
        val helper = fakeHelper(2)
        val e = assertFailsWith<IOException> { UhidHelper.connect(socket) }
        helper.join()
        assertTrue(e.message!!.contains("errno 2"), e.message)
    }

    @Test
    fun noAnswer() {
        val helper = fakeHelper(null) { Thread.sleep(500) }
        val e = assertFailsWith<IOException> { UhidHelper.connect(socket, 100.milliseconds) }
        helper.join()
        assertTrue(e.message!!.contains("did not answer"), e.message)
    }

    @Test
    fun closedWithoutStatus() {
        val helper = fakeHelper(null)
        assertFailsWith<EOFException> { UhidHelper.connect(socket) }
        helper.join()
    }

    @Test
    fun missing() {
        val e = assertFailsWith<IOException> { UhidHelper.connect(socket) }
        assertTrue(e.message!!.contains("Could not connect to the security key helper"), e.message)
    }
}
