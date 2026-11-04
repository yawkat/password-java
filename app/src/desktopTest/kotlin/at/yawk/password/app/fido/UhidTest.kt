package at.yawk.password.app.fido

import at.yawk.password.app.fido.Uhid.Companion.putCreate2
import java.io.IOException
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.Path
import kotlin.concurrent.thread
import kotlin.io.path.createTempDirectory
import kotlin.io.path.deleteRecursively
import kotlin.io.path.readBytes
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class UhidTest {
    @Test
    fun sizes() {
        // of linux/uhid.h
        assertEquals(4380, Uhid.EVENT_SIZE)
        assertEquals(4372, Uhid.CREATE2_SIZE)
    }

    @Test
    fun create2() {
        val buffer = ByteBuffer.allocate(Uhid.EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(Uhid.UHID_CREATE2)
        buffer.putCreate2("key", Uhid.FIDO_REPORT_DESCRIPTOR)
        assertEquals(4 + Uhid.CREATE2_SIZE, buffer.position())
        assertEquals(11, buffer.getInt(0))
        assertContentEquals("key".toByteArray() + 0, ByteArray(4).also { buffer.get(4, it) })
        // rd_size and bus after name[128], phys[64], uniq[64]
        assertEquals(Uhid.FIDO_REPORT_DESCRIPTOR.size, buffer.getShort(4 + 256).toInt())
        assertEquals(3, buffer.getShort(4 + 258).toInt())
        // rd_data after vendor, product, version and country
        val descriptor = ByteArray(Uhid.FIDO_REPORT_DESCRIPTOR.size)
        buffer.get(4 + 276, descriptor)
        assertContentEquals(Uhid.FIDO_REPORT_DESCRIPTOR, descriptor)
    }

    @Test
    fun longNameIsTruncated() {
        val buffer = ByteBuffer.allocate(Uhid.EVENT_SIZE)
        buffer.putCreate2("x".repeat(200), ByteArray(0))
        assertEquals(0, buffer.get(127).toInt())
        assertEquals('x'.code, buffer.get(126).toInt())
    }

    @Test
    fun descriptor() {
        // the FIDO usage page, which browsers and systemd's fido_id look for
        assertContentEquals(byteArrayOf(0x06, 0xd0.toByte(), 0xf1.toByte(), 0x09, 0x01), Uhid.FIDO_REPORT_DESCRIPTOR.copyOf(5))
    }

    private lateinit var dir: Path

    @BeforeTest
    fun setup() {
        dir = createTempDirectory("uhid")
    }

    @AfterTest
    @OptIn(kotlin.io.path.ExperimentalPathApi::class)
    fun cleanup() {
        dir.deleteRecursively()
    }

    private fun readEvent(channel: SocketChannel): ByteBuffer {
        val buffer = ByteBuffer.allocate(Uhid.EVENT_SIZE).order(ByteOrder.nativeOrder())
        while (buffer.hasRemaining()) {
            check(channel.read(buffer) >= 0)
        }
        return buffer.flip()
    }

    /**
     * A helper at [socket] that sends [status] and then runs [session] with the connection.
     */
    private fun fakeHelper(socket: Path, status: Int, session: (SocketChannel) -> Unit = {}): Thread {
        val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX).bind(UnixDomainSocketAddress.of(socket))
        return thread {
            server.use {
                server.accept().use { channel ->
                    channel.write(ByteBuffer.wrap(byteArrayOf(status.toByte())))
                    session(channel)
                }
            }
        }
    }

    @Test
    fun helper() {
        val socket = dir.resolve("helper.sock")
        val received = mutableListOf<ByteBuffer>()
        val helper = fakeHelper(socket, 0) { channel ->
            // an output report from the host, in two pieces
            val output = ByteBuffer.allocate(Uhid.EVENT_SIZE).order(ByteOrder.nativeOrder())
            output.putInt(Uhid.UHID_OUTPUT)
            output.put(ByteArray(64) { 7 })
            output.putShort(4 + Uhid.DATA_MAX, 64.toShort())
            channel.write(output.slice(0, 100))
            Thread.sleep(50)
            channel.write(output.slice(100, Uhid.EVENT_SIZE - 100))
            // the reply, then DESTROY when closed
            received += readEvent(channel)
            received += readEvent(channel)
        }
        // never touched while the helper is there
        val device = dir.resolve("missing")
        val uhid = Uhid.createSecurityKey(socket, device)
        val event = assertIs<Uhid.Event.Output>(uhid.read())
        assertContentEquals(ByteArray(64) { 7 }, event.data)
        uhid.sendInput(byteArrayOf(1, 2, 3))
        uhid.close()
        helper.join()

        // whole events, padded with zeros
        val input = received[0]
        assertEquals(Uhid.UHID_INPUT2, input.getInt(0))
        assertEquals(3, input.getShort(4).toInt())
        assertEquals(listOf<Byte>(1, 2, 3), (6 until 9).map { input.get(it) })
        assertTrue((9 until Uhid.EVENT_SIZE).all { input.get(it) == 0.toByte() })
        assertEquals(Uhid.UHID_DESTROY, received[1].getInt(0))
        assertTrue((4 until Uhid.EVENT_SIZE).all { received[1].get(it) == 0.toByte() })
        assertTrue(Files.notExists(device))
    }

    @Test
    fun helperError() {
        val socket = dir.resolve("helper.sock")
        val helper = fakeHelper(socket, 2)
        val e = assertFailsWith<IOException> { Uhid.createSecurityKey(socket, dir.resolve("missing")) }
        helper.join()
        assertTrue(e.message!!.contains("errno 2"), e.message)
        // the direct attempt failed as well
        assertEquals(1, e.suppressed.size)
    }

    @Test
    fun helperErrorFallsBackToDevice() {
        val socket = dir.resolve("helper.sock")
        val helper = fakeHelper(socket, 13)
        // a file stands in for /dev/uhid
        val device = Files.createFile(dir.resolve("uhid"))
        Uhid.createSecurityKey(socket, device).close()
        helper.join()
        val written = device.readBytes()
        assertEquals(2 * Uhid.EVENT_SIZE, written.size)
        val events = ByteBuffer.wrap(written).order(ByteOrder.nativeOrder())
        assertEquals(Uhid.UHID_CREATE2, events.getInt(0))
        assertEquals(Uhid.UHID_DESTROY, events.getInt(Uhid.EVENT_SIZE))
    }

    @Test
    fun withoutHelper() {
        val device = Files.createFile(dir.resolve("uhid"))
        Uhid.createSecurityKey(dir.resolve("missing.sock"), device).close()
        val events = ByteBuffer.wrap(device.readBytes()).order(ByteOrder.nativeOrder())
        assertEquals(Uhid.UHID_CREATE2, events.getInt(0))
        assertEquals("password-java security key", String(device.readBytes(), 4, 26))
        assertEquals(0, events.get(4 + 26).toInt())
    }

    @Test
    fun neither() {
        val e = assertFailsWith<IOException> {
            Uhid.createSecurityKey(dir.resolve("missing.sock"), dir.resolve("missing"))
        }
        assertEquals(0, e.suppressed.size)
    }
}
