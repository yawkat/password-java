package at.yawk.password.app.fido

import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.nio.file.Path
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * A connection to the `password-uhid` helper (`uhid-helper/` of this repository), which creates a FIDO security key
 * through Linux's uhid driver for us: a HID device with the FIDO alliance's usage page and 64-byte input and output
 * reports. Browsers, and systemd's `fido_id` (which lets the logged-in user open it), recognize it by that.
 *
 * After a status byte, the helper and we exchange bare 64-byte reports. The device is gone when this is closed.
 */
class UhidHelper private constructor(private val channel: SocketChannel) : Closeable {
    private val readBuffer = ByteBuffer.allocate(CtapHid.REPORT_SIZE)

    /**
     * Wait for the next output report from the host. Closing this from another thread makes it throw
     * [java.nio.channels.ClosedChannelException].
     */
    fun read(): ByteArray {
        val buffer = readBuffer
        buffer.clear()
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) < 0) {
                throw EOFException("The security key helper ended the connection")
            }
        }
        return buffer.array().copyOf()
    }

    /**
     * Send an input report to the host.
     */
    @Synchronized
    fun sendInput(report: ByteArray) {
        require(report.size == CtapHid.REPORT_SIZE)
        val buffer = ByteBuffer.wrap(report)
        while (buffer.hasRemaining()) {
            channel.write(buffer)
        }
    }

    /**
     * Remove the device.
     */
    override fun close() {
        channel.close()
    }

    companion object {
        /** The socket of the helper (`uhid-helper/password-uhid.socket`) */
        const val SOCKET = "/run/password-uhid.sock"

        /**
         * Create the security key.
         *
         * @throws IOException if the helper isn't there, we may not use it, or it can't create the device
         */
        fun connect(socket: Path = Path.of(SOCKET), timeout: Duration = 10.seconds): UhidHelper {
            val channel = try {
                SocketChannel.open(UnixDomainSocketAddress.of(socket))
            } catch (e: IOException) {
                throw IOException("Could not connect to the security key helper at $socket: ${e.message}", e)
            }
            try {
                // one byte first: 0 if the device was created, otherwise the helper's errno. Don't wait forever if
                // the helper doesn't start.
                val status = ByteBuffer.allocate(1)
                channel.configureBlocking(false)
                Selector.open().use { selector ->
                    channel.register(selector, SelectionKey.OP_READ)
                    val deadline = System.nanoTime() + timeout.inWholeNanoseconds
                    while (status.hasRemaining()) {
                        val remaining = (deadline - System.nanoTime()) / 1_000_000
                        if (remaining <= 0) {
                            throw IOException("The security key helper at $socket did not answer")
                        }
                        selector.select(remaining)
                        if (channel.read(status) < 0) {
                            throw EOFException("The security key helper at $socket closed the connection")
                        }
                    }
                }
                channel.configureBlocking(true)
                val errno = status.get(0).toInt() and 0xff
                if (errno != 0) {
                    throw IOException("The security key helper at $socket could not create the device (errno $errno)")
                }
            } catch (e: IOException) {
                channel.close()
                throw e
            }
            return UhidHelper(channel)
        }
    }
}
