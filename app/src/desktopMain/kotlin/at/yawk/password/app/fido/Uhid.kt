package at.yawk.password.app.fido

import java.io.Closeable
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/**
 * A virtual HID device of Linux's uhid driver (`/dev/uhid`, see the kernel's `Documentation/hid/uhid.rst`): the kernel
 * makes a hidraw device of it, as if it was plugged in. The events are the C structs of `linux/uhid.h`, in the byte
 * order of the machine.
 *
 * The device is gone when this is closed.
 */
class Uhid private constructor(private val channel: FileChannel) : Closeable {
    private val writeBuffer = ByteBuffer.allocateDirect(EVENT_SIZE).order(ByteOrder.nativeOrder())
    private val readBuffer = ByteBuffer.allocateDirect(EVENT_SIZE).order(ByteOrder.nativeOrder())

    sealed interface Event {
        /** An output report from the host, without the report number */
        class Output(val data: ByteArray) : Event

        /** A GET_REPORT request, which must be answered with [Uhid.replyGetReport] */
        class GetReport(val id: Int) : Event

        /** A SET_REPORT request, which must be answered with [Uhid.replySetReport] */
        class SetReport(val id: Int) : Event

        /** START, STOP, OPEN, CLOSE: nothing to do */
        data class Other(val type: Int) : Event
    }

    /**
     * Wait for the next event. Closing the device from another thread makes this throw.
     */
    fun read(): Event {
        val buffer = readBuffer
        buffer.clear()
        val read = channel.read(buffer)
        if (read < 4) {
            throw IOException("Short read from uhid: $read")
        }
        val type = buffer.getInt(0)
        return when (type) {
            UHID_OUTPUT -> {
                val size = (buffer.getShort(OUTPUT_SIZE_OFFSET).toInt() and 0xffff).coerceAtMost(DATA_MAX)
                val data = ByteArray(size)
                buffer.get(4, data)
                // Our report descriptor has no report IDs, so hidraw puts a 0 in front of the report
                if (size == CtapHid.REPORT_SIZE + 1 && data[0] == 0.toByte()) {
                    Event.Output(data.copyOfRange(1, size))
                } else {
                    Event.Output(data)
                }
            }
            UHID_GET_REPORT -> Event.GetReport(buffer.getInt(4))
            UHID_SET_REPORT -> Event.SetReport(buffer.getInt(4))
            else -> Event.Other(type)
        }
    }

    /**
     * Send an input report to the host.
     */
    @Synchronized
    fun sendInput(report: ByteArray) {
        require(report.size <= DATA_MAX)
        write(UHID_INPUT2) {
            putShort(report.size.toShort())
            put(report)
        }
    }

    /**
     * We have no feature reports: fail the request.
     */
    @Synchronized
    fun replyGetReport(id: Int) {
        write(UHID_GET_REPORT_REPLY) {
            putInt(id)
            putShort(EIO)
            putShort(0)
        }
    }

    @Synchronized
    fun replySetReport(id: Int) {
        write(UHID_SET_REPORT_REPLY) {
            putInt(id)
            putShort(EIO)
        }
    }

    private inline fun write(type: Int, body: ByteBuffer.() -> Unit) {
        val buffer = writeBuffer
        buffer.clear()
        buffer.putInt(type)
        buffer.body()
        buffer.flip()
        while (buffer.hasRemaining()) {
            channel.write(buffer)
        }
    }

    /**
     * Remove the device.
     */
    override fun close() {
        try {
            synchronized(this) { write(UHID_DESTROY) {} }
        } catch (e: IOException) {
            // closing removes it as well
        } finally {
            channel.close()
        }
    }

    companion object {
        const val DEFAULT_PATH = "/dev/uhid"

        /**
         * Create a FIDO security key: a HID device with the FIDO alliance's usage page and 64-byte input and output
         * reports. Browsers, and systemd's `fido_id` (which lets the logged-in user open it), recognize it by that.
         *
         * @throws IOException if `/dev/uhid` can't be opened, e.g. for lack of permission
         */
        fun createSecurityKey(name: String, path: Path = Path.of(DEFAULT_PATH)): Uhid {
            val channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)
            val uhid = Uhid(channel)
            try {
                uhid.write(UHID_CREATE2) { putCreate2(name, FIDO_REPORT_DESCRIPTOR) }
            } catch (e: IOException) {
                channel.close()
                throw e
            }
            return uhid
        }

        /**
         * The `uhid_create2_req` for a USB device, after the event type.
         */
        internal fun ByteBuffer.putCreate2(name: String, descriptor: ByteArray) {
            val start = position()
            putString(name, 128)
            putString("", 64) // phys
            putString("", 64) // uniq
            putShort(descriptor.size.toShort())
            putShort(BUS_USB)
            putInt(0) // vendor
            putInt(0) // product
            putInt(0) // version
            putInt(0) // country
            put(descriptor)
            position(start + CREATE2_SIZE)
        }

        private fun ByteBuffer.putString(text: String, size: Int) {
            val bytes = text.toByteArray(StandardCharsets.UTF_8)
            // NUL-terminated
            val count = minOf(bytes.size, size - 1)
            put(bytes, 0, count)
            put(ByteArray(size - count))
        }

        // enum uhid_event_type
        internal const val UHID_DESTROY = 1
        internal const val UHID_OUTPUT = 6
        internal const val UHID_GET_REPORT = 9
        internal const val UHID_GET_REPORT_REPLY = 10
        internal const val UHID_CREATE2 = 11
        internal const val UHID_INPUT2 = 12
        internal const val UHID_SET_REPORT = 13
        internal const val UHID_SET_REPORT_REPLY = 14

        private const val BUS_USB: Short = 3
        private const val EIO: Short = 5

        /** UHID_DATA_MAX and HID_MAX_DESCRIPTOR_SIZE */
        internal const val DATA_MAX = 4096

        /** sizeof(struct uhid_create2_req), the largest member of the union */
        internal const val CREATE2_SIZE = 128 + 64 + 64 + 2 + 2 + 4 * 4 + DATA_MAX

        /**
         * sizeof(struct uhid_event): the union is aligned to 8 bytes (the legacy `uhid_create_req` has a pointer),
         * which pads it beyond [CREATE2_SIZE]
         */
        internal const val EVENT_SIZE = 4 + (CREATE2_SIZE + 7) / 8 * 8

        /** Offset of `size` in an UHID_OUTPUT event, after `data` */
        private const val OUTPUT_SIZE_OFFSET = 4 + DATA_MAX

        /**
         * FIDO usage page (0xF1D0), CTAPHID usage, 64 bytes of input (usage 0x20) and output (usage 0x21)
         */
        internal val FIDO_REPORT_DESCRIPTOR = byteArrayOf(
            0x06, 0xd0.toByte(), 0xf1.toByte(), // Usage Page (FIDO Alliance)
            0x09, 0x01, // Usage (CTAPHID)
            0xa1.toByte(), 0x01, // Collection (Application)
            0x09, 0x20, //   Usage (Input Report Data)
            0x15, 0x00, //   Logical Minimum (0)
            0x26, 0xff.toByte(), 0x00, //   Logical Maximum (255)
            0x75, 0x08, //   Report Size (8)
            0x95.toByte(), 0x40, //   Report Count (64)
            0x81.toByte(), 0x02, //   Input (Data, Variable, Absolute)
            0x09, 0x21, //   Usage (Output Report Data)
            0x15, 0x00, //   Logical Minimum (0)
            0x26, 0xff.toByte(), 0x00, //   Logical Maximum (255)
            0x75, 0x08, //   Report Size (8)
            0x95.toByte(), 0x40, //   Report Count (64)
            0x91.toByte(), 0x02, //   Output (Data, Variable, Absolute)
            0xc0.toByte(), // End Collection
        )
    }
}
