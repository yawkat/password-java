package at.yawk.password.app.fido

import at.yawk.password.app.fido.Uhid.Companion.putCreate2
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

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
}
