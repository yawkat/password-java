package at.yawk.password.app

import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatReader
import com.google.zxing.qrcode.QRCodeWriter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class QrDecodeTest {
    private val text = "otpauth://totp/Hetzner:me?secret=KRSXG5CTMVRXEZLU&issuer=Hetzner"

    /**
     * A camera frame's luminance plane: rows of [rowStride] bytes, the last one without the padding.
     */
    private fun frame(width: Int, height: Int, rowStride: Int): ByteArray {
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height)
        val data = ByteArray(rowStride * (height - 1) + width) { 0x55 }
        for (y in 0 until height) {
            for (x in 0 until width) {
                data[y * rowStride + x] = if (matrix[x, y]) 0 else 0xff.toByte()
            }
        }
        return data
    }

    @Test
    fun decodesPaddedRows() {
        val reader = MultiFormatReader()
        assertEquals(text, decodeLuminance(reader, frame(480, 360, 512), 512, 480, 360))
        // the reader is reset between frames
        assertEquals(text, decodeLuminance(reader, frame(480, 360, 480), 480, 480, 360))
    }

    @Test
    fun noCode() {
        val data = ByteArray(480 * 360) { 0x7f }
        assertNull(decodeLuminance(MultiFormatReader(), data, 480, 480, 360))
    }
}
