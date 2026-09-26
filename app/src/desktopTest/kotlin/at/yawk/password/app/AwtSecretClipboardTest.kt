package at.yawk.password.app

import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.ClipboardOwner
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.awt.datatransfer.Transferable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Uses a private [Clipboard], which works without a display.
 */
class AwtSecretClipboardTest {
    private val clipboard = Clipboard("test")
    private val secretClipboard = AwtSecretClipboard(clipboard = { clipboard })

    private fun contents(): String? = clipboard.getContents(null)
        ?.takeIf { it.isDataFlavorSupported(DataFlavor.stringFlavor) }
        ?.getTransferData(DataFlavor.stringFlavor) as String?

    @Test
    fun clearsOwnSecret() {
        assertTrue(secretClipboard.copySecret("secret"))
        assertEquals("secret", contents())
        secretClipboard.clearIfOurs()
        assertEquals(null, contents())
    }

    @Test
    fun clearsAfterOwnershipMovedToClipboardManager() {
        secretClipboard.copySecret("secret")
        // a clipboard manager takes over the clipboard with the same contents
        clipboard.setContents(StringSelection("secret"), null)
        secretClipboard.clearIfOurs()
        assertEquals(null, contents())
    }

    @Test
    fun keepsOtherContents() {
        secretClipboard.copySecret("secret")
        clipboard.setContents(StringSelection("something else"), null)
        secretClipboard.clearIfOurs()
        assertEquals("something else", contents())
    }

    @Test
    fun unavailableClipboard() {
        val busy = object : Clipboard("busy") {
            override fun setContents(contents: Transferable?, owner: ClipboardOwner?) =
                throw IllegalStateException("cannot open system clipboard")
        }
        assertFalse(AwtSecretClipboard(clipboard = { busy }).copySecret("secret"))
    }
}
