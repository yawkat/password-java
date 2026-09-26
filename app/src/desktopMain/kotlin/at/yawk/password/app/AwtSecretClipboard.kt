package at.yawk.password.app

import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.SystemFlavorMap
import java.awt.datatransfer.Transferable
import java.awt.datatransfer.UnsupportedFlavorException
import java.io.ByteArrayInputStream
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(AwtSecretClipboard::class.java)

/**
 * Copies secrets to the system clipboard through AWT and removes them again after [clearAfterSeconds], like the old
 * Qt GUI's `ClipboardHelper`. The clipboard is only cleared if it still holds the secret we put there.
 *
 * Like the Qt GUI, this compares the contents and ignores ownership: a clipboard manager may take over the
 * clipboard (and with it the ownership) while keeping our secret in it.
 */
class AwtSecretClipboard(
    override val clearAfterSeconds: Int = CLEAR_AFTER_SECONDS,
    private val clipboard: () -> Clipboard = { Toolkit.getDefaultToolkit().systemClipboard },
) : SecretClipboard {
    private val timer = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "clipboard-clear").apply { isDaemon = true }
    }

    private var copiedSecret: String? = null
    private var pendingClear: ScheduledFuture<*>? = null

    @Synchronized
    override fun copySecret(text: String): Boolean {
        try {
            clipboard().setContents(SecretTransferable(text), null)
        } catch (e: IllegalStateException) {
            // the clipboard is currently unavailable
            log.warn("Could not copy to clipboard", e)
            return false
        }
        copiedSecret = text
        pendingClear?.cancel(false)
        pendingClear = timer.schedule(::clearIfOurs, clearAfterSeconds.toLong(), TimeUnit.SECONDS)
        return true
    }

    @Synchronized
    override fun clearIfOurs() {
        val secret = copiedSecret ?: return
        copiedSecret = null
        pendingClear?.cancel(false)
        pendingClear = null
        try {
            val clipboard = clipboard()
            val current = clipboard.getContents(null)
            if (current != null &&
                current.isDataFlavorSupported(DataFlavor.stringFlavor) &&
                current.getTransferData(DataFlavor.stringFlavor) == secret
            ) {
                clipboard.setContents(EmptyTransferable, null)
            }
        } catch (e: Exception) {
            log.warn("Could not clear clipboard", e)
        }
    }

    private class SecretTransferable(private val text: String) : Transferable {
        override fun getTransferDataFlavors() = arrayOf(DataFlavor.stringFlavor, PASSWORD_MANAGER_HINT)

        override fun isDataFlavorSupported(flavor: DataFlavor) = flavor in transferDataFlavors

        override fun getTransferData(flavor: DataFlavor): Any = when (flavor) {
            DataFlavor.stringFlavor -> text
            PASSWORD_MANAGER_HINT -> ByteArrayInputStream("secret".toByteArray(Charsets.US_ASCII))
            else -> throw UnsupportedFlavorException(flavor)
        }
    }

    private object EmptyTransferable : Transferable {
        override fun getTransferDataFlavors() = arrayOf<DataFlavor>()
        override fun isDataFlavorSupported(flavor: DataFlavor) = false
        override fun getTransferData(flavor: DataFlavor): Any = throw UnsupportedFlavorException(flavor)
    }

    companion object {
        const val CLEAR_AFTER_SECONDS = 30

        /**
         * Tells KDE Klipper (and other clipboard managers honoring it) not to keep the entry in its history. The
         * native (X11 target) name has no MIME type syntax, so it is mapped onto a private flavor.
         */
        private val PASSWORD_MANAGER_HINT: DataFlavor =
            DataFlavor("application/x-kde-passwordmanagerhint;class=java.io.InputStream").also { flavor ->
                val map = SystemFlavorMap.getDefaultFlavorMap() as? SystemFlavorMap
                map?.addUnencodedNativeForFlavor(flavor, "x-kde-passwordManagerHint")
                map?.addFlavorForUnencodedNative("x-kde-passwordManagerHint", flavor)
            }
    }
}
