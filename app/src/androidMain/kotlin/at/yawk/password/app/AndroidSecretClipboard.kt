package at.yawk.password.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.util.Log

/**
 * Copies secrets to the Android clipboard, marked as sensitive so the system (and keyboards honoring it) don't show or
 * keep them, and removes them again after [clearAfterSeconds].
 *
 * Android only lets the focused app read the clipboard. Usually the app is in the background when the timer runs out
 * (the user switched away to paste), so the clipboard can't be checked then and is cleared regardless of what it holds.
 * While the app can read the clipboard, it is only cleared if it still holds our secret.
 */
class AndroidSecretClipboard internal constructor(
    private val clipboard: ClipboardAccess,
    private val scheduler: Scheduler,
    override val clearAfterSeconds: Int = CLEAR_AFTER_SECONDS,
) : SecretClipboard {
    constructor(context: Context) : this(SystemClipboard(context), MainLooperScheduler())

    private var copiedSecret: String? = null
    private var cancelClear: (() -> Unit)? = null

    @Synchronized
    override fun copySecret(text: String): Boolean {
        try {
            clipboard.setSensitive(text)
        } catch (e: RuntimeException) {
            Log.w(TAG, "Could not copy to the clipboard", e)
            return false
        }
        copiedSecret = text
        cancelClear?.invoke()
        cancelClear = scheduler.schedule(clearAfterSeconds * 1000L, ::clearIfOurs)
        return true
    }

    @Synchronized
    override fun clearIfOurs() {
        val secret = copiedSecret ?: return
        copiedSecret = null
        cancelClear?.invoke()
        cancelClear = null
        try {
            val current = clipboard.readText()
            // null: not readable (in the background) or already empty
            if (current == null || current == secret) {
                clipboard.clear()
            }
        } catch (e: RuntimeException) {
            Log.w(TAG, "Could not clear the clipboard", e)
        }
    }

    /**
     * The parts of [ClipboardManager] used here, to test without a device.
     */
    internal interface ClipboardAccess {
        fun setSensitive(text: String)

        /**
         * @return The text on the clipboard, `""` if it holds something other than text, or `null` if it is empty or
         * can't be read right now.
         */
        fun readText(): String?

        fun clear()
    }

    internal fun interface Scheduler {
        /**
         * Run [task] after [delayMillis].
         *
         * @return Cancels the task
         */
        fun schedule(delayMillis: Long, task: () -> Unit): () -> Unit
    }

    private class SystemClipboard(context: Context) : ClipboardAccess {
        private val manager = context.getSystemService(ClipboardManager::class.java)

        override fun setSensitive(text: String) {
            val clip = ClipData.newPlainText("Password", text)
            clip.description.extras = PersistableBundle().apply {
                putBoolean(
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        ClipDescription.EXTRA_IS_SENSITIVE
                    } else {
                        // the same key, understood by some keyboards and clipboard managers before Android 13
                        "android.content.extra.IS_SENSITIVE"
                    },
                    true,
                )
            }
            manager.setPrimaryClip(clip)
        }

        override fun readText(): String? {
            val clip = manager.primaryClip ?: return null
            if (clip.itemCount == 0) {
                return null
            }
            return clip.getItemAt(0).text?.toString() ?: ""
        }

        override fun clear() = manager.clearPrimaryClip()
    }

    private class MainLooperScheduler : Scheduler {
        private val handler = Handler(Looper.getMainLooper())

        override fun schedule(delayMillis: Long, task: () -> Unit): () -> Unit {
            val runnable = Runnable(task)
            handler.postDelayed(runnable, delayMillis)
            return { handler.removeCallbacks(runnable) }
        }
    }

    companion object {
        const val CLEAR_AFTER_SECONDS = 30
        private const val TAG = "SecretClipboard"
    }
}
