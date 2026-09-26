package at.yawk.password.app

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle
import android.os.SystemClock
import android.util.Log

/**
 * Copies secrets to the Android clipboard, marked as sensitive so the system (and keyboards honoring it) don't show or
 * keep them, and removes them again after [clearAfterSeconds].
 *
 * Android only lets the focused app read the clipboard. Usually the app is in the background when the timer runs out
 * (the user switched away to paste), so the clipboard can't be checked then and is cleared regardless of what it holds.
 * While the app can read the clipboard, it is only cleared if it still holds our secret.
 *
 * The timer is an alarm ([ClipboardClearReceiver]) rather than a handler of the app's own thread, which would not run
 * while Android has frozen the (cached) process or the device sleeps, and not at all once the process is gone.
 */
class AndroidSecretClipboard internal constructor(
    private val clipboard: ClipboardAccess,
    private val scheduler: Scheduler,
    override val clearAfterSeconds: Int = CLEAR_AFTER_SECONDS,
) : SecretClipboard {
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
        cancelClear = scheduler.schedule(clearAfterSeconds * 1000L)
        return true
    }

    @Synchronized
    override fun clearIfOurs() {
        val secret = copiedSecret ?: return
        copiedSecret = null
        cancelClear?.invoke()
        cancelClear = null
        clear { it == null || it == secret }
    }

    /**
     * The clear timer ran out.
     */
    @Synchronized
    internal fun onTimer() {
        if (copiedSecret != null) {
            clearIfOurs()
        } else {
            // The process was restarted since the copy, so the secret is unknown. Clear the clipboard unless we can
            // see what it holds (then the app has the focus and the user copied something else).
            cancelClear = null
            clear { it == null }
        }
    }

    /**
     * Clear the clipboard if [condition] holds for its current text (`null` if it can't be read).
     */
    private fun clear(condition: (String?) -> Boolean) {
        try {
            if (condition(clipboard.readText())) {
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
         * Call [onTimer] after [delayMillis], replacing any earlier schedule.
         *
         * @return Cancels it
         */
        fun schedule(delayMillis: Long): () -> Unit
    }

    private class SystemClipboard(context: Context) : ClipboardAccess {
        private val manager = context.getSystemService(ClipboardManager::class.java)

        override fun setSensitive(text: String) {
            val clip = ClipData.newPlainText("Password", text)
            clip.description.extras = PersistableBundle().apply {
                // ClipDescription.EXTRA_IS_SENSITIVE, which Android 13 made public; keyboards and clipboard managers
                // understood the key before that already
                putBoolean("android.content.extra.IS_SENSITIVE", true)
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

    /**
     * An inexact alarm that wakes the device: exact alarms need an extra permission, and a few seconds later don't
     * matter. It survives the process, see [onTimer].
     */
    private class AlarmScheduler(private val context: Context) : Scheduler {
        private val alarms = context.getSystemService(AlarmManager::class.java)

        private fun intent() = PendingIntent.getBroadcast(
            context,
            0,
            Intent(context, ClipboardClearReceiver::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        override fun schedule(delayMillis: Long): () -> Unit {
            val intent = intent()
            alarms.setWindow(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + delayMillis,
                ALARM_WINDOW_MS,
                intent,
            )
            return { alarms.cancel(intent) }
        }
    }

    companion object {
        const val CLEAR_AFTER_SECONDS = 30
        private const val ALARM_WINDOW_MS = 10_000L
        private const val TAG = "SecretClipboard"

        @Volatile
        private var instance: AndroidSecretClipboard? = null

        /**
         * The process-wide instance, which the alarm reaches as well.
         */
        fun get(context: Context): AndroidSecretClipboard = instance ?: synchronized(this) {
            instance ?: context.applicationContext.let {
                AndroidSecretClipboard(SystemClipboard(it), AlarmScheduler(it))
            }.also { instance = it }
        }
    }
}

/**
 * Receives the clear alarm of [AndroidSecretClipboard]. Not exported, only the app's own alarm can trigger it.
 */
class ClipboardClearReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        AndroidSecretClipboard.get(context).onTimer()
    }
}
