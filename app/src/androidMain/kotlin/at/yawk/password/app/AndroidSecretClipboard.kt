package at.yawk.password.app

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipDescription
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
 * Our copies are recognized by their [ClipDescription] (label and sensitive flag), which can be read without reading
 * the clip itself: reading another app's clip would be none of our business, and Android 12+ shows a "pasted from
 * your clipboard" notice for it. Android only lets the focused app read even the description. Usually the app is in
 * the background when the timer runs out (the user switched away to paste), so the clipboard can't be checked then and
 * is cleared regardless of what it holds. While the app can read it, it is only cleared if it holds one of our copies.
 *
 * The timer is an alarm ([ClipboardClearReceiver]) rather than a handler of the app's own thread, which would not run
 * while Android has frozen the (cached) process or the device sleeps, and not at all once the process is gone.
 */
class AndroidSecretClipboard internal constructor(
    private val clipboard: ClipboardAccess,
    private val scheduler: Scheduler,
    override val clearAfterSeconds: Int = CLEAR_AFTER_SECONDS,
) : SecretClipboard {
    /** Whether we copied something that may still be on the clipboard */
    private var copied = false
    private var cancelClear: (() -> Unit)? = null

    @Synchronized
    override fun copySecret(text: String): Boolean {
        try {
            clipboard.setSensitive(text)
        } catch (e: RuntimeException) {
            Log.w(TAG, "Could not copy to the clipboard", e)
            return false
        }
        copied = true
        cancelClear?.invoke()
        cancelClear = scheduler.schedule(clearAfterSeconds * 1000L)
        return true
    }

    @Synchronized
    override fun clearIfOurs() {
        if (!copied) {
            return
        }
        cancelClear?.invoke()
        clear()
    }

    /**
     * The clear timer ran out. This may be in a new process, which doesn't know about the copy, but the timer only
     * runs after one.
     */
    @Synchronized
    internal fun onTimer() {
        clear()
    }

    /**
     * Clear the clipboard unless it visibly holds something that isn't ours.
     */
    private fun clear() {
        copied = false
        cancelClear = null
        try {
            if (clipboard.holdsOurClip() != false) {
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
         * @return Whether the clipboard holds one of our copies, or `null` if it is empty or can't be read right now.
         */
        fun holdsOurClip(): Boolean?

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
            val clip = ClipData.newPlainText(CLIP_LABEL, text)
            clip.description.extras = PersistableBundle().apply {
                putBoolean(EXTRA_IS_SENSITIVE, true)
            }
            manager.setPrimaryClip(clip)
        }

        override fun holdsOurClip(): Boolean? {
            // the description only, see the class documentation
            val description = manager.primaryClipDescription ?: return null
            return description.label == CLIP_LABEL && description.extras?.getBoolean(EXTRA_IS_SENSITIVE) == true
        }

        override fun clear() = manager.clearPrimaryClip()
    }

    /**
     * An inexact alarm that wakes the device, also in Doze: exact alarms need an extra permission, and a few seconds
     * later don't matter. (setWindow is stretched to a 10 minute window since Android 12, and deferred in Doze.) The
     * alarm survives the process, see [onTimer].
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
            alarms.setAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + delayMillis,
                intent,
            )
            return { alarms.cancel(intent) }
        }
    }

    companion object {
        const val CLEAR_AFTER_SECONDS = 30
        /** Identifies our copies; not shown to the user */
        private const val CLIP_LABEL = "at.yawk.password secret"

        /**
         * ClipDescription.EXTRA_IS_SENSITIVE, which Android 13 made public; keyboards and clipboard managers
         * understood the key before that already.
         */
        private const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"
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
