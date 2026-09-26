package at.yawk.password.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AndroidSecretClipboardTest {
    private class FakeClipboard : AndroidSecretClipboard.ClipboardAccess {
        var text: String? = null
        var sensitive = false
        /** Whether the app has the focus; Android only lets the focused app read the clipboard */
        var readable = true
        var failWrites = false

        override fun setSensitive(text: String) {
            if (failWrites) throw SecurityException("denied")
            this.text = text
            sensitive = true
        }

        override fun readText() = if (readable) text else null

        override fun clear() {
            text = null
            sensitive = false
        }
    }

    /** Like the alarm: one pending schedule at most, a new one replaces it */
    private inner class FakeScheduler : AndroidSecretClipboard.Scheduler {
        var pending: Long? = null

        override fun schedule(delayMillis: Long): () -> Unit {
            pending = delayMillis
            return { pending = null }
        }

        fun runAll() {
            if (pending != null) {
                pending = null
                secretClipboard.onTimer()
            }
        }
    }

    private val clipboard = FakeClipboard()
    private val scheduler = FakeScheduler()
    private val secretClipboard = AndroidSecretClipboard(clipboard, scheduler)

    @Test
    fun copiesAsSensitiveAndClearsAfterTimeout() {
        assertTrue(secretClipboard.copySecret("secret"))
        assertEquals("secret", clipboard.text)
        assertTrue(clipboard.sensitive)
        assertEquals(30_000L, scheduler.pending)
        scheduler.runAll()
        assertNull(clipboard.text)
    }

    @Test
    fun keepsOtherContentsWhileReadable() {
        secretClipboard.copySecret("secret")
        clipboard.text = "something else"
        scheduler.runAll()
        assertEquals("something else", clipboard.text)
    }

    @Test
    fun clearsWhenNotReadable() {
        secretClipboard.copySecret("secret")
        // in the background, the clipboard can't be checked
        clipboard.readable = false
        scheduler.runAll()
        assertNull(clipboard.text)
    }

    @Test
    fun newCopyRestartsTimer() {
        secretClipboard.copySecret("a")
        secretClipboard.copySecret("b")
        assertEquals(30_000L, scheduler.pending)
        scheduler.runAll()
        assertNull(clipboard.text)
    }

    @Test
    fun clearIfOursCancelsTimer() {
        secretClipboard.copySecret("secret")
        secretClipboard.clearIfOurs()
        assertNull(clipboard.text)
        assertNull(scheduler.pending)
        // nothing of ours left: later contents stay
        clipboard.text = "other"
        clipboard.readable = false
        secretClipboard.clearIfOurs()
        assertEquals("other", clipboard.text)
    }

    @Test
    fun failedCopy() {
        clipboard.failWrites = true
        assertFalse(secretClipboard.copySecret("secret"))
        assertNull(scheduler.pending)
    }

    @Test
    fun timerAfterProcessRestart() {
        // a new process gets the alarm of the old one: clear what can't be checked, keep what can
        val restarted = AndroidSecretClipboard(clipboard, scheduler)
        clipboard.text = "secret"
        clipboard.readable = true
        restarted.onTimer()
        assertEquals("secret", clipboard.text)
        clipboard.readable = false
        restarted.onTimer()
        assertNull(clipboard.text)
    }
}
