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

    private class FakeScheduler : AndroidSecretClipboard.Scheduler {
        val pending = mutableListOf<Pair<Long, () -> Unit>>()

        override fun schedule(delayMillis: Long, task: () -> Unit): () -> Unit {
            val entry = delayMillis to task
            pending += entry
            return { pending.remove(entry) }
        }

        fun runAll() {
            val tasks = pending.toList()
            pending.clear()
            tasks.forEach { it.second() }
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
        assertEquals(listOf(30_000L), scheduler.pending.map { it.first })
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
        assertEquals(1, scheduler.pending.size)
        scheduler.runAll()
        assertNull(clipboard.text)
    }

    @Test
    fun clearIfOursCancelsTimer() {
        secretClipboard.copySecret("secret")
        secretClipboard.clearIfOurs()
        assertNull(clipboard.text)
        assertTrue(scheduler.pending.isEmpty())
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
        assertTrue(scheduler.pending.isEmpty())
    }
}
