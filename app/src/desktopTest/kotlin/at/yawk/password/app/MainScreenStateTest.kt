package at.yawk.password.app

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.insert
import at.yawk.password.model.PasswordEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

private fun entry(name: String, value: String = "pw-$name\nuser") = PasswordEntry().apply {
    this.name = name
    this.value = value
}

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
class MainScreenStateTest {
    @Test
    fun selectionIsByIdentity() {
        val ui = MainScreenState()
        val old = listOf(entry("a"), entry("b"))
        ui.select(old[1])
        assertSame(old[1], ui.current(old))

        // a reload returns equal but different objects; the store only accepts the new ones
        val reloaded = listOf(entry("a"), entry("b"))
        assertEquals(old, reloaded)
        assertSame(reloaded[0], ui.current(reloaded), "old selection is not part of the new list")
        assertTrue(ui.visible(reloaded).all { v -> reloaded.any { it === v } })

        ui.reselectByName(reloaded, "b")
        assertSame(reloaded[1], ui.current(reloaded))
    }

    @Test
    fun moveSelectionAndSearch() {
        val ui = MainScreenState()
        val entries = listOf(entry("c"), entry("a"), entry("b"))
        assertEquals("a", ui.current(entries)?.name)
        ui.moveSelection(entries, 1)
        assertEquals("b", ui.current(entries)?.name)
        ui.moveSelection(entries, 10)
        assertEquals("c", ui.current(entries)?.name)
        assertTrue(ui.typeToSearch('b'.code))
        assertEquals("b", ui.query.text)
        assertEquals(listOf("b"), ui.visible(entries).map { it.name })
        assertEquals("b", ui.current(entries)?.name)
    }

    @Test
    fun listIsInertWhileEditing() {
        val ui = MainScreenState()
        val entries = listOf(entry("a"), entry("b"))
        ui.select(entries[0])
        ui.startEditing(entries[0])
        ui.moveSelection(entries, 1)
        ui.select(entries[1])
        assertFalse(ui.typeToSearch('x'.code))
        assertEquals("", ui.query.text)
        assertSame(entries[0], ui.current(entries))
        ui.stopEditing()
        ui.moveSelection(entries, 1)
        assertSame(entries[1], ui.current(entries))
    }

    @Test
    fun selectAfterDelete() {
        val ui = MainScreenState()
        val before = listOf(entry("a"), entry("b"), entry("c"))
        ui.selectAfterDelete(before, listOf(before[0], before[2]), before[1])
        assertSame(before[2], ui.selected)
        ui.selectAfterDelete(listOf(before[0], before[2]), listOf(before[0]), before[2])
        assertSame(before[0], ui.selected)
        ui.selectAfterDelete(listOf(before[0]), listOf(), before[0])
        assertNull(ui.selected)
    }

    @Test
    fun copyUsesTheGivenEntry() {
        val clipboard = FakeClipboard()
        val a = entry("a")
        val b = entry("b")
        val ui = MainScreenState()
        ui.select(a)
        // double-clicking b copies b, whatever the (not yet recomposed) selection says
        ui.select(b)
        assertEquals("Copied password of “b” (cleared in 30s)", copyEntry(clipboard, b, full = false))
        assertEquals("pw-b", clipboard.copied)
        copyEntry(clipboard, a, full = true)
        assertEquals("pw-a\nuser", clipboard.copied)

        clipboard.available = false
        assertEquals("Could not copy to the clipboard, try again", copyEntry(clipboard, a, full = false))
    }

    @Test
    fun clearSecretLeavesNoUndo() {
        val field = TextFieldState()
        field.edit { insert(0, "master password") }
        field.clearText()
        assertTrue(field.undoState.canUndo, "plain clearText can be undone")

        val secret = TextFieldState()
        secret.edit { insert(0, "master password") }
        secret.clearSecret()
        assertEquals("", secret.text.toString())
        assertFalse(secret.undoState.canUndo)
        secret.undoState.undo()
        assertEquals("", secret.text.toString())
    }

    @Test
    fun toStringHidesSecrets() {
        val e = entry("name", "secret-value")
        val unlocked = UiState.Unlocked(entries = listOf(e), fromLocalStorage = false)
        assertFalse(unlocked.toString().contains("secret-value"), unlocked.toString())
        assertFalse(MainDialog.ConfirmDelete(e).toString().contains("secret-value"))
    }

    @Test
    fun unlockedComparesEntriesByIdentity() {
        val status = StatusMessage("x")
        val a = UiState.Unlocked(listOf(entry("a")), fromLocalStorage = false, status = status)
        val b = UiState.Unlocked(listOf(entry("a")), fromLocalStorage = false, status = status)
        assertTrue(a != b)
        assertEquals(a, a.copy())
    }

    private class FakeClipboard : SecretClipboard {
        var copied: String? = null
        var available = true
        override val clearAfterSeconds = 30

        override fun copySecret(text: String): Boolean {
            if (available) copied = text
            return available
        }

        override fun clearIfOurs() {
            copied = null
        }
    }
}
