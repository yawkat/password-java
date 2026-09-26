package at.yawk.password.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.referentialEqualityPolicy
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import at.yawk.password.client.PasswordStore
import at.yawk.password.model.PasswordEntry

/**
 * UI-only state of the unlocked screen: search, selection and the entry being edited.
 *
 * Entries are always matched by identity, like `PasswordStore` does: `PasswordEntry` has value equality, but only the
 * exact objects of the current store can be updated or deleted. Methods take the current entry list as a parameter
 * instead of caching anything derived from it, so they never work on a stale list.
 */
class MainScreenState {
    var query by mutableStateOf(TextFieldValue(""))

    /** Selected entry, by identity. May be filtered out by [query]; see [current]. */
    // referential equality: an equal entry from another list is a different entry for the store
    var selected by mutableStateOf<PasswordEntry?>(null, referentialEqualityPolicy())
    var revealed by mutableStateOf(false)

    var editing by mutableStateOf(false)
        private set

    /** Entry being edited, `null` when creating a new one */
    var editTarget by mutableStateOf<PasswordEntry?>(null, referentialEqualityPolicy())
        private set
    var draftName by mutableStateOf(TextFieldValue(""))
    var draftValue by mutableStateOf("")

    var dialog by mutableStateOf<MainDialog?>(null)

    val isModified: Boolean
        get() {
            if (!editing) {
                return false
            }
            val target = editTarget ?: return draftName.text.isNotBlank() || draftValue.isNotEmpty()
            return draftName.text.trim() != target.name || draftValue != target.value.orEmpty()
        }

    /**
     * The entries matching [query], sorted by name.
     */
    fun visible(entries: List<PasswordEntry>): List<PasswordEntry> = filterEntries(entries, query.text)

    /**
     * The selected entry if it is visible, otherwise the first visible one.
     */
    fun current(entries: List<PasswordEntry>): PasswordEntry? {
        val visible = visible(entries)
        return visible.firstOrNull { it === selected } ?: visible.firstOrNull()
    }

    /**
     * Move the selection by [delta] rows. Ignored while editing, like the disabled list of the Qt GUI.
     */
    fun moveSelection(entries: List<PasswordEntry>, delta: Int) {
        if (editing) {
            return
        }
        val visible = visible(entries)
        if (visible.isEmpty()) {
            return
        }
        val index = visible.indexOfFirst { it === current(entries) }
        selected = visible[(index + delta).coerceIn(0, visible.size - 1)]
    }

    /**
     * Select [entry], e.g. on click.
     */
    fun select(entry: PasswordEntry) {
        if (!editing) {
            selected = entry
        }
    }

    /**
     * Typing while the list has the focus appends to the search.
     *
     * @return Whether the character was taken (not while editing)
     */
    fun typeToSearch(codePoint: Int): Boolean {
        if (editing) {
            return false
        }
        val text = query.text + String(Character.toChars(codePoint))
        query = TextFieldValue(text, TextRange(text.length))
        return true
    }

    /**
     * After [deleted] was removed, select the entry that took its row in the list. [before] is the entry list from
     * before the deletion, [after] the one after it.
     */
    fun selectAfterDelete(before: List<PasswordEntry>, after: List<PasswordEntry>, deleted: PasswordEntry) {
        val row = visible(before).indexOfFirst { it === deleted }
        val remaining = visible(after)
        selected = remaining.getOrNull(minOf(row, remaining.size - 1))
    }

    /**
     * After a reload all entries are new objects; select the one with the previous name.
     */
    fun reselectByName(entries: List<PasswordEntry>, name: String?) {
        selected = entries.firstOrNull { it.name == name }
    }

    fun startEditing(entry: PasswordEntry?) {
        editTarget = entry
        draftName = TextFieldValue(entry?.name.orEmpty(), TextRange(0, entry?.name.orEmpty().length))
        draftValue = entry?.value.orEmpty()
        editing = true
    }

    fun stopEditing() {
        editing = false
        editTarget = null
        draftName = TextFieldValue("")
        draftValue = ""
    }
}

/**
 * Copy the password (first line) or the full value of [entry], which the caller passes explicitly rather than reading
 * a selection that may not have been recomposed yet.
 *
 * @return The status message to show
 */
fun copyEntry(clipboard: SecretClipboard, entry: PasswordEntry, full: Boolean): String {
    val text = if (full) entry.value.orEmpty() else PasswordStore.firstLine(entry.value)
    if (!clipboard.copySecret(text)) {
        return "Could not copy to the clipboard, try again"
    }
    val what = if (full) "full entry" else "password of"
    return "Copied $what “${entry.name}” (cleared in ${clipboard.clearAfterSeconds}s)"
}

sealed interface MainDialog {
    class ConfirmDelete(val entry: PasswordEntry) : MainDialog {
        // never print the entry (Lombok's toString includes the value)
        override fun toString() = "ConfirmDelete"
    }

    class ConfirmDiscard(val onDiscard: () -> Unit) : MainDialog
    class ConfirmOfflineSave(val onConfirm: () -> Unit) : MainDialog
    data object MissingName : MainDialog
}
