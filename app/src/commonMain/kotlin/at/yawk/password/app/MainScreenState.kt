package at.yawk.password.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import at.yawk.password.model.PasswordEntry

/**
 * UI-only state of the unlocked screen: search, selection and the entry being edited.
 */
class MainScreenState {
    var query by mutableStateOf(TextFieldValue(""))

    /** Selected entry, by identity. May be filtered out by [query]; see [current]. */
    var selected by mutableStateOf<PasswordEntry?>(null)
    var revealed by mutableStateOf(false)

    var editing by mutableStateOf(false)
        private set

    /** Entry being edited, `null` when creating a new one */
    var editTarget by mutableStateOf<PasswordEntry?>(null)
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
     * The selected entry if it is visible, otherwise the first visible one.
     */
    fun current(visible: List<PasswordEntry>): PasswordEntry? =
        visible.firstOrNull { it === selected } ?: visible.firstOrNull()

    fun moveSelection(visible: List<PasswordEntry>, delta: Int) {
        if (visible.isEmpty()) {
            return
        }
        val index = visible.indexOfFirst { it === current(visible) }
        selected = visible[(index + delta).coerceIn(0, visible.size - 1)]
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

sealed interface MainDialog {
    data class ConfirmDelete(val entry: PasswordEntry) : MainDialog
    data class ConfirmDiscard(val onDiscard: () -> Unit) : MainDialog
    data class ConfirmOfflineSave(val onConfirm: () -> Unit) : MainDialog
    data object MissingName : MainDialog
}
