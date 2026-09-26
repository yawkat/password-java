package at.yawk.password.app

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.PlainTooltip
import androidx.compose.material3.TooltipAnchorPosition
import androidx.compose.material3.TooltipBox
import androidx.compose.material3.TooltipDefaults
import androidx.compose.material3.rememberTooltipState
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isAltPressed
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onKeyEvent
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.input.key.utf16CodePoint
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import at.yawk.password.client.PasswordStore
import at.yawk.password.model.PasswordEntry
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private const val STATUS_TIMEOUT_MS = 5000L
private const val PAGE_SIZE = 10

private val OfflineBannerColor = Color(0xFFF67400)

/**
 * The unlocked database: toolbar, offline banner, search and entry list on the left, the selected entry (or the
 * editor) on the right, and a status bar. Keyboard shortcuts follow the old Qt GUI.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MainScreen(
    state: UiState.Unlocked,
    ui: MainScreenState,
    viewModel: PasswordViewModel,
    clipboard: SecretClipboard,
    hooks: WindowHooks,
) {
    val scope = rememberCoroutineScope()
    val focusManager = LocalFocusManager.current
    val searchFocus = remember { FocusRequester() }
    val listFocus = remember { FocusRequester() }
    val nameFocus = remember { FocusRequester() }
    val listState = rememberLazyListState()

    val visible = remember(state.entries, ui.query.text) { filterEntries(state.entries, ui.query.text) }
    val current = ui.current(visible)
    val busy = state.busy
    val editing = ui.editing
    val idle = !busy && !editing

    // ---- actions ----

    fun copy(full: Boolean) {
        val entry = current ?: return
        if (editing) return
        if (full) {
            clipboard.copySecret(entry.value.orEmpty())
            viewModel.showStatus("Copied full entry “${entry.name}” (cleared in ${clipboard.clearAfterSeconds}s)")
        } else {
            clipboard.copySecret(PasswordStore.firstLine(entry.value))
            viewModel.showStatus("Copied password of “${entry.name}” (cleared in ${clipboard.clearAfterSeconds}s)")
        }
    }

    fun focusSearch() {
        ui.query = ui.query.copy(selection = TextRange(0, ui.query.text.length))
        searchFocus.requestFocus()
    }

    fun newEntry() {
        if (!idle) return
        ui.startEditing(null)
    }

    fun editEntry() {
        if (!idle) return
        ui.startEditing(current ?: return)
    }

    fun withOfflineConfirmation(action: () -> Unit) {
        if (state.fromLocalStorage && !state.offlineSaveConfirmed) {
            ui.dialog = MainDialog.ConfirmOfflineSave {
                viewModel.confirmOfflineSave()
                action()
            }
        } else {
            action()
        }
    }

    fun save() {
        if (!editing || busy) return
        val name = ui.draftName.text.trim()
        val value = ui.draftValue
        if (name.isEmpty()) {
            ui.dialog = MainDialog.MissingName
            return
        }
        val old = ui.editTarget
        withOfflineConfirmation {
            scope.launch {
                val saved = viewModel.save(old, name, value).await() ?: return@launch
                // clear the search if it would hide the saved entry
                if (!name.contains(ui.query.text, ignoreCase = true)) {
                    ui.query = TextFieldValue("")
                }
                ui.stopEditing()
                ui.selected = saved
                listFocus.requestFocus()
            }
        }
    }

    fun cancelEditing() {
        if (!editing || busy) return
        val cancel: () -> Unit = {
            ui.stopEditing()
            listFocus.requestFocus()
        }
        if (ui.isModified) ui.dialog = MainDialog.ConfirmDiscard(cancel) else cancel()
    }

    fun deleteEntry() {
        val entry = current ?: return
        if (!idle) return
        ui.dialog = MainDialog.ConfirmDelete(entry)
    }

    fun doDelete(entry: PasswordEntry) {
        withOfflineConfirmation {
            val row = visible.indexOfFirst { it === entry }
            scope.launch {
                if (viewModel.delete(entry).await()) {
                    // keep the selection at the same row
                    val remaining = visible.filter { it !== entry }
                    ui.selected = remaining.getOrNull(minOf(row, remaining.size - 1))
                }
            }
        }
    }

    fun reload() {
        if (!idle) return
        val previousName = current?.name
        scope.launch {
            if (viewModel.reload().await()) {
                ui.selected = viewModel.state.value.let { it as? UiState.Unlocked }
                    ?.entries?.firstOrNull { it.name == previousName }
            }
        }
    }

    fun lock() {
        if (!idle) return
        clipboard.clearIfOurs()
        viewModel.lock()
    }

    // ---- window integration ----

    DisposableEffect(hooks) {
        hooks.closeHandler = { onConfirmed ->
            when {
                viewModel.state.value.let { it is UiState.Unlocked && it.busy } ->
                    viewModel.showStatus("Please wait until saving has finished")
                ui.isModified -> ui.dialog = MainDialog.ConfirmDiscard(onConfirmed)
                else -> onConfirmed()
            }
        }
        onDispose {
            hooks.closeHandler = null
            hooks.keyHandler = null
        }
    }

    LaunchedEffect(Unit) { searchFocus.requestFocus() }

    // keep the current entry in view
    val currentIndex = visible.indexOfFirst { it === current }
    LaunchedEffect(currentIndex) {
        if (currentIndex >= 0) {
            val info = listState.layoutInfo.visibleItemsInfo
            if (info.none { it.index == currentIndex && it.offset >= 0 } || info.lastOrNull()?.index == currentIndex) {
                listState.scrollToItem(currentIndex)
            }
        }
    }

    // window-wide shortcuts, as in the Qt GUI
    val shortcuts: (KeyEvent) -> Boolean = shortcuts@{ event ->
        if (event.type != KeyEventType.KeyDown || ui.dialog != null || state.error != null) {
            return@shortcuts false
        }
        val ctrl = event.isCtrlPressed
        val shift = event.isShiftPressed
        when {
            ctrl && !shift && event.key == Key.N -> newEntry().let { true }
            (ctrl && !shift && event.key == Key.E) || event.key == Key.F2 -> editEntry().let { true }
            ctrl && shift && event.key == Key.C && !editing -> copy(full = true).let { true }
            ctrl && !shift && event.key == Key.R && !editing -> { ui.revealed = !ui.revealed; true }
            event.key == Key.F5 -> reload().let { true }
            ctrl && !shift && event.key == Key.S && editing -> save().let { true }
            !ctrl && event.key == Key.Escape && editing -> cancelEditing().let { true }
            ctrl && !shift && event.key == Key.F && !editing -> focusSearch().let { true }
            ctrl && !shift && event.key == Key.L && idle -> lock().let { true }
            else -> false
        }
    }
    SideEffect { hooks.keyHandler = shortcuts }

    // ---- layout ----

    Column(Modifier.fillMaxSize()) {
        Toolbar(
            idle = idle,
            editing = editing,
            hasSelection = current != null,
            revealed = ui.revealed,
            onNew = ::newEntry,
            onEdit = ::editEntry,
            onDelete = ::deleteEntry,
            onCopy = { copy(full = false) },
            onCopyAll = { copy(full = true) },
            onReveal = { ui.revealed = !ui.revealed },
            onReload = ::reload,
            onLock = ::lock,
            clearAfterSeconds = clipboard.clearAfterSeconds,
        )
        HorizontalDivider()
        if (state.fromLocalStorage) {
            Text(
                "Offline: showing the local copy, which may be outdated. Saving will overwrite the server copy.",
                color = Color.Black,
                modifier = Modifier.fillMaxWidth().background(OfflineBannerColor).padding(8.dp),
            )
        }
        Row(Modifier.weight(1f).fillMaxWidth()) {
            Column(Modifier.weight(1f).fillMaxHeight().padding(8.dp)) {
                SearchField(
                    value = ui.query,
                    onValueChange = { ui.query = it },
                    enabled = idle,
                    modifier = Modifier.fillMaxWidth().focusRequester(searchFocus).onPreviewKeyEvent { event ->
                        if (event.type != KeyEventType.KeyDown) return@onPreviewKeyEvent false
                        when (event.key) {
                            Key.DirectionUp -> ui.moveSelection(visible, -1).let { true }
                            Key.DirectionDown -> ui.moveSelection(visible, 1).let { true }
                            Key.PageUp -> ui.moveSelection(visible, -PAGE_SIZE).let { true }
                            Key.PageDown -> ui.moveSelection(visible, PAGE_SIZE).let { true }
                            Key.Enter, Key.NumPadEnter -> copy(full = false).let { true }
                            Key.Escape -> if (ui.query.text.isNotEmpty()) {
                                ui.query = TextFieldValue("")
                                true
                            } else {
                                false
                            }
                            // don't claim Ctrl+C without a selection, copy the selected password instead
                            Key.C -> if (event.isCtrlPressed && !event.isShiftPressed && ui.query.selection.collapsed) {
                                copy(full = false)
                                true
                            } else {
                                false
                            }
                            else -> false
                        }
                    },
                )
                Spacer(Modifier.height(8.dp))
                EntryList(
                    entries = visible,
                    current = current,
                    enabled = idle,
                    listState = listState,
                    onSelect = {
                        ui.selected = it
                        listFocus.requestFocus()
                    },
                    onActivate = {
                        ui.selected = it
                        copy(full = false)
                    },
                    onCopy = { copy(full = false) },
                    modifier = Modifier.weight(1f).fillMaxWidth().focusRequester(listFocus).onKeyEvent { event ->
                        listKey(event, ui, visible, ::copy, ::deleteEntry, searchFocus)
                    },
                )
            }
            VerticalDivider()
            Box(Modifier.weight(2f).fillMaxHeight().padding(12.dp)) {
                EntryPane(
                    ui = ui,
                    entry = current,
                    busy = busy,
                    nameFocus = nameFocus,
                    onSave = ::save,
                    onCancel = ::cancelEditing,
                    onTab = { forward -> focusManager.moveFocus(if (forward) FocusDirection.Next else FocusDirection.Previous) },
                )
            }
        }
        HorizontalDivider()
        StatusBar(state.status, busy, visible.size, state.entries.size)
    }

    LaunchedEffect(editing) {
        if (editing) nameFocus.requestFocus()
    }

    // ---- dialogs ----

    // give the focus back once a dialog closes
    val dialogOpen = ui.dialog != null || state.error != null
    var hadDialog by remember { mutableStateOf(false) }
    LaunchedEffect(dialogOpen) {
        if (dialogOpen) {
            hadDialog = true
        } else if (hadDialog) {
            hadDialog = false
            if (ui.editing) nameFocus.requestFocus() else listFocus.requestFocus()
        }
    }

    state.error?.let { error ->
        MessageDialog(error.title, error.text, onDismiss = { viewModel.dismissError() })
    }
    when (val dialog = ui.dialog) {
        null -> {}
        is MainDialog.ConfirmDelete -> ConfirmDialog(
            title = "Delete entry",
            text = "Delete “${dialog.entry.name}”?",
            confirm = "Delete",
            onConfirm = { doDelete(dialog.entry) },
            onDismiss = { ui.dialog = null },
        )
        is MainDialog.ConfirmDiscard -> ConfirmDialog(
            title = "Unsaved changes",
            text = "Discard the changes to this entry?",
            confirm = "Discard",
            onConfirm = dialog.onDiscard,
            onDismiss = { ui.dialog = null },
        )
        is MainDialog.ConfirmOfflineSave -> ConfirmDialog(
            title = "Offline copy",
            text = "The database was loaded from the local copy because the server was unreachable. It may be " +
                "older than the copy on the server.\n\nSaving replaces the server copy with this version. Continue?",
            confirm = "Save",
            onConfirm = dialog.onConfirm,
            onDismiss = { ui.dialog = null },
        )
        MainDialog.MissingName ->
            MessageDialog("Missing name", "The entry needs a name.", onDismiss = { ui.dialog = null })
    }
}

private fun listKey(
    event: KeyEvent,
    ui: MainScreenState,
    visible: List<PasswordEntry>,
    copy: (Boolean) -> Unit,
    delete: () -> Unit,
    searchFocus: FocusRequester,
): Boolean {
    if (event.type != KeyEventType.KeyDown) return false
    val commandModifier = event.isCtrlPressed || event.isAltPressed || event.isMetaPressed
    return when {
        event.key == Key.DirectionUp -> ui.moveSelection(visible, -1).let { true }
        event.key == Key.DirectionDown -> ui.moveSelection(visible, 1).let { true }
        event.key == Key.PageUp -> ui.moveSelection(visible, -PAGE_SIZE).let { true }
        event.key == Key.PageDown -> ui.moveSelection(visible, PAGE_SIZE).let { true }
        event.key == Key.MoveHome -> ui.moveSelection(visible, -visible.size).let { true }
        event.key == Key.MoveEnd -> ui.moveSelection(visible, visible.size).let { true }
        event.key == Key.Enter || event.key == Key.NumPadEnter -> copy(false).let { true }
        event.key == Key.Delete && !commandModifier -> delete().let { true }
        event.key == Key.C && event.isCtrlPressed && !event.isShiftPressed -> copy(false).let { true }
        !commandModifier && isPrintable(event.utf16CodePoint) -> {
            // typing in the list starts a search
            val text = ui.query.text + String(Character.toChars(event.utf16CodePoint))
            ui.query = TextFieldValue(text, TextRange(text.length))
            searchFocus.requestFocus()
            true
        }
        else -> false
    }
}

private fun isPrintable(codePoint: Int) =
    codePoint > 0 && codePoint != 0xFFFF && !Character.isISOControl(codePoint) && Character.isDefined(codePoint)

@Composable
private fun Toolbar(
    idle: Boolean,
    editing: Boolean,
    hasSelection: Boolean,
    revealed: Boolean,
    onNew: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onCopy: () -> Unit,
    onCopyAll: () -> Unit,
    onReveal: () -> Unit,
    onReload: () -> Unit,
    onLock: () -> Unit,
    clearAfterSeconds: Int,
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        ToolButton("New entry", "Ctrl+N", idle, onNew)
        ToolButton("Edit", "Ctrl+E, F2", idle && hasSelection, onEdit)
        ToolButton("Delete", "Del", idle && hasSelection, onDelete)
        Spacer(Modifier.width(8.dp))
        ToolButton(
            "Copy password",
            "Ctrl+C, Enter or double-click. Cleared after $clearAfterSeconds seconds and on exit.",
            !editing && hasSelection,
            onCopy,
        )
        ToolButton("Copy all", "Ctrl+Shift+C", !editing && hasSelection, onCopyAll)
        ToolButton(if (revealed) "Hide" else "Reveal", "Ctrl+R", !editing, onReveal, highlighted = revealed)
        Spacer(Modifier.width(8.dp))
        ToolButton("Reload", "F5", idle, onReload)
        Spacer(Modifier.weight(1f))
        ToolButton("Lock", "Ctrl+L", idle, onLock)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ToolButton(
    text: String,
    hint: String,
    enabled: Boolean,
    onClick: () -> Unit,
    highlighted: Boolean = false,
) {
    TooltipBox(
        positionProvider = TooltipDefaults.rememberTooltipPositionProvider(TooltipAnchorPosition.Below),
        tooltip = { PlainTooltip { Text(hint) } },
        state = rememberTooltipState(),
    ) {
        val padding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
        if (highlighted) {
            FilledTonalButton(onClick = onClick, enabled = enabled, contentPadding = padding) {
                Text(text, maxLines = 1)
            }
        } else {
            OutlinedButton(onClick = onClick, enabled = enabled, contentPadding = padding) { Text(text, maxLines = 1) }
        }
    }
}

@Composable
private fun SearchField(
    value: TextFieldValue,
    onValueChange: (TextFieldValue) -> Unit,
    enabled: Boolean,
    modifier: Modifier,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        placeholder = { Text("Search (Ctrl+F)") },
        singleLine = true,
        enabled = enabled,
        trailingIcon = if (value.text.isNotEmpty() && enabled) {
            { TextButton(onClick = { onValueChange(TextFieldValue("")) }) { Text("✕") } }
        } else {
            null
        },
        modifier = modifier,
    )
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun EntryList(
    entries: List<PasswordEntry>,
    current: PasswordEntry?,
    enabled: Boolean,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onSelect: (PasswordEntry) -> Unit,
    onActivate: (PasswordEntry) -> Unit,
    onCopy: () -> Unit,
    modifier: Modifier,
) {
    var focused by remember { mutableStateOf(false) }
    val colors = MaterialTheme.colorScheme
    Box(
        modifier
            .onFocusChanged { focused = it.hasFocus }
            // stays focusable while disabled, so the focus can move here right when an edit ends
            .focusable(),
    ) {
        if (entries.isEmpty()) {
            Text(
                "No entries",
                color = colors.onSurfaceVariant,
                modifier = Modifier.padding(8.dp),
            )
        }
        LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
            itemsIndexed(entries) { _, entry ->
                val isCurrent = entry === current
                val background = when {
                    isCurrent && focused -> colors.primaryContainer
                    isCurrent -> colors.surfaceVariant
                    else -> Color.Transparent
                }
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(background)
                        .combinedClickable(
                            enabled = enabled,
                            onClick = { onSelect(entry) },
                            onDoubleClick = { onActivate(entry) },
                        )
                        .padding(horizontal = 8.dp, vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        entry.name.orEmpty(),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        color = if (isCurrent && focused) colors.onPrimaryContainer else colors.onSurface,
                        modifier = Modifier.weight(1f).padding(vertical = 6.dp),
                    )
                    if (isCurrent) {
                        TextButton(onClick = onCopy, enabled = enabled) { Text("Copy") }
                    }
                }
            }
        }
    }
}

@Composable
private fun EntryPane(
    ui: MainScreenState,
    entry: PasswordEntry?,
    busy: Boolean,
    nameFocus: FocusRequester,
    onSave: () -> Unit,
    onCancel: () -> Unit,
    onTab: (forward: Boolean) -> Unit,
) {
    val mono = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace)
    if (ui.editing) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = ui.draftName,
                onValueChange = { ui.draftName = it },
                label = { Text("Name") },
                singleLine = true,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().focusRequester(nameFocus).onPreviewKeyEvent {
                    if (it.type == KeyEventType.KeyDown && (it.key == Key.Enter || it.key == Key.NumPadEnter)) {
                        onSave()
                        true
                    } else {
                        false
                    }
                },
            )
            OutlinedTextField(
                value = ui.draftValue,
                onValueChange = { ui.draftValue = it },
                label = { Text("Value") },
                placeholder = { Text("First line: password\nFurther lines: username, notes, …") },
                textStyle = mono,
                enabled = !busy,
                minLines = 6,
                modifier = Modifier.fillMaxWidth().weight(1f, fill = false).onPreviewKeyEvent {
                    // Tab moves the focus instead of inserting a tab character
                    if (it.key == Key.Tab && !it.isCtrlPressed) {
                        if (it.type == KeyEventType.KeyDown) onTab(!it.isShiftPressed)
                        true
                    } else {
                        false
                    }
                },
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(
                    onClick = { ui.draftValue = withGeneratedPassword(ui.draftValue) },
                    enabled = !busy,
                ) { Text("Generate password") }
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") }
                Button(onClick = onSave, enabled = !busy) { Text("Save") }
            }
        }
    } else if (entry == null) {
        Text(
            "Select an entry, or press Ctrl+N to create one.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    } else {
        SelectionContainer {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(entry.name.orEmpty(), style = MaterialTheme.typography.titleLarge)
                Text(if (ui.revealed) entry.value.orEmpty() else maskedValue(entry.value), style = mono)
            }
        }
    }
}

@Composable
private fun StatusBar(
    status: StatusMessage?,
    busy: Boolean,
    visibleCount: Int,
    totalCount: Int,
) {
    var shown by remember { mutableStateOf<StatusMessage?>(null) }
    LaunchedEffect(status, busy) {
        shown = status
        if (status != null && !busy) {
            delay(STATUS_TIMEOUT_MS)
            shown = null
        }
    }
    Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp)) {
        Text(
            shown?.text ?: "",
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        Text(
            when {
                visibleCount != totalCount -> "$visibleCount of $totalCount entries"
                totalCount == 1 -> "1 entry"
                else -> "$totalCount entries"
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ConfirmDialog(
    title: String,
    text: String,
    confirm: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    // like the Qt GUI, the safe choice is the default: Enter cancels, Tab then Enter confirms
    val cancelFocus = remember { FocusRequester() }
    LaunchedEffect(Unit) { cancelFocus.requestFocus() }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = {
            Button(onClick = {
                onDismiss()
                onConfirm()
            }) { Text(confirm) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, modifier = Modifier.focusRequester(cancelFocus)) { Text("Cancel") }
        },
    )
}

@Composable
private fun MessageDialog(title: String, text: String, onDismiss: () -> Unit) {
    val okFocus = remember { FocusRequester() }
    LaunchedEffect(Unit) { okFocus.requestFocus() }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = {
            Button(onClick = onDismiss, modifier = Modifier.focusRequester(okFocus)) { Text("OK") }
        },
    )
}
