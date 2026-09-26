package at.yawk.password.app

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PlainTooltip
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TooltipAnchorPosition
import androidx.compose.material3.TooltipBox
import androidx.compose.material3.TooltipDefaults
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.rememberTooltipState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
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
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import at.yawk.password.model.PasswordEntry
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private const val STATUS_TIMEOUT_MS = 5000L
private const val PAGE_SIZE = 10

private val OfflineBannerColor = Color(0xFFF67400)

/**
 * The unlocked database: toolbar, offline banner, search and entry list on the left, the selected entry (or the
 * editor) on the right, and a status bar. Keyboard shortcuts follow the old Qt GUI.
 *
 * With [touchInput] (Android), a compact single-pane layout instead: the list, where tapping an entry copies its
 * password (like the old Android app), and separate pages for an entry and the editor, which the back button closes.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MainScreen(
    state: UiState.Unlocked,
    ui: MainScreenState,
    viewModel: PasswordViewModel,
    clipboard: SecretClipboard,
    hooks: WindowHooks,
    touchInput: Boolean = false,
) {
    val scope = rememberCoroutineScope()
    val focusManager = LocalFocusManager.current
    val searchFocus = remember { FocusRequester() }
    val listFocus = remember { FocusRequester() }
    val nameFocus = remember { FocusRequester() }
    val listState = rememberLazyListState()

    // Event handlers read the latest state through this instead of values captured at the last composition, which
    // may be outdated when several events arrive before the next recomposition.
    val latest by rememberUpdatedState(state)
    fun entries() = latest.entries
    fun currentNow() = ui.current(entries())
    fun idleNow() = !latest.busy && !ui.editing

    // not remembered: PasswordEntry has value equality, so a cache keyed on the entry list could keep returning the
    // objects of an older, equal list, which the store no longer accepts
    val visible = ui.visible(state.entries)
    val current = ui.current(state.entries)
    val busy = state.busy
    val editing = ui.editing
    val idle = !busy && !editing

    // ---- actions ----

    // The list only takes the focus in the desktop layout; the compact layout doesn't always show it.
    fun focusList() {
        if (!touchInput) listFocus.requestFocus()
    }

    fun copy(entry: PasswordEntry?, full: Boolean) {
        if (entry == null || ui.editing) return
        viewModel.showStatus(copyEntry(clipboard, entry, full))
    }

    fun focusSearch() {
        ui.query = ui.query.copy(selection = TextRange(0, ui.query.text.length))
        searchFocus.requestFocus()
    }

    fun newEntry() {
        if (!idleNow()) return
        ui.startEditing(null)
    }

    fun editEntry() {
        if (!idleNow()) return
        ui.startEditing(currentNow() ?: return)
    }

    fun withOfflineConfirmation(action: () -> Unit) {
        if (latest.fromLocalStorage && !latest.offlineSaveConfirmed) {
            ui.dialog = MainDialog.ConfirmOfflineSave {
                viewModel.confirmOfflineSave()
                action()
            }
        } else {
            action()
        }
    }

    fun save() {
        if (!ui.editing || latest.busy) return
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
                focusList()
            }
        }
    }

    fun cancelEditing() {
        if (!ui.editing || latest.busy) return
        val cancel: () -> Unit = {
            ui.stopEditing()
            focusList()
        }
        if (ui.isModified) ui.dialog = MainDialog.ConfirmDiscard(cancel) else cancel()
    }

    fun deleteEntry() {
        val entry = currentNow() ?: return
        if (!idleNow()) return
        ui.dialog = MainDialog.ConfirmDelete(entry)
    }

    fun doDelete(entry: PasswordEntry) {
        withOfflineConfirmation {
            val before = entries()
            scope.launch {
                if (viewModel.delete(entry).await()) {
                    // keep the selection at the same row
                    val after = (viewModel.state.value as? UiState.Unlocked)?.entries ?: return@launch
                    ui.selectAfterDelete(before, after, entry)
                    // back to the list instead of showing the next entry
                    if (ui.detailOpen) ui.closeDetail()
                }
            }
        }
    }

    fun reload() {
        if (!idleNow()) return
        val previousName = currentNow()?.name
        scope.launch {
            if (viewModel.reload().await()) {
                val reloaded = (viewModel.state.value as? UiState.Unlocked)?.entries ?: return@launch
                ui.reselectByName(reloaded, previousName)
            }
        }
    }

    fun lock() {
        if (!idleNow()) return
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

    // a phone would show the soft keyboard right away, covering half of the list
    if (!touchInput) {
        LaunchedEffect(Unit) { searchFocus.requestFocus() }
    }

    // keep the current entry in view (in the compact layout, the selection only changes by tapping a visible row)
    val currentIndex = visible.indexOfFirst { it === current }
    LaunchedEffect(currentIndex) {
        if (currentIndex >= 0 && !touchInput) {
            val info = listState.layoutInfo.visibleItemsInfo
            if (info.none { it.index == currentIndex && it.offset >= 0 } || info.lastOrNull()?.index == currentIndex) {
                listState.scrollToItem(currentIndex)
            }
        }
    }

    // window-wide shortcuts, as in the Qt GUI
    val shortcuts: (KeyEvent) -> Boolean = shortcuts@{ event ->
        if (event.type != KeyEventType.KeyDown || ui.dialog != null || latest.error != null) {
            return@shortcuts false
        }
        val ctrl = event.isCtrlPressed
        val shift = event.isShiftPressed
        when {
            ctrl && !shift && event.key == Key.N -> newEntry().let { true }
            (ctrl && !shift && event.key == Key.E) || event.key == Key.F2 -> editEntry().let { true }
            ctrl && shift && event.key == Key.C && !ui.editing -> copy(currentNow(), full = true).let { true }
            ctrl && !shift && event.key == Key.R && !ui.editing -> { ui.revealed = !ui.revealed; true }
            event.key == Key.F5 -> reload().let { true }
            ctrl && !shift && event.key == Key.S && ui.editing -> save().let { true }
            !ctrl && event.key == Key.Escape && ui.editing -> cancelEditing().let { true }
            ctrl && !shift && event.key == Key.F && !ui.editing -> focusSearch().let { true }
            ctrl && !shift && event.key == Key.L -> lock().let { true }
            else -> false
        }
    }
    SideEffect { hooks.keyHandler = shortcuts }

    // ---- layout ----

    // back closes the editor (asking about unsaved changes), then the entry page, then clears the search. Dialogs
    // handle back themselves.
    // handle back while saving as well, so it doesn't leave the app halfway (the save goes on anyway)
    PlatformBackHandler(enabled = editing || busy || ui.detailOpen || ui.query.text.isNotEmpty()) {
        when {
            latest.busy -> viewModel.showStatus("Please wait until saving has finished")
            ui.editing -> cancelEditing()
            ui.detailOpen -> ui.closeDetail()
            else -> ui.query = TextFieldValue("")
        }
    }

    if (touchInput) {
        val detail = ui.detail(state.entries)
        // Not while editing or busy: a save or reload replaces the entry objects, and the new selection is only set
        // once that has finished.
        if (ui.detailOpen && detail == null && !editing && !busy) {
            SideEffect { ui.reopenOrCloseDetail(state.entries) }
        }
        Column(Modifier.fillMaxSize()) {
            when {
                editing -> {
                    CompactBar(
                        title = if (ui.editTarget == null) "New entry" else "Edit entry",
                        onBack = ::cancelEditing,
                        backEnabled = !busy,
                    ) {
                        Button(onClick = ::save, enabled = !busy) { Text("Save") }
                    }
                    HorizontalDivider()
                    CompactEditor(ui, busy, nameFocus, Modifier.weight(1f))
                }
                detail != null -> {
                    CompactBar(title = detail.name.orEmpty(), onBack = { ui.closeDetail() })
                    HorizontalDivider()
                    CompactDetail(
                        entry = detail,
                        idle = idle,
                        revealed = ui.revealed,
                        onCopy = { copy(detail, full = it) },
                        onReveal = { ui.revealed = !ui.revealed },
                        onEdit = ::editEntry,
                        onDelete = ::deleteEntry,
                        modifier = Modifier.weight(1f),
                    )
                }
                else -> {
                    Row(
                        Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Passwords", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                        TextButton(onClick = ::newEntry, enabled = idle) { Text("New") }
                        TextButton(onClick = ::reload, enabled = idle) { Text("Reload") }
                        TextButton(onClick = ::lock, enabled = idle) { Text("Lock") }
                    }
                    HorizontalDivider()
                    if (state.fromLocalStorage) {
                        OfflineBanner()
                    }
                    SearchField(
                        value = ui.query,
                        onValueChange = { ui.query = it },
                        enabled = idle,
                        touchInput = true,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)
                            .focusRequester(searchFocus),
                    )
                    CompactEntryList(
                        entries = visible,
                        enabled = idle,
                        listState = listState,
                        onCopy = {
                            ui.select(it)
                            copy(it, full = false)
                        },
                        onOpen = { ui.openDetail(it) },
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                }
            }
            HorizontalDivider()
            StatusBar(state.status, busy, visible.size, state.entries.size)
        }
    } else {
        Column(Modifier.fillMaxSize()) {
            Toolbar(
                idle = idle,
                editing = editing,
                hasSelection = current != null,
                revealed = ui.revealed,
                onNew = ::newEntry,
                onEdit = ::editEntry,
                onDelete = ::deleteEntry,
                onCopy = { copy(currentNow(), full = false) },
                onCopyAll = { copy(currentNow(), full = true) },
                onReveal = { ui.revealed = !ui.revealed },
                onReload = ::reload,
                onLock = ::lock,
                clearAfterSeconds = clipboard.clearAfterSeconds,
            )
            HorizontalDivider()
            if (state.fromLocalStorage) {
                OfflineBanner()
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
                                Key.DirectionUp -> ui.moveSelection(entries(), -1).let { true }
                                Key.DirectionDown -> ui.moveSelection(entries(), 1).let { true }
                                Key.PageUp -> ui.moveSelection(entries(), -PAGE_SIZE).let { true }
                                Key.PageDown -> ui.moveSelection(entries(), PAGE_SIZE).let { true }
                                Key.Enter, Key.NumPadEnter -> copy(currentNow(), full = false).let { true }
                                Key.Escape -> if (ui.query.text.isNotEmpty()) {
                                    ui.query = TextFieldValue("")
                                    true
                                } else {
                                    false
                                }
                                // don't claim Ctrl+C without a selection, copy the selected password instead
                                Key.C -> if (event.isCtrlPressed && !event.isShiftPressed && ui.query.selection.collapsed) {
                                    copy(currentNow(), full = false)
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
                            ui.select(it)
                            listFocus.requestFocus()
                        },
                        onActivate = {
                            ui.select(it)
                            copy(it, full = false)
                        },
                        onCopy = { copy(it, full = false) },
                        modifier = Modifier.weight(1f).fillMaxWidth().focusRequester(listFocus).onKeyEvent { event ->
                            listKey(event, ui, entries(), { copy(currentNow(), it) }, ::deleteEntry, searchFocus)
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
            if (ui.editing) nameFocus.requestFocus() else focusList()
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
    entries: List<PasswordEntry>,
    copy: (Boolean) -> Unit,
    delete: () -> Unit,
    searchFocus: FocusRequester,
): Boolean {
    // the list is inert while an entry is edited
    if (event.type != KeyEventType.KeyDown || ui.editing) return false
    val visible = ui.visible(entries)
    val commandModifier = event.isCtrlPressed || event.isAltPressed || event.isMetaPressed
    return when {
        event.key == Key.DirectionUp -> ui.moveSelection(entries, -1).let { true }
        event.key == Key.DirectionDown -> ui.moveSelection(entries, 1).let { true }
        event.key == Key.PageUp -> ui.moveSelection(entries, -PAGE_SIZE).let { true }
        event.key == Key.PageDown -> ui.moveSelection(entries, PAGE_SIZE).let { true }
        event.key == Key.MoveHome -> ui.moveSelection(entries, -visible.size).let { true }
        event.key == Key.MoveEnd -> ui.moveSelection(entries, visible.size).let { true }
        event.key == Key.Enter || event.key == Key.NumPadEnter -> copy(false).let { true }
        event.key == Key.Delete && !commandModifier -> delete().let { true }
        event.key == Key.C && event.isCtrlPressed && !event.isShiftPressed -> copy(false).let { true }
        // typing in the list starts a search
        !commandModifier && isPrintable(event.utf16CodePoint) && ui.typeToSearch(event.utf16CodePoint) -> {
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
    touchInput: Boolean = false,
) {
    val keyboard = LocalSoftwareKeyboardController.current
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        placeholder = { Text(if (touchInput) "Search" else "Search (Ctrl+F)") },
        singleLine = true,
        enabled = enabled,
        trailingIcon = if (value.text.isNotEmpty() && enabled) {
            { TextButton(onClick = { onValueChange(TextFieldValue("")) }) { Text("✕") } }
        } else {
            null
        },
        // the soft keyboard's search button just hides the keyboard, the list filters while typing
        keyboardOptions = if (touchInput) {
            KeyboardOptions(autoCorrectEnabled = false, imeAction = ImeAction.Search)
        } else {
            KeyboardOptions.Default
        },
        keyboardActions = if (touchInput) KeyboardActions(onSearch = { keyboard?.hide() }) else KeyboardActions.Default,
        modifier = modifier,
    )
}

/**
 * Title bar of a page of the compact layout, with a back button.
 */
@Composable
private fun CompactBar(
    title: String,
    onBack: () -> Unit,
    backEnabled: Boolean = true,
    actions: @Composable () -> Unit = {},
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TextButton(onClick = onBack, enabled = backEnabled) { Text("‹ Back") }
        Text(
            title,
            style = MaterialTheme.typography.titleLarge,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f).padding(horizontal = 8.dp),
        )
        actions()
        Spacer(Modifier.width(8.dp))
    }
}

@Composable
private fun OfflineBanner() {
    Text(
        "Offline: showing the local copy, which may be outdated. Saving will overwrite the server copy.",
        color = Color.Black,
        modifier = Modifier.fillMaxWidth().background(OfflineBannerColor).padding(8.dp),
    )
}

/**
 * The entry list of the compact layout: tapping a row copies the password, long-pressing it or its › button opens the
 * entry's page.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun CompactEntryList(
    entries: List<PasswordEntry>,
    enabled: Boolean,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onCopy: (PasswordEntry) -> Unit,
    onOpen: (PasswordEntry) -> Unit,
    modifier: Modifier,
) {
    val colors = MaterialTheme.colorScheme
    Column(modifier) {
        Text(
            if (entries.isEmpty()) "No entries" else "Tap to copy the password, long-press for details",
            style = MaterialTheme.typography.bodySmall,
            color = colors.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )
        LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
            items(entries) { entry ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 56.dp)
                        .combinedClickable(
                            enabled = enabled,
                            onClick = { onCopy(entry) },
                            onLongClick = { onOpen(entry) },
                            onLongClickLabel = "Show details",
                        )
                        .padding(start = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        entry.name.orEmpty(),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        onClick = { onOpen(entry) },
                        enabled = enabled,
                        modifier = Modifier.sizeIn(minWidth = 56.dp, minHeight = 56.dp)
                            .semantics { contentDescription = "Details of ${entry.name}" },
                    ) {
                        Text("›", style = MaterialTheme.typography.titleLarge)
                    }
                }
                HorizontalDivider(color = colors.outlineVariant)
            }
        }
    }
}

/**
 * Page of one entry in the compact layout.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CompactDetail(
    entry: PasswordEntry,
    idle: Boolean,
    revealed: Boolean,
    onCopy: (full: Boolean) -> Unit,
    onReveal: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier,
) {
    Column(
        modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Button(onClick = { onCopy(false) }) { Text("Copy password") }
            OutlinedButton(onClick = { onCopy(true) }) { Text("Copy all") }
            if (revealed) {
                FilledTonalButton(onClick = onReveal) { Text("Hide") }
            } else {
                OutlinedButton(onClick = onReveal) { Text("Reveal") }
            }
            OutlinedButton(onClick = onEdit, enabled = idle) { Text("Edit") }
            OutlinedButton(onClick = onDelete, enabled = idle) { Text("Delete") }
        }
        Text(
            if (revealed) entry.value.orEmpty() else maskedValue(entry.value),
            style = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
        )
    }
}

/**
 * The editor page of the compact layout. Saving and cancelling are in its title bar, so they stay reachable while the
 * soft keyboard is open.
 */
@Composable
private fun CompactEditor(ui: MainScreenState, busy: Boolean, nameFocus: FocusRequester, modifier: Modifier) {
    Column(
        modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = ui.draftName,
            onValueChange = { ui.draftName = it },
            label = { Text("Name") },
            singleLine = true,
            enabled = !busy,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            modifier = Modifier.fillMaxWidth().focusRequester(nameFocus),
        )
        OutlinedTextField(
            value = ui.draftValue,
            onValueChange = { ui.draftValue = it },
            label = { Text("Value") },
            placeholder = { Text("First line: password\nFurther lines: username, notes, …") },
            textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
            enabled = !busy,
            minLines = 6,
            // A normal (multi-line) keyboard: the password type makes some keyboards drop the newline key. Compose
            // has no way to set IME_FLAG_NO_PERSONALIZED_LEARNING, so without suggestions is the best we can do.
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedButton(
            onClick = { ui.draftValue = withGeneratedPassword(ui.draftValue) },
            enabled = !busy,
        ) { Text("Generate password") }
    }
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
    onCopy: (PasswordEntry) -> Unit,
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
                        TextButton(onClick = { onCopy(entry) }, enabled = enabled) { Text("Copy") }
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
