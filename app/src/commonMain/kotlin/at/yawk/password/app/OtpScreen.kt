package at.yawk.password.app

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameMillis
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import at.yawk.password.model.OtpAccount
import at.yawk.password.model.OtpAlgorithm
import at.yawk.password.otp.Totp
import kotlin.math.roundToInt
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * The 2FA vault: its lock screen, or the unlocked accounts.
 */
@Composable
fun OtpApp(
    state: OtpState,
    viewModel: OtpViewModel,
    clipboard: SecretClipboard,
    hooks: WindowHooks,
    touchInput: Boolean,
) {
    // not saveable, like the master password field; replaced for every session
    val password = remember(state is OtpState.Unlocked) { TextFieldState() }
    when (state) {
        OtpState.Closed -> {}
        is OtpState.Locked ->
            OtpUnlockScreen(state.config, state.error, busy = false, state.fingerprint, password, viewModel, hooks)
        is OtpState.Unlocking ->
            OtpUnlockScreen(state.config, null, busy = true, fingerprint = false, password, viewModel, hooks)
        is OtpState.ConfirmCreate -> {
            OtpUnlockScreen(state.config, null, busy = true, fingerprint = false, password, viewModel, hooks)
            OtpCreateDialog(viewModel, hooks)
        }
        is OtpState.Unlocked -> OtpScreen(state, viewModel.screenState, viewModel, clipboard, hooks, touchInput)
    }
}

@Composable
private fun OtpUnlockScreen(
    config: AppConfig,
    error: String?,
    busy: Boolean,
    fingerprint: Boolean,
    password: TextFieldState,
    viewModel: OtpViewModel,
    hooks: WindowHooks,
) {
    val focus = remember { FocusRequester() }
    fun unlock() {
        if (!busy && password.text.isNotEmpty()) {
            viewModel.unlock(password.text)
            password.clearSecret()
        }
    }
    LaunchedEffect(busy) {
        if (!busy) focus.requestFocus()
    }
    DisposableEffect(hooks, password) {
        val handler = { password.clearSecret() }
        hooks.backgroundHandlers += handler
        onDispose { hooks.backgroundHandlers -= handler }
    }
    PlatformBackHandler(enabled = !busy) { viewModel.close() }
    BoxWithConstraints(Modifier.fillMaxSize()) {
        Box(
            Modifier.verticalScroll(rememberScrollState()).heightIn(min = maxHeight).fillMaxWidth().padding(24.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(Modifier.widthIn(max = 480.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Unlock 2FA codes", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "The 2FA codes and backup codes have their own password, the backup password. The master " +
                        "password does not open them.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                SecretInput {
                    OutlinedSecureTextField(
                        state = password,
                        label = { Text("Backup password (18-028)") },
                        enabled = !busy,
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done,
                        ),
                        onKeyboardAction = { unlock() },
                        modifier = Modifier.fillMaxWidth().focusRequester(focus).onPreviewKeyEvent {
                            if (isEnter(it)) {
                                unlock()
                                true
                            } else {
                                false
                            }
                        },
                    )
                }
                Text(
                    "Server: ${config.url}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (error != null) {
                    Text(error, color = MaterialTheme.colorScheme.error)
                }
                if (busy) {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                }
                if (fingerprint) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { viewModel.unlockWithFingerprint() }, enabled = !busy) { Text("Use fingerprint") }
                        TextButton(onClick = { viewModel.forgetFingerprint() }, enabled = !busy) {
                            Text("Forget fingerprint")
                        }
                    }
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End)) {
                    TextButton(onClick = { viewModel.close() }, enabled = !busy) { Text("Back to passwords") }
                    Button(onClick = ::unlock, enabled = !busy) { Text("Unlock") }
                }
            }
        }
    }
}

@Composable
private fun OtpCreateDialog(viewModel: OtpViewModel, hooks: WindowHooks) {
    val repeated = remember { TextFieldState() }
    val focus = remember { FocusRequester() }
    fun create() {
        viewModel.confirmCreate(repeated.text)
        repeated.clearSecret()
    }
    LaunchedEffect(Unit) { focus.requestFocus() }
    DisposableEffect(hooks, repeated) {
        val handler = { repeated.clearSecret() }
        hooks.backgroundHandlers += handler
        onDispose { hooks.backgroundHandlers -= handler }
    }
    AlertDialog(
        onDismissRequest = { viewModel.cancelCreate() },
        title = { Text("No 2FA vault found") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "There is no 2FA vault on the server or in the local copy.\n\n" +
                        "Create a new, empty one with this backup password? Use a strong password that is not the " +
                        "master password, and keep it written down: it is what opens your 2FA codes when your phone " +
                        "is lost.",
                )
                SecretInput {
                    OutlinedSecureTextField(
                        state = repeated,
                        label = { Text("Repeat the backup password (18-028)") },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done,
                        ),
                        onKeyboardAction = { create() },
                        modifier = Modifier.fillMaxWidth().focusRequester(focus).onPreviewKeyEvent {
                            if (isEnter(it)) {
                                create()
                                true
                            } else {
                                false
                            }
                        },
                    )
                }
            }
        },
        confirmButton = { Button(onClick = ::create) { Text("Create") } },
        dismissButton = { TextButton(onClick = { viewModel.cancelCreate() }) { Text("Cancel") } },
    )
}

private fun isEnter(event: KeyEvent) =
    event.type == KeyEventType.KeyDown && (event.key == Key.Enter || event.key == Key.NumPadEnter)

/**
 * The current time, updated every second. Only the composables that show codes read it (through the returned
 * function), so that only they recompose every second, not the whole screen.
 */
@Composable
private fun rememberClock(): () -> Long {
    val now = produceState(System.currentTimeMillis()) {
        while (true) {
            value = System.currentTimeMillis()
            delay(1000 - value % 1000)
        }
    }
    return remember(now) { { now.value } }
}

/**
 * The unlocked 2FA vault: the account list (tapping an account copies its code), and pages for an account with its
 * backup codes, the editor and the import. The same layout serves touch and desktop.
 */
@Composable
private fun OtpScreen(
    state: OtpState.Unlocked,
    ui: OtpScreenState,
    viewModel: OtpViewModel,
    clipboard: SecretClipboard,
    hooks: WindowHooks,
    touchInput: Boolean,
) {
    val scope = rememberCoroutineScope()
    val searchFocus = remember { FocusRequester() }
    val clock = rememberClock()
    val latest by rememberUpdatedState(state)
    val busy = state.busy
    val visible = remember(state.accounts, ui.query.text) { filterAccounts(state.accounts, ui.query.text) }

    // ---- actions ----

    fun copy(account: OtpAccount) {
        if (viewModel.state.value !is OtpState.Unlocked) return
        val copied = codeToCopy(account, System.currentTimeMillis())
        viewModel.showStatus(
            when {
                copied == null -> "“${accountTitle(account)}” has invalid parameters, edit it"
                !clipboard.copySecret(copied.first) -> "Could not copy to the clipboard, try again"
                else -> "Copied the ${if (copied.second) "next " else ""}code of “${accountTitle(account)}” " +
                    "(cleared in ${clipboard.clearAfterSeconds}s)"
            },
        )
    }

    fun withOfflineConfirmation(action: () -> Unit) {
        if (latest.localReason != null && !ui.offlineSaveConfirmed) {
            ui.dialog = OtpDialog.ConfirmOfflineSave {
                ui.offlineSaveConfirmed = true
                action()
            }
        } else {
            action()
        }
    }

    fun back() {
        if (latest.busy) {
            viewModel.showStatus("Please wait until saving has finished")
            return
        }
        when {
            ui.scanning -> ui.scanning = false
            ui.page == OtpPage.List -> ui.query = TextFieldValue("")
            ui.isModified -> ui.dialog = OtpDialog.ConfirmDiscard { ui.backToList() }
            else -> ui.backToList()
        }
    }

    fun save(id: String?) {
        if (latest.busy) return
        val account = ui.draft.toAccount(id).getOrElse { return }
        withOfflineConfirmation {
            scope.launch {
                if (viewModel.save(account).await()) {
                    ui.backToList()
                    ui.openDetail(account)
                }
            }
        }
    }

    fun import(accounts: List<OtpAccount>) {
        if (latest.busy || accounts.isEmpty()) return
        withOfflineConfirmation {
            scope.launch {
                if (viewModel.import(accounts).await()) ui.backToList()
            }
        }
    }

    fun delete(account: OtpAccount) {
        withOfflineConfirmation {
            scope.launch {
                if (viewModel.delete(account).await()) ui.backToList()
            }
        }
    }

    fun reload() {
        if (latest.busy) return
        scope.launch {
            if (viewModel.reload().await()) ui.offlineSaveConfirmed = false
        }
    }

    fun lock() {
        if (latest.busy) return
        val doLock = {
            clipboard.clearIfOurs()
            viewModel.lock()
        }
        // like Back and closing the window: locking drops a draft or a pasted import
        if (ui.isModified) ui.dialog = OtpDialog.ConfirmDiscard(doLock) else doLock()
    }

    // ---- window integration ----

    DisposableEffect(hooks) {
        hooks.closeHandler = { onConfirmed ->
            when {
                viewModel.state.value.let { it is OtpState.Unlocked && it.busy } ->
                    viewModel.showStatus("Please wait until saving has finished")
                ui.isModified -> ui.dialog = OtpDialog.ConfirmDiscard(onConfirmed)
                else -> onConfirmed()
            }
        }
        onDispose {
            hooks.closeHandler = null
            hooks.keyHandler = null
        }
    }
    val shortcuts: (KeyEvent) -> Boolean = shortcuts@{ event ->
        viewModel.onActivity()
        if (event.type != KeyEventType.KeyDown || ui.dialog != null || latest.error != null) {
            return@shortcuts false
        }
        val ctrl = event.isCtrlPressed && !event.isShiftPressed
        when {
            ctrl && event.key == Key.L -> lock().let { true }
            ctrl && event.key == Key.F && ui.page == OtpPage.List -> searchFocus.requestFocus().let { true }
            ctrl && event.key == Key.N && ui.page == OtpPage.List && !latest.busy -> ui.startEditing(null).let { true }
            event.key == Key.F5 && ui.page == OtpPage.List -> reload().let { true }
            event.key == Key.Escape && ui.page != OtpPage.List -> back().let { true }
            else -> false
        }
    }
    SideEffect { hooks.keyHandler = shortcuts }
    PlatformBackHandler(enabled = ui.page != OtpPage.List || ui.query.text.isNotEmpty()) { back() }
    // typing on a soft keyboard sends no key events: count the edits as activity for the idle lock
    LaunchedEffect(ui.query.text, ui.draft, ui.uri, ui.importText) { viewModel.onActivity() }

    if (!touchInput) {
        LaunchedEffect(Unit) { searchFocus.requestFocus() }
    }

    // ---- layout ----

    Column(
        // any input counts as activity for the idle lock
        Modifier.fillMaxSize().pointerInput(viewModel) {
            awaitPointerEventScope {
                while (true) {
                    awaitPointerEvent(PointerEventPass.Initial)
                    viewModel.onActivity()
                }
            }
        },
    ) {
        when (val page = ui.page) {
            OtpPage.List -> {
                Row(
                    Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        "2FA codes",
                        style = MaterialTheme.typography.titleLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(onClick = { ui.startEditing(null) }, enabled = !busy) { Text("Add") }
                    TextButton(onClick = { ui.startImport() }, enabled = !busy) { Text("Import") }
                    TextButton(onClick = ::reload, enabled = !busy) { Text("Reload") }
                    TextButton(onClick = ::lock, enabled = !busy) { Text("Lock") }
                }
                HorizontalDivider()
                if (state.localReason != null) {
                    OfflineBanner()
                }
                if (state.offerFingerprint) {
                    FingerprintOffer(
                        enabled = !busy,
                        onEnable = { viewModel.enableFingerprint() },
                        onDismiss = { viewModel.dismissFingerprintOffer() },
                    )
                }
                SearchField(
                    value = ui.query,
                    onValueChange = { ui.query = it },
                    enabled = true,
                    touchInput = touchInput,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)
                        .focusRequester(searchFocus).onPreviewKeyEvent {
                            // Enter copies the code of the first match
                            if (isEnter(it)) {
                                visible.firstOrNull()?.let(::copy)
                                true
                            } else {
                                false
                            }
                        },
                )
                if (state.accounts.isEmpty()) {
                    Text(
                        "No accounts yet. Add one, or import them, e.g. from Authy (see the README).",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp),
                    )
                }
                LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
                    // ids are unique, see OtpBlob.setAccounts
                    items(visible, key = { it.id }) { account ->
                        AccountRow(account, clock, onCopy = { copy(account) }, onOpen = { ui.openDetail(account) })
                        HorizontalDivider()
                    }
                }
            }
            is OtpPage.Detail -> {
                val account = state.accounts.firstOrNull { it.id == page.id }
                if (account == null) {
                    // deleted or reloaded away
                    SideEffect { ui.backToList() }
                } else {
                    CompactBar(title = accountTitle(account), onBack = ::back) {
                        TextButton(onClick = { ui.startEditing(account) }, enabled = !busy) { Text("Edit") }
                        TextButton(
                            onClick = { ui.dialog = OtpDialog.ConfirmDelete(account) },
                            enabled = !busy,
                        ) { Text("Delete") }
                    }
                    HorizontalDivider()
                    AccountDetail(
                        account,
                        clock,
                        backupCodesShown = ui.backupCodesShown,
                        onToggleBackupCodes = { ui.backupCodesShown = !ui.backupCodesShown },
                        onCopy = { copy(account) },
                        modifier = Modifier.weight(1f),
                    )
                }
            }
            is OtpPage.Edit if ui.scanning -> {
                CompactBar(title = "Scan QR code", onBack = ::back)
                HorizontalDivider()
                QrScanner(
                    onResult = {
                        ui.scanning = false
                        ui.fillInFromUri(it)
                    },
                    onError = {
                        ui.scanning = false
                        ui.uriError = it
                    },
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                )
            }
            is OtpPage.Edit -> {
                CompactBar(
                    title = if (page.id == null) "New account" else "Edit account",
                    onBack = ::back,
                    backEnabled = !busy,
                ) {
                    val valid = remember(ui.draft, page.id) { ui.draft.toAccount(page.id).isSuccess }
                    Button(onClick = { save(page.id) }, enabled = !busy && valid) {
                        Text("Save")
                    }
                }
                HorizontalDivider()
                AccountEditor(ui, page.id, clock, enabled = !busy, modifier = Modifier.weight(1f))
            }
            OtpPage.Import -> {
                val lines = remember(ui.importText, state.accounts) { parseImport(ui.importText, state.accounts) }
                val accounts = lines.filter { it.account != null && it.duplicate == null }.map { it.account!! }
                CompactBar(title = "Import", onBack = ::back, backEnabled = !busy) {
                    Button(onClick = { import(accounts) }, enabled = !busy && accounts.isNotEmpty()) {
                        Text("Import ${accounts.size}")
                    }
                }
                HorizontalDivider()
                ImportPage(
                    ui,
                    lines,
                    clock,
                    enabled = !busy,
                    onPickFile = if (viewModel.canPickTextFile) {
                        { scope.launch { viewModel.pickImportFile()?.let { ui.importText = it } } }
                    } else {
                        null
                    },
                    modifier = Modifier.weight(1f),
                )
            }
        }
        HorizontalDivider()
        StatusBar(state.status, busy, countText(visible.size, state.accounts.size, "account", "accounts"))
    }

    // ---- dialogs ----

    state.error?.let { error ->
        MessageDialog(error.title, error.text, onDismiss = { viewModel.dismissError() })
    }
    when (val dialog = ui.dialog) {
        null -> {}
        is OtpDialog.ConfirmDelete -> ConfirmDialog(
            title = "Delete account",
            text = "Delete “${accountTitle(dialog.account)}” with its backup codes? Without them, you can only log in " +
                "there with another second factor.",
            confirm = "Delete",
            onConfirm = { delete(dialog.account) },
            onDismiss = { ui.dialog = null },
        )
        is OtpDialog.ConfirmDiscard -> ConfirmDialog(
            title = "Unsaved changes",
            text = "Discard the changes?",
            confirm = "Discard",
            onConfirm = dialog.onDiscard,
            onDismiss = { ui.dialog = null },
        )
        is OtpDialog.ConfirmOfflineSave -> ConfirmDialog(
            title = "Local copy",
            text = "The 2FA vault was loaded from the local copy, not from the server: the server was unreachable, " +
                "or its copy could not be used. The two may differ.\n\nSaving replaces the server copy with this " +
                "version. Continue?",
            confirm = "Save",
            onConfirm = dialog.onConfirm,
            onDismiss = { ui.dialog = null },
        )
    }
}

@Composable
private fun FingerprintOffer(enabled: Boolean, onEnable: () -> Unit, onDismiss: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.secondaryContainer)
            .padding(start = 16.dp, end = 8.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            "Open the 2FA codes with your fingerprint next time?",
            color = MaterialTheme.colorScheme.onSecondaryContainer,
            modifier = Modifier.weight(1f),
        )
        TextButton(onClick = onDismiss, enabled = enabled) { Text("Not now") }
        TextButton(onClick = onEnable, enabled = enabled) { Text("Enable") }
    }
}

@Composable
private fun Avatar(account: OtpAccount) {
    val icon = siteIcon(account)
    Box(
        Modifier.size(40.dp).clip(CircleShape)
            .background(icon?.color ?: Color.hsv(avatarHue(account), 0.45f, 0.7f)),
        contentAlignment = Alignment.Center,
    ) {
        if (icon == null) {
            Text(avatarLetter(account), color = Color.White, style = MaterialTheme.typography.titleMedium)
        } else {
            // the title next to the avatar names the service
            Image(icon.vector, contentDescription = null, modifier = Modifier.size(22.dp))
        }
    }
}

/**
 * The time left of the current code, as a ring and in seconds.
 */
@Composable
private fun Countdown(account: OtpAccount, now: Long) {
    if (account.period <= 0) return
    val remaining = Totp.millisUntilNext(account, now)
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        CircularProgressIndicator(
            progress = { remaining.toFloat() / (account.period * 1000L) },
            modifier = Modifier.size(18.dp),
            strokeWidth = 3.dp,
        )
        Text(
            "${(remaining + 999) / 1000}s",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * The codes on a drum that turns continuously: the current code moves up from the bottom row to the top row as it runs
 * out and the next one follows below it, so that the next code can be read before the current one expires (with 10 s codes there is
 * little time to type one). [now] picks the codes; the position follows the frame time, so that only the layout
 * changes on every frame.
 */
@Composable
private fun CodeDrum(account: OtpAccount, now: Long, style: TextStyle) {
    val code = codeOrNull(account, now)
    if (code == null || account.period <= 0) {
        Text(
            code?.let(::formatCode) ?: "invalid",
            style = style,
            fontFamily = FontFamily.Monospace,
            color = if (code == null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
            maxLines = 1,
        )
        return
    }
    val frameTime = produceState(now) {
        while (true) {
            withFrameMillis { }
            value = System.currentTimeMillis()
        }
    }
    val periodMillis = account.period * 1000L
    val step = Math.floorDiv(now, periodMillis)
    val rowHeight = with(LocalDensity.current) { style.lineHeight.toDp() }
    // two rows: the current code starts in the bottom one, below the previous code, and the next one comes into view
    // as it moves up. The code after that only appears once the next one is current.
    Box(Modifier.height(rowHeight * 2).clipToBounds()) {
        // four rows, taller than the window: it clips them
        Column(
            Modifier.wrapContentHeight(Alignment.Top, unbounded = true).offset {
                // relative to [step] rather than wrapped, so that a frame past the change before [now] catches up
                // doesn't jump back
                val progress = (frameTime.value - step * periodMillis).toFloat() / periodMillis
                IntOffset(0, (-progress * rowHeight.toPx()).roundToInt())
            },
        ) {
            val colors = MaterialTheme.colorScheme
            for (s in step - 1..step + 2) {
                Text(
                    codeOrNull(account, s * periodMillis)?.let(::formatCode) ?: "",
                    Modifier.height(rowHeight),
                    style = style,
                    fontFamily = FontFamily.Monospace,
                    color = if (s == step) colors.primary else colors.onSurfaceVariant,
                    maxLines = 1,
                )
            }
        }
    }
}

/**
 * The current code with its countdown, for previews.
 */
@Composable
private fun LiveCode(account: OtpAccount, clock: () -> Long, style: TextStyle) {
    val now = clock()
    Text(
        codeOrNull(account, now)?.let(::formatCode) ?: "invalid",
        style = style,
        fontFamily = FontFamily.Monospace,
        color = MaterialTheme.colorScheme.primary,
    )
    Countdown(account, now)
}

/**
 * An account in the list: name, then the code below it, so that both fit on a phone.
 */
@Composable
private fun AccountRow(account: OtpAccount, clock: () -> Long, onCopy: () -> Unit, onOpen: () -> Unit) {
    val now = clock()
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onCopy).padding(start = 12.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Avatar(account)
        Column(Modifier.weight(1f)) {
            val subtitle = accountSubtitle(account)
            Text(
                if (subtitle.isEmpty()) accountTitle(account) else "${accountTitle(account)} · $subtitle",
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            CodeDrum(account, now, MaterialTheme.typography.headlineSmall)
        }
        Countdown(account, now)
        TextButton(onClick = onOpen) { Text("›") }
    }
}

@Composable
private fun AccountDetail(
    account: OtpAccount,
    clock: () -> Long,
    backupCodesShown: Boolean,
    onToggleBackupCodes: () -> Unit,
    onCopy: () -> Unit,
    modifier: Modifier,
) {
    val now = clock()
    val code = codeOrNull(account, now)
    Column(
        modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Avatar(account)
            Column {
                Text(accountTitle(account), style = MaterialTheme.typography.titleMedium)
                if (accountSubtitle(account).isNotEmpty()) {
                    Text(accountSubtitle(account), color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            CodeDrum(account, now, MaterialTheme.typography.displaySmall)
            Countdown(account, now)
        }
        Button(onClick = onCopy, enabled = code != null) { Text("Copy code") }
        Text(
            "${account.algorithm} · ${account.digits} digits · every ${account.period} s",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        HorizontalDivider()
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Backup codes", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            if (account.backupCodes.isNotEmpty()) {
                OutlinedButton(onClick = onToggleBackupCodes) { Text(if (backupCodesShown) "Hide" else "Show") }
            }
        }
        when {
            account.backupCodes.isEmpty() -> Text(
                "None. Edit the account to add them.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            backupCodesShown -> SelectionContainer {
                Text(account.backupCodes, fontFamily = FontFamily.Monospace)
            }
            else -> Text(PASSWORD_MASK, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AccountEditor(ui: OtpScreenState, id: String?, clock: () -> Long, enabled: Boolean, modifier: Modifier) {
    val draft = ui.draft
    val parsed = remember(draft, id) { draft.toAccount(id) }
    val canScan = qrScannerAvailable()
    Column(
        modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            if (canScan) {
                "Scan the QR code or paste its otpauth:// link to fill in the fields, or enter them by hand."
            } else {
                "Paste the otpauth:// link of the QR code to fill in the fields, or enter them by hand."
            },
            style = MaterialTheme.typography.bodyMedium,
        )
        if (canScan) {
            Button(
                onClick = {
                    ui.uriError = null
                    ui.scanning = true
                },
                enabled = enabled,
            ) { Text("Scan QR code") }
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SecretInput {
                OutlinedTextField(
                    value = ui.uri,
                    onValueChange = {
                        ui.uri = it
                        ui.uriError = null
                    },
                    label = { Text("otpauth:// link") },
                    singleLine = true,
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                )
            }
            OutlinedButton(
                onClick = { ui.fillInFromUri(ui.uri) },
                enabled = enabled && ui.uri.isNotBlank(),
            ) { Text("Fill in") }
        }
        ui.uriError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        OutlinedTextField(
            value = draft.issuer,
            onValueChange = { ui.draft = draft.copy(issuer = it) },
            label = { Text("Service (issuer)") },
            singleLine = true,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = draft.label,
            onValueChange = { ui.draft = draft.copy(label = it) },
            label = { Text("Account") },
            singleLine = true,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
        )
        SecretInput {
            OutlinedTextField(
                value = draft.secret,
                onValueChange = { ui.draft = draft.copy(secret = it) },
                label = { Text("Secret key (Base32)") },
                singleLine = true,
                enabled = enabled,
                textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            for (algorithm in OtpAlgorithm.entries) {
                FilterChip(
                    selected = draft.algorithm == algorithm,
                    onClick = { ui.draft = draft.copy(algorithm = algorithm) },
                    label = { Text(algorithm.name) },
                    enabled = enabled,
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = draft.digits,
                onValueChange = { ui.draft = draft.copy(digits = it) },
                label = { Text("Digits") },
                singleLine = true,
                enabled = enabled,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f),
            )
            OutlinedTextField(
                value = draft.period,
                onValueChange = { ui.draft = draft.copy(period = it) },
                label = { Text("Period (seconds)") },
                singleLine = true,
                enabled = enabled,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f),
            )
        }
        Text(
            "Most services use SHA1, 6 digits and 30 seconds. Authy's own tokens (e.g. Cloudflare) use 7 digits and " +
                "10 seconds.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        parsed.fold(
            onSuccess = { account ->
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Current code:")
                    LiveCode(account, clock, MaterialTheme.typography.titleLarge)
                }
            },
            onFailure = {
                if (draft.secret.isNotBlank()) Text(it.message ?: "Invalid", color = MaterialTheme.colorScheme.error)
            },
        )
        SecretInput {
            OutlinedTextField(
                value = draft.backupCodes,
                onValueChange = { ui.draft = draft.copy(backupCodes = it) },
                label = { Text("Backup codes and notes") },
                minLines = 4,
                enabled = enabled,
                textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun ImportPage(
    ui: OtpScreenState,
    lines: List<ImportLine>,
    clock: () -> Long,
    enabled: Boolean,
    onPickFile: (() -> Unit)?,
    modifier: Modifier,
) {
    LazyColumn(modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
        item {
            Column(Modifier.padding(vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "Paste one otpauth:// link per line, as the Authy extraction scripts and the plain text exports " +
                        "of other apps write them${if (onPickFile != null) ", or open such a file" else ""}. Check " +
                        "that the codes below match those of your old app before you delete anything there.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (onPickFile != null) {
                    OutlinedButton(onClick = onPickFile, enabled = enabled) { Text("Open file…") }
                }
                SecretInput {
                    OutlinedTextField(
                        value = ui.importText,
                        onValueChange = { ui.importText = it },
                        label = { Text("otpauth:// links") },
                        minLines = 4,
                        maxLines = 10,
                        enabled = enabled,
                        textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }
        items(lines) { line ->
            val account = line.account
            Row(
                Modifier.fillMaxWidth().padding(vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (account == null) {
                    Text("Line ${line.lineNumber}: ${line.error}", color = MaterialTheme.colorScheme.error)
                } else {
                    Avatar(account)
                    Column(Modifier.weight(1f)) {
                        Text(accountTitle(account), maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            when (line.duplicate) {
                                ImportDuplicate.IN_VAULT -> "Line ${line.lineNumber}: already in the vault, skipped"
                                ImportDuplicate.EARLIER_LINE ->
                                    "Line ${line.lineNumber}: the same as an earlier line, skipped"
                                null -> "Line ${line.lineNumber}: ${accountSubtitle(account)}"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (line.duplicate == null) {
                        LiveCode(account, clock, MaterialTheme.typography.titleMedium)
                    }
                }
            }
            HorizontalDivider()
        }
    }
}
