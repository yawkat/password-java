package at.yawk.password.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp

/**
 * Connects the platform window to the current screen: close requests (the screen may refuse or ask about unsaved
 * edits) and window-wide keyboard shortcuts, which must work even when no element has the focus.
 */
class WindowHooks {
    internal var closeHandler: ((onConfirmed: () -> Unit) -> Unit)? = null
    internal var keyHandler: ((KeyEvent) -> Boolean)? = null
    internal val backgroundHandlers = mutableSetOf<() -> Unit>()

    /**
     * To be called when the app goes to the background (Android). Forgets master passwords that were typed but not
     * submitted; locking is up to the caller ([PasswordViewModel.onBackground]).
     */
    fun onBackground() {
        backgroundHandlers.toList().forEach { it() }
    }

    fun requestClose(onConfirmed: () -> Unit) {
        val h = closeHandler
        if (h == null) onConfirmed() else h(onConfirmed)
    }

    /**
     * To be called for every key event of the window before it is dispatched to the focused element.
     */
    fun onPreviewKeyEvent(event: KeyEvent): Boolean = keyHandler?.invoke(event) ?: false
}

/**
 * Window title for the given state.
 */
fun titleFor(state: UiState) = when (state) {
    is UiState.Unlocked -> "Passwords"
    else -> "Unlock password database"
}

/**
 * @param touchInput Whether this runs on a touch device (Android). The unlocked screen then uses a single-pane layout
 * made for touch and small screens instead of the desktop layout, which relies on keyboard shortcuts and double-clicks.
 */
@Composable
fun App(
    viewModel: PasswordViewModel,
    clipboard: SecretClipboard,
    hooks: WindowHooks,
    onExit: () -> Unit,
    touchInput: Boolean = false,
) {
    val state by viewModel.state.collectAsState()
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
        Surface(Modifier.fillMaxSize()) {
            // Not rememberSaveable, so the password never ends up in saved instance state. The field is cleared (with
            // its undo history) as soon as the view model has taken the password, and replaced for every session.
            val password = remember(state is UiState.Unlocked) { TextFieldState() }
            // keep clear of the system bars, cutouts and the soft keyboard (Android; no insets on desktop)
            Box(Modifier.fillMaxSize().safeDrawingPadding()) {
                when (val s = state) {
                    is UiState.Locked ->
                        UnlockScreen(s.config, s.error, busy = false, password, viewModel, hooks, touchInput, onExit)
                    is UiState.Unlocking ->
                        UnlockScreen(s.config, null, busy = true, password, viewModel, hooks, touchInput, onExit)
                    is UiState.ConfirmCreate -> {
                        UnlockScreen(s.config, null, busy = true, password, viewModel, hooks, touchInput, onExit)
                        CreateDatabaseDialog(s.config, viewModel, hooks)
                    }
                    is UiState.Unlocked -> {
                        MainScreen(s, viewModel.screenState, viewModel, clipboard, hooks, touchInput)
                    }
                    is UiState.Error -> ErrorScreen(s.message, onExit)
                }
            }
        }
    }
}

@Composable
private fun UnlockScreen(
    config: AppConfig,
    error: String?,
    busy: Boolean,
    password: TextFieldState,
    viewModel: PasswordViewModel,
    hooks: WindowHooks,
    touchInput: Boolean,
    onExit: () -> Unit,
) {
    var url by remember(config.url) { mutableStateOf(config.url) }
    val focus = remember { FocusRequester() }
    fun unlock() {
        if (!busy && password.text.isNotEmpty()) {
            viewModel.unlock(url, password.text)
            // the view model keeps its own (wipeable) copy
            password.clearSecret()
        }
    }
    LaunchedEffect(busy) {
        if (!busy) {
            focus.requestFocus()
        }
    }
    DisposableEffect(hooks, password) {
        val handler = { password.clearSecret() }
        hooks.backgroundHandlers += handler
        onDispose { hooks.backgroundHandlers -= handler }
    }
    val onEnter = Modifier.onPreviewKeyEvent {
        if (it.type == KeyEventType.KeyDown && (it.key == Key.Enter || it.key == Key.NumPadEnter)) {
            unlock()
            true
        } else {
            false
        }
    }
    // centered, and scrollable when the soft keyboard leaves too little room
    BoxWithConstraints(Modifier.fillMaxSize()) {
        Box(
            Modifier.verticalScroll(rememberScrollState()).heightIn(min = maxHeight).fillMaxWidth().padding(24.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(Modifier.widthIn(max = 480.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Unlock password database", style = MaterialTheme.typography.headlineSmall)
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Server") },
                    singleLine = true,
                    enabled = !busy,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Uri,
                        autoCorrectEnabled = false,
                        imeAction = ImeAction.Next,
                    ),
                    modifier = Modifier.fillMaxWidth().then(onEnter),
                )
                SecretInput {
                    OutlinedSecureTextField(
                        state = password,
                        label = { Text("Master password") },
                        enabled = !busy,
                        // the soft keyboard's action button unlocks
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done,
                        ),
                        onKeyboardAction = { unlock() },
                        modifier = Modifier.fillMaxWidth().focusRequester(focus).then(onEnter),
                    )
                }
                Text(
                    "Local copy: ${config.storageDirectory}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (error != null) {
                    Text(error, color = MaterialTheme.colorScheme.error)
                }
                if (busy) {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End)) {
                    // Android apps are left with the back or home button
                    if (!touchInput) {
                        TextButton(onClick = onExit) { Text("Close") }
                    }
                    Button(onClick = ::unlock, enabled = !busy) { Text("Unlock") }
                }
            }
        }
    }
}

@Composable
private fun CreateDatabaseDialog(config: AppConfig, viewModel: PasswordViewModel, hooks: WindowHooks) {
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
        title = { Text("No database found") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "No password database exists on the server or in ${config.storageDirectory}.\n\n" +
                        "Create a new, empty database with this master password?",
                )
                SecretInput {
                    OutlinedSecureTextField(
                        state = repeated,
                        label = { Text("Repeat the master password") },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done,
                        ),
                        onKeyboardAction = { create() },
                        modifier = Modifier.fillMaxWidth().focusRequester(focus).onPreviewKeyEvent {
                            if (it.type == KeyEventType.KeyDown && (it.key == Key.Enter || it.key == Key.NumPadEnter)) {
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

@Composable
private fun ErrorScreen(message: String, onExit: () -> Unit) {
    AlertDialog(
        onDismissRequest = onExit,
        title = { Text("Configuration error") },
        text = { Text(message) },
        confirmButton = { Button(onClick = onExit) { Text("Close") } },
    )
}
