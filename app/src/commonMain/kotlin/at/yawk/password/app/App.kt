package at.yawk.password.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
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
import androidx.compose.ui.unit.dp

/**
 * Connects the platform window to the current screen: close requests (the screen may refuse or ask about unsaved
 * edits) and window-wide keyboard shortcuts, which must work even when no element has the focus.
 */
class WindowHooks {
    internal var closeHandler: ((onConfirmed: () -> Unit) -> Unit)? = null
    internal var keyHandler: ((KeyEvent) -> Boolean)? = null

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

@Composable
fun App(
    viewModel: PasswordViewModel,
    clipboard: SecretClipboard,
    hooks: WindowHooks,
    onExit: () -> Unit,
) {
    val state by viewModel.state.collectAsState()
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
        Surface(Modifier.fillMaxSize()) {
            // the password field is cleared as soon as the view model has taken the password
            val password = rememberTextFieldState()
            when (val s = state) {
                is UiState.Locked -> UnlockScreen(s.config, s.error, busy = false, password, viewModel, onExit)
                is UiState.Unlocking -> UnlockScreen(s.config, null, busy = true, password, viewModel, onExit)
                is UiState.ConfirmCreate -> {
                    UnlockScreen(s.config, null, busy = true, password, viewModel, onExit)
                    CreateDatabaseDialog(s.config, viewModel)
                }
                is UiState.Unlocked -> {
                    val mainState = remember { MainScreenState() }
                    MainScreen(s, mainState, viewModel, clipboard, hooks)
                }
                is UiState.Error -> ErrorScreen(s.message, onExit)
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
    onExit: () -> Unit,
) {
    var url by remember(config.url) { mutableStateOf(config.url) }
    val focus = remember { FocusRequester() }
    fun unlock() {
        if (!busy && password.text.isNotEmpty()) {
            viewModel.unlock(url, password.text)
            // the view model keeps its own (wipeable) copy
            password.clearText()
        }
    }
    LaunchedEffect(busy) {
        if (!busy) {
            focus.requestFocus()
        }
    }
    val onEnter = Modifier.onPreviewKeyEvent {
        if (it.type == KeyEventType.KeyDown && (it.key == Key.Enter || it.key == Key.NumPadEnter)) {
            unlock()
            true
        } else {
            false
        }
    }
    Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
        Column(Modifier.widthIn(max = 480.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Unlock password database", style = MaterialTheme.typography.headlineSmall)
            OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text("Server") },
                singleLine = true,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().then(onEnter),
            )
            OutlinedSecureTextField(
                state = password,
                label = { Text("Master password") },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().focusRequester(focus).then(onEnter),
            )
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
                TextButton(onClick = onExit) { Text("Close") }
                Button(onClick = ::unlock, enabled = !busy) { Text("Unlock") }
            }
        }
    }
}

@Composable
private fun CreateDatabaseDialog(config: AppConfig, viewModel: PasswordViewModel) {
    val repeated = rememberTextFieldState()
    val focus = remember { FocusRequester() }
    fun create() {
        viewModel.confirmCreate(repeated.text)
        repeated.clearText()
    }
    LaunchedEffect(Unit) { focus.requestFocus() }
    AlertDialog(
        onDismissRequest = { viewModel.cancelCreate() },
        title = { Text("No database found") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "No password database exists on the server or in ${config.storageDirectory}.\n\n" +
                        "Create a new, empty database with this master password?",
                )
                OutlinedSecureTextField(
                    state = repeated,
                    label = { Text("Repeat the master password") },
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
