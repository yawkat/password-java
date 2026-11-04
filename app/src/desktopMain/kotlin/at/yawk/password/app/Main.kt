package at.yawk.password.app

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import at.yawk.password.app.fido.SecurityKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger("at.yawk.password.app.Main")

fun main() {
    log.info(
        "starting (XDG_SESSION_TYPE={}, WAYLAND_DISPLAY={}, DISPLAY={})",
        System.getenv("XDG_SESSION_TYPE"), System.getenv("WAYLAND_DISPLAY"), System.getenv("DISPLAY"),
    )
    val platform = DesktopPlatform()
    val clipboard = AwtSecretClipboard()
    val viewModels = object : ViewModelStoreOwner {
        override val viewModelStore = ViewModelStore()
    }
    application {
        val hooks = remember { WindowHooks() }
        val exit = {
            clipboard.clearIfOurs()
            // wipes the master password and the backup password
            viewModels.viewModelStore.clear()
            exitApplication()
        }
        CompositionLocalProvider(LocalViewModelStoreOwner provides viewModels) {
            val viewModel = viewModel { PasswordViewModel(platform) }
            val otpViewModel = viewModel { OtpViewModel(platform) }
            val state by viewModel.state.collectAsState()
            val otpState by otpViewModel.state.collectAsState()
            val passkeyRequest by viewModel.passkeyRequest.collectAsState()
            var securityKeyError by remember { mutableStateOf<String?>(null) }
            LaunchedEffect(viewModel) {
                // reading the configuration and opening /dev/uhid block, so not on the EDT
                var key: SecurityKey? = null
                try {
                    withContext(Dispatchers.IO) {
                        key = startSecurityKey(platform, viewModel) { securityKeyError = it }
                    }
                    awaitCancellation()
                } finally {
                    withContext(NonCancellable + Dispatchers.IO) { key?.close() }
                }
            }
            Window(
                onCloseRequest = { hooks.requestClose(exit) },
                title = titleFor(state, otpState),
                state = rememberWindowState(size = DpSize(900.dp, 560.dp)),
                onPreviewKeyEvent = hooks::onPreviewKeyEvent,
            ) {
                App(viewModel, otpViewModel, clipboard, hooks, onExit = exit)
                // a browser asks for a passkey: show the request
                LaunchedEffect(passkeyRequest) {
                    if (passkeyRequest != null) {
                        window.isMinimized = false
                        window.toFront()
                        window.requestFocus()
                    }
                }
                securityKeyError?.let { error ->
                    AlertDialog(
                        onDismissRequest = { securityKeyError = null },
                        title = { Text("Security key unavailable") },
                        text = { Text(error) },
                        confirmButton = { Button(onClick = { securityKeyError = null }) { Text("OK") } },
                    )
                }
            }
        }
    }
}

/**
 * Create the security key if the configuration asks for it.
 *
 * @return The key, or `null` if it is disabled or could not be created (then [onError] was called)
 */
private fun startSecurityKey(
    platform: DesktopPlatform,
    viewModel: PasswordViewModel,
    onError: (String) -> Unit,
): SecurityKey? = try {
    if (platform.securityKeyEnabled()) {
        SecurityKey.start(viewModel::handlePasskeyRequest, viewModel::unlockedPasskeys)
    } else {
        null
    }
} catch (e: Exception) {
    log.warn("Could not create the security key", e)
    onError(
        "Could not create the security key for passkeys: ${e.message ?: e}\n\n" +
            "It needs the password-uhid helper, or read and write access to /dev/uhid, see the README.",
    )
    null
}
