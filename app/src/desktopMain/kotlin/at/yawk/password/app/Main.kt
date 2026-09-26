package at.yawk.password.app

import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import org.slf4j.LoggerFactory

fun main() {
    LoggerFactory.getLogger("at.yawk.password.app.Main").info(
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
            // wipes the master password
            viewModels.viewModelStore.clear()
            exitApplication()
        }
        CompositionLocalProvider(LocalViewModelStoreOwner provides viewModels) {
            val viewModel = viewModel { PasswordViewModel(platform) }
            val state by viewModel.state.collectAsState()
            Window(
                onCloseRequest = { hooks.requestClose(exit) },
                title = titleFor(state),
                state = rememberWindowState(size = DpSize(900.dp, 560.dp)),
                onPreviewKeyEvent = hooks::onPreviewKeyEvent,
            ) {
                App(viewModel, clipboard, hooks, onExit = exit)
            }
        }
    }
}
