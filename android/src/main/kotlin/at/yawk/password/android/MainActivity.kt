package at.yawk.password.android

import android.os.Bundle
import android.os.SystemClock
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import at.yawk.password.app.AndroidPlatform
import at.yawk.password.app.AndroidSecretClipboard
import at.yawk.password.app.App
import at.yawk.password.app.BiometricAuthenticator
import at.yawk.password.app.OtpViewModel
import at.yawk.password.app.PasswordViewModel
import at.yawk.password.app.UiState
import at.yawk.password.app.WindowHooks
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val viewModel: PasswordViewModel by viewModels {
        viewModelFactory {
            initializer {
                // elapsedRealtime keeps counting while the device sleeps
                PasswordViewModel(AndroidPlatform(applicationContext), clock = SystemClock::elapsedRealtime)
            }
        }
    }
    private val otpViewModel: OtpViewModel by viewModels {
        viewModelFactory {
            initializer {
                OtpViewModel(AndroidPlatform(applicationContext), clock = SystemClock::elapsedRealtime)
            }
        }
    }
    private val hooks = WindowHooks()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // no screenshots, screen recordings or recents thumbnails of the passwords
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        // the fingerprint prompt needs the activity; the view model outlives it
        otpViewModel.authenticator = BiometricAuthenticator(this)
        val clipboard = AndroidSecretClipboard.get(this)
        setContent {
            App(viewModel, otpViewModel, clipboard, hooks, onExit = ::finish, touchInput = true)
        }
        // also while stopped, e.g. next to a browser in multi-window: saving our stale copy would drop the passkey
        lifecycleScope.launch { DatabaseChanges.flow.collect { viewModel.markStale() } }
        // a sign-in must not use a passkey that was deleted or replaced since it was unlocked
        lifecycleScope.launch {
            viewModel.state.map { (it as? UiState.Unlocked)?.passkeys }.filterNotNull().distinctUntilChanged().drop(1)
                .collect { PasskeySession.clear() }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        otpViewModel.authenticator = null
    }

    override fun onStart() {
        super.onStart()
        // locks right away if the app was in the background for too long, before anything is drawn
        viewModel.onForeground()
        otpViewModel.onForeground()
    }

    override fun onStop() {
        super.onStop()
        // In the background (other app, home screen, screen off): lock after a timeout (BACKGROUND_LOCK_TIMEOUT_MS),
        // and forget a typed master password now. The clipboard is left alone, the user probably switched away to
        // paste; it is cleared by its own timer.
        if (!isChangingConfigurations) {
            hooks.onBackground()
            viewModel.onBackground()
            // Unlike the password database, the 2FA vault locks right away (unless an unsaved draft is open): the
            // code was copied already, and with the fingerprint unlock opening it again is quick.
            otpViewModel.onBackground()
        }
    }
}
