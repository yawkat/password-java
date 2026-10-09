package at.yawk.password.android

import android.os.Bundle
import android.os.SystemClock
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import at.yawk.password.app.AndroidPlatform
import at.yawk.password.app.AndroidSecretClipboard
import at.yawk.password.app.App
import at.yawk.password.app.OtpViewModel
import at.yawk.password.app.PasswordViewModel
import at.yawk.password.app.WindowHooks

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
        val clipboard = AndroidSecretClipboard.get(this)
        setContent {
            App(viewModel, otpViewModel, clipboard, hooks, onExit = ::finish, touchInput = true)
        }
    }

    override fun onStart() {
        super.onStart()
        // locks right away if the app was in the background for too long, before anything is drawn
        viewModel.onForeground()
    }

    override fun onStop() {
        super.onStop()
        // In the background (other app, home screen, screen off): lock after a timeout (BACKGROUND_LOCK_TIMEOUT_MS),
        // and forget a typed master password now. The clipboard is left alone, the user probably switched away to
        // paste; it is cleared by its own timer.
        if (!isChangingConfigurations) {
            hooks.onBackground()
            viewModel.onBackground()
            // Unlike the password database, the 2FA vault locks right away. The code was copied already, and with
            // the fingerprint unlock (to come) opening it again is quick.
            otpViewModel.lockNow()
        }
    }
}
