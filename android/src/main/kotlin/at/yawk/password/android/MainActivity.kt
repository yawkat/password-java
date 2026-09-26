package at.yawk.password.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import at.yawk.password.app.AndroidPlatform
import at.yawk.password.app.App
import at.yawk.password.app.PasswordViewModel
import at.yawk.password.app.WindowHooks

class MainActivity : ComponentActivity() {
    private val viewModel: PasswordViewModel by viewModels {
        viewModelFactory {
            initializer { PasswordViewModel(AndroidPlatform(applicationContext)) }
        }
    }
    private val hooks = WindowHooks()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // no screenshots, screen recordings or recents thumbnails of the passwords
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        val clipboard = (application as PasswordApplication).clipboard
        setContent {
            App(viewModel, clipboard, hooks, onExit = ::finish, touchInput = true)
        }
    }

    override fun onStop() {
        super.onStop()
        // In the background (other app, home screen, screen off): lock, and forget a typed master password. The
        // clipboard is left alone, the user probably switched away to paste; it is cleared by its timer.
        if (!isChangingConfigurations) {
            hooks.onBackground()
            viewModel.lockWhenIdle()
        }
    }
}
