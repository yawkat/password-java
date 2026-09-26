package at.yawk.password.android

import android.app.Application
import at.yawk.password.app.AndroidSecretClipboard

class PasswordApplication : Application() {
    /**
     * Process-wide, so its clear timer outlives the activity.
     */
    val clipboard by lazy { AndroidSecretClipboard(this) }
}
