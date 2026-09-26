package at.yawk.password.app

import androidx.compose.runtime.Composable

/**
 * Handles the system back button (Android) while [enabled]. Without an enabled handler, back leaves the app. There is
 * no such button on desktop, so this does nothing there.
 */
@Composable
expect fun PlatformBackHandler(enabled: Boolean, onBack: () -> Unit)
