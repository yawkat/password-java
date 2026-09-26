package at.yawk.password.app

import androidx.compose.runtime.Composable

/**
 * For text fields holding secrets: asks the soft keyboard (Android) not to suggest or learn what is typed. Does
 * nothing on desktop.
 */
@Composable
expect fun SecretInput(content: @Composable () -> Unit)
