package at.yawk.password.app

import androidx.compose.runtime.Composable

@Composable
actual fun SecretInput(content: @Composable () -> Unit) = content()
