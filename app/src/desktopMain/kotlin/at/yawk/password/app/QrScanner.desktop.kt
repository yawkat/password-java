package at.yawk.password.app

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@Composable
actual fun qrScannerAvailable() = false

@Composable
actual fun QrScanner(onResult: (String) -> Unit, onError: (String) -> Unit, modifier: Modifier) {
}
