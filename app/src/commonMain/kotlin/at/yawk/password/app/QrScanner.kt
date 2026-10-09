package at.yawk.password.app

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

/**
 * Whether [QrScanner] works on this platform (Android, with a camera).
 */
@Composable
expect fun qrScannerAvailable(): Boolean

/**
 * The camera preview, which calls [onResult] once with the text of the first QR code it sees. Asks for the camera
 * permission first, and calls [onError] if it is denied or the camera fails. The text may hold a secret: it is never
 * logged.
 */
@Composable
expect fun QrScanner(onResult: (String) -> Unit, onError: (String) -> Unit, modifier: Modifier)
