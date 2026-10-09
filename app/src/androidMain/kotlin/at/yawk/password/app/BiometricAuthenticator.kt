package at.yawk.password.app

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * The fingerprint (or another strong biometric) check, with the system prompt (`android.hardware.biometrics`, no
 * library needed on Android 10 and later).
 */
class BiometricAuthenticator(private val activity: Activity) : Authenticator {
    override suspend fun authenticate(cipher: Cipher, title: String): Cipher? =
        suspendCancellableCoroutine { continuation ->
            val executor = activity.mainExecutor
            val builder = BiometricPrompt.Builder(activity)
                .setTitle(title)
                .setConfirmationRequired(false)
                .setNegativeButton("Use the password", executor) { _, _ ->
                    if (continuation.isActive) continuation.resume(null)
                }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            }
            val cancel = CancellationSignal()
            continuation.invokeOnCancellation { cancel.cancel() }
            builder.build().authenticate(
                BiometricPrompt.CryptoObject(cipher),
                cancel,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (continuation.isActive) continuation.resume(result.cryptoObject?.cipher ?: cipher)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (!continuation.isActive) return
                        when (errorCode) {
                            BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
                            BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
                            -> continuation.resume(null)
                            else -> continuation.resumeWithException(AuthenticationException(errString.toString()))
                        }
                    }
                },
            )
        }
}

/**
 * Whether the device can do the check that [BiometricAuthenticator] asks for: a screen lock, and a strong biometric
 * (e.g. a fingerprint) enrolled. Without them, no key that needs the check can be made.
 */
fun strongBiometricsAvailable(context: Context): Boolean {
    if (context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure != true) return false
    val biometrics = context.getSystemService(BiometricManager::class.java) ?: return false
    val result = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        biometrics.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    } else {
        @Suppress("DEPRECATION")
        biometrics.canAuthenticate()
    }
    return result == BiometricManager.BIOMETRIC_SUCCESS
}
