package at.yawk.password.android

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.domerrors.SecurityError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import at.yawk.password.app.AndroidPlatform
import at.yawk.password.app.PasskeyApp
import at.yawk.password.app.PasskeyOutcome
import at.yawk.password.app.PasskeyRequest
import at.yawk.password.app.PasswordViewModel
import at.yawk.password.app.UiState
import at.yawk.password.app.WindowHooks
import at.yawk.password.passkey.PasskeyAuthenticator
import at.yawk.password.passkey.WebAuthnJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val TAG = "PasskeyActivity"

/**
 * Opened by the credential manager through the entries of [PasskeyProviderService]: unlocks the password database with
 * the master password and creates a passkey ([MODE_CREATE]), unlocks it for a sign-in ([MODE_UNLOCK]), or signs in
 * with the chosen passkey ([MODE_GET]).
 *
 * Entering the master password counts as user verification. It is asked for every passkey operation: the activity
 * keeps nothing unlocked, apart from the list of passkeys of [MODE_UNLOCK], for the one sign-in that follows.
 */
@RequiresApi(34)
class PasskeyActivity : ComponentActivity() {
    private val viewModel: PasswordViewModel by viewModels {
        viewModelFactory {
            initializer { PasswordViewModel(AndroidPlatform(applicationContext), clock = SystemClock::elapsedRealtime) }
        }
    }
    private val hooks = WindowHooks()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        setContent { PasskeyApp(viewModel, hooks, onCancel = ::cancel) }
        // after a configuration change, the coroutine of the first instance is gone with it; start over
        when (intent.getStringExtra(EXTRA_MODE)) {
            MODE_CREATE -> lifecycleScope.launch { create() }
            MODE_UNLOCK -> lifecycleScope.launch { unlock() }
            MODE_GET -> lifecycleScope.launch { get() }
            else -> cancel()
        }
    }

    override fun onStart() {
        super.onStart()
        viewModel.onForeground()
    }

    override fun onStop() {
        super.onStop()
        // like MainActivity: forget a typed master password, and lock after a while in the background
        if (!isChangingConfigurations) {
            hooks.onBackground()
            viewModel.onBackground()
        }
    }

    private fun cancel() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    private fun finishWith(result: Intent) {
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private suspend fun create() {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val callingRequest = request?.callingRequest as? CreatePublicKeyCredentialRequest ?: return cancel()
        fun fail(e: CreateCredentialException) {
            Log.i(TAG, "Not creating a passkey: ${e.message}")
            finishWith(Intent().also { PendingIntentHandler.setCreateCredentialException(it, e) })
        }

        val caller = try {
            PasskeyCaller.of(this, request.callingAppInfo)
        } catch (e: SecurityException) {
            return fail(CreatePublicKeyCredentialDomException(SecurityError(), e.message))
        }
        val options = try {
            WebAuthnJson.parseCreationOptions(callingRequest.requestJson, caller.defaultRpId)
        } catch (e: IllegalArgumentException) {
            return fail(CreateCredentialUnknownException("Invalid request: ${e.message}"))
        }
        if (!withContext(Dispatchers.IO) { caller.mayUse(options.rpId) }) {
            return fail(CreatePublicKeyCredentialDomException(SecurityError(), "${caller.origin} may not use ${options.rpId}"))
        }
        if (!options.isEs256) {
            return fail(CreatePublicKeyCredentialDomException(NotSupportedError(), "Only ES256 is supported"))
        }
        val passkey = try {
            PasskeyAuthenticator.create(
                options.rpId, options.userId, options.userName, options.userDisplayName, System.currentTimeMillis(),
            )
        } catch (e: IllegalArgumentException) {
            return fail(CreateCredentialUnknownException("Invalid request: ${e.message}"))
        }
        // saving it, or undoing that for a cancelled request
        MainActivity.databaseChanged = true
        when (viewModel.handlePasskeyRequest(PasskeyRequest.Create(passkey, options.excludeCredentials))) {
            PasskeyOutcome.Created -> {
                val clientDataJson = WebAuthnJson.clientDataJson(
                    "webauthn.create", options.challenge, caller.origin, caller.packageName,
                )
                // a browser has signed its own clientDataJSON already (clientDataHash), and replaces ours
                val authData = PasskeyAuthenticator.registrationAuthData(passkey, true)
                val json = WebAuthnJson.registrationResponse(passkey, clientDataJson, authData)
                finishWith(Intent().also {
                    PendingIntentHandler.setCreateCredentialResponse(it, CreatePublicKeyCredentialResponse(json))
                })
            }
            PasskeyOutcome.Excluded -> fail(CreatePublicKeyCredentialDomException(InvalidStateError(), "Passkey exists"))
            PasskeyOutcome.Failed -> fail(CreateCredentialUnknownException("The passkey could not be saved"))
            else -> fail(CreateCredentialCancellationException())
        }
    }

    /**
     * Unlock, and return the passkeys to choose from.
     */
    private suspend fun unlock() {
        val request = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent) ?: return cancel()
        val unlocked = viewModel.state.first { it is UiState.Unlocked } as UiState.Unlocked
        val candidates = PasskeyProviderService.candidates(this, request, unlocked.passkeys)
        val packageName = request.callingAppInfo?.packageName
        if (packageName != null) {
            PasskeySession.put(candidates.map { it.second }.distinct(), packageName)
        }
        val response = BeginGetCredentialResponse(credentialEntries = PasskeyProviderService.entries(this, candidates))
        finishWith(Intent().also { PendingIntentHandler.setBeginGetCredentialResponse(it, response) })
    }

    /**
     * Sign in with the passkey chosen from those of [unlock].
     */
    private suspend fun get() {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return cancel()
        fun fail(e: GetCredentialException) {
            Log.i(TAG, "Not signing in: ${e.message}")
            finishWith(Intent().also { PendingIntentHandler.setGetCredentialException(it, e) })
        }

        val passkey = PasskeySession.take(intent.getStringExtra(EXTRA_PASSKEY) ?: "", request.callingAppInfo.packageName)
            ?: return fail(NoCredentialException("Unlock the password database again"))
        val caller = try {
            PasskeyCaller.of(this, request.callingAppInfo)
        } catch (e: SecurityException) {
            return fail(GetPublicKeyCredentialDomException(SecurityError(), e.message))
        }
        for (option in request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>()) {
            val options = try {
                WebAuthnJson.parseRequestOptions(option.requestJson, caller.defaultRpId)
            } catch (e: IllegalArgumentException) {
                continue
            }
            if (PasskeyRequest.Get(options.rpId, options.allowCredentials).candidates(listOf(passkey)).isEmpty()) {
                continue
            }
            if (!withContext(Dispatchers.IO) { caller.mayUse(options.rpId) }) {
                return fail(GetPublicKeyCredentialDomException(SecurityError(), "${caller.origin} may not use ${options.rpId}"))
            }
            val clientDataJson = WebAuthnJson.clientDataJson("webauthn.get", options.challenge, caller.origin, caller.packageName)
            val authData = PasskeyAuthenticator.assertionAuthData(options.rpId, true)
            // A privileged browser signs its own clientDataJSON (clientDataHash), and replaces ours. Any other app
            // gets ours: a hash of its own could claim a web origin.
            val clientDataHash = option.clientDataHash.takeIf { caller.packageName == null }
            val signature = PasskeyAuthenticator.sign(
                passkey,
                authData,
                clientDataHash ?: PasskeyAuthenticator.sha256(clientDataJson),
            )
            val json = WebAuthnJson.assertionResponse(passkey, clientDataJson, authData, signature)
            return finishWith(Intent().also {
                PendingIntentHandler.setGetCredentialResponse(it, GetCredentialResponse(PublicKeyCredential(json)))
            })
        }
        fail(GetPublicKeyCredentialDomException(NotAllowedError(), "The passkey does not fit the request"))
    }

    companion object {
        const val EXTRA_MODE = "at.yawk.password.android.PASSKEY_MODE"
        const val EXTRA_PASSKEY = "at.yawk.password.android.PASSKEY_ID"
        const val MODE_CREATE = "create"
        const val MODE_UNLOCK = "unlock"
        const val MODE_GET = "get"

        fun intent(context: Context, mode: String): Intent =
            Intent(context, PasskeyActivity::class.java).putExtra(EXTRA_MODE, mode)
                // PendingIntents that differ only in extras are the same, so each mode needs its own
                .setIdentifier(mode)
    }
}
