package at.yawk.password.android

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import at.yawk.password.app.PasskeyRequest
import at.yawk.password.app.passkeyAccount
import at.yawk.password.model.Passkey
import at.yawk.password.passkey.WebAuthnJson
private const val TAG = "PasskeyProvider"

/**
 * The passkeys of the password database for Android's credential manager (Android 14 and later): the user enables it
 * under Settings, Passwords & accounts.
 *
 * The database is locked here, so this only offers entries that open [PasskeyActivity]: to create a passkey, or to
 * unlock the database for a sign-in, which then lists the passkeys ([PasskeySession]).
 */
@RequiresApi(34)
class PasskeyProviderService : CredentialProviderService() {
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            callback.onError(CreateCredentialUnsupportedException("Only passkeys are supported"))
            return
        }
        val intent = PasskeyActivity.intent(this, PasskeyActivity.MODE_CREATE)
        val entry = CreateEntry.Builder(getString(R.string.passkey_account), pendingIntent(intent)).build()
        callback.onResult(BeginCreateCredentialResponse(createEntries = listOf(entry)))
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        if (request.beginGetCredentialOptions.none { it is BeginGetPublicKeyCredentialOption }) {
            callback.onResult(BeginGetCredentialResponse())
            return
        }
        val passkeys = PasskeySession.get()
        callback.onResult(
            if (passkeys != null) {
                entries(this, request, passkeys)
            } else {
                val intent = PasskeyActivity.intent(this, PasskeyActivity.MODE_UNLOCK)
                BeginGetCredentialResponse(
                    authenticationActions = listOf(
                        AuthenticationAction(getString(R.string.passkey_unlock), pendingIntent(intent)),
                    ),
                )
            },
        )
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        PasskeySession.clear()
        callback.onResult(null)
    }

    companion object {
        /**
         * Mutable, so that the credential manager can add the request to it.
         */
        fun pendingIntent(context: Context, intent: Intent): PendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        private fun CredentialProviderService.pendingIntent(intent: Intent) = pendingIntent(this, intent)

        /**
         * The passkeys of [passkeys] that [request] can use, as entries that sign in with [PasskeyActivity].
         */
        fun entries(context: Context, request: BeginGetCredentialRequest, passkeys: List<Passkey>): BeginGetCredentialResponse {
            // The caller is checked when the passkey is used. Here only the relying party ID of a request without one
            // comes from the browser's origin.
            val defaultRpId = request.callingAppInfo?.let {
                try {
                    PasskeyCaller.of(context, it).defaultRpId
                } catch (e: SecurityException) {
                    null
                }
            }
            val entries = mutableListOf<CredentialEntry>()
            for (option in request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>()) {
                val options = try {
                    WebAuthnJson.parseRequestOptions(option.requestJson, defaultRpId)
                } catch (e: IllegalArgumentException) {
                    Log.w(TAG, "Invalid passkey request", e)
                    continue
                }
                for (passkey in PasskeyRequest.Get(options.rpId, options.allowCredentials).candidates(passkeys)) {
                    val intent = PasskeyActivity.intent(context, PasskeyActivity.MODE_GET)
                        .putExtra(PasskeyActivity.EXTRA_PASSKEY, passkey.id)
                        // one PendingIntent per entry: extras don't tell them apart
                        .setIdentifier(PasskeyActivity.MODE_GET + ":" + passkey.id)
                    entries += PublicKeyCredentialEntry.Builder(
                        context,
                        passkeyAccount(passkey),
                        pendingIntent(context, intent),
                        option,
                    ).apply {
                        if (passkey.userDisplayName.isNotEmpty()) setDisplayName(passkey.userDisplayName)
                    }.build()
                }
            }
            return BeginGetCredentialResponse(credentialEntries = entries)
        }
    }
}
