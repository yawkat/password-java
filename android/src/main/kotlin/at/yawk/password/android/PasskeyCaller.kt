package at.yawk.password.android

import android.content.Context
import android.content.pm.Signature
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import at.yawk.password.app.AssetLinks
import at.yawk.password.passkey.PasskeyAuthenticator
import at.yawk.password.passkey.WebAuthnJson

/**
 * Who asks for a passkey through the credential manager, and whether it may use those of a relying party.
 *
 * - A browser of Google's list of privileged apps (`res/raw/privileged_browsers.json`) names the web origin it asks
 *   for. That origin must belong to the relying party.
 * - Any other app gets the origin `android:apk-key-hash:<hash of its signing certificate>`, and must be named by the
 *   relying party's Digital Asset Links ([AssetLinks]).
 *
 * @property origin The origin for `clientDataJSON`
 * @property packageName The calling app, for `clientDataJSON`; `null` for a browser
 */
@RequiresApi(34)
class PasskeyCaller private constructor(
    val origin: String,
    val packageName: String?,
    private val fingerprints: List<String> = emptyList(),
) {
    /**
     * Whether the caller may use the passkeys of [rpId]. Loads the asset links of an app's relying party, so don't
     * call this on the main thread.
     */
    fun mayUse(rpId: String): Boolean = if (packageName == null) {
        WebAuthnJson.originMatchesRpId(origin, rpId)
    } else {
        // the caller chose rpId: whatever goes wrong with it, the answer is no
        try {
            AssetLinks.allows(AssetLinks.fetch(rpId), packageName, fingerprints)
        } catch (e: Exception) {
            false
        }
    }

    /** The relying party ID if the request names none: the host of a web origin */
    val defaultRpId: String? get() = if (packageName == null) WebAuthnJson.webOriginHost(origin) else null

    companion object {
        @Volatile
        private var allowlist: String? = null

        private fun allowlist(context: Context): String = allowlist
            ?: context.resources.openRawResource(R.raw.privileged_browsers).use { it.readBytes().decodeToString() }
                .also { allowlist = it }

        fun of(context: Context, info: CallingAppInfo): PasskeyCaller {
            if (info.isOriginPopulated()) {
                val allowlist = allowlist(context)
                // throws unless the caller is one of the privileged browsers
                val origin = try {
                    info.getOrigin(allowlist)
                } catch (e: IllegalStateException) {
                    null
                } catch (e: IllegalArgumentException) {
                    null
                } ?: throw SecurityException("${info.packageName} is not a known browser, but names a website")
                return PasskeyCaller(origin, null)
            }
            val signing = info.signingInfo
            val current = signing.apkContentsSigners.firstOrNull()
                ?: throw SecurityException("${info.packageName} has no signature")
            // a rotated key still counts for the older certificates the website may name
            val all: Array<Signature> = if (signing.hasMultipleSigners()) {
                signing.apkContentsSigners
            } else {
                signing.signingCertificateHistory ?: signing.apkContentsSigners
            }
            return PasskeyCaller(
                "android:apk-key-hash:" + PasskeyAuthenticator.base64Url(PasskeyAuthenticator.sha256(current.toByteArray())),
                info.packageName,
                all.map { fingerprint(it.toByteArray()) },
            )
        }

        /** SHA-256 in the notation of asset links: upper-case hex, colon-separated */
        fun fingerprint(certificate: ByteArray): String =
            PasskeyAuthenticator.sha256(certificate).joinToString(":") { "%02X".format(it) }
    }
}
