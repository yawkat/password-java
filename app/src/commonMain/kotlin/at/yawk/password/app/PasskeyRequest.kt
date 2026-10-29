package at.yawk.password.app

import at.yawk.password.model.Passkey
import at.yawk.password.passkey.PasskeyAuthenticator

/**
 * A relying party (a website or app) asks for a passkey: through the desktop security key, or Android's credential
 * manager. The user answers it in the app once the database is unlocked, see [PasswordViewModel.handlePasskeyRequest].
 *
 * Not data classes: the same request asked twice is two requests.
 */
sealed interface PasskeyRequest {
    val rpId: String

    /**
     * Create [passkey] (already made by the caller, with its relying party and user) and add it to the database.
     *
     * @property excludeCredentials Credential IDs that the relying party already knows for this account. If the
     * database has one of them, nothing is created.
     */
    class Create(val passkey: Passkey, val excludeCredentials: List<ByteArray>) : PasskeyRequest {
        override val rpId: String get() = passkey.rpId

        /** The passkey of [excludeCredentials] in [passkeys], if there is one */
        fun excluded(passkeys: List<Passkey>): Passkey? =
            if (excludeCredentials.isEmpty()) null else PasskeyAuthenticator.find(passkeys, rpId, excludeCredentials).firstOrNull()
    }

    /**
     * Sign in with one of the passkeys for [rpId].
     *
     * @property allowCredentials The credential IDs that the relying party accepts, empty for any
     */
    class Get(override val rpId: String, val allowCredentials: List<ByteArray>) : PasskeyRequest {
        fun candidates(passkeys: List<Passkey>): List<Passkey> =
            PasskeyAuthenticator.find(passkeys, rpId, allowCredentials)
    }
}

sealed interface PasskeyOutcome {
    /** The passkey of a [PasskeyRequest.Create] was saved. */
    data object Created : PasskeyOutcome

    /** The database already has a passkey of [PasskeyRequest.Create.excludeCredentials]; the user was told. */
    data object Excluded : PasskeyOutcome

    /** The user chose [passkey] for a [PasskeyRequest.Get]. */
    class Chosen(val passkey: Passkey) : PasskeyOutcome

    /** The database has no passkey for a [PasskeyRequest.Get]; the user was told. */
    data object NoCredentials : PasskeyOutcome

    /** The user refused. */
    data object Denied : PasskeyOutcome

    /** Saving a created passkey failed. The error is shown in the app. */
    data object Failed : PasskeyOutcome
}

/**
 * The user's answer to a [PasskeyRequest], see [PasswordViewModel.answerPasskeyRequest].
 */
sealed interface PasskeyAnswer {
    /**
     * Create the passkey, or sign in with [passkey].
     */
    class Approve(val passkey: Passkey? = null) : PasskeyAnswer

    /**
     * Refuse, or acknowledge that there is nothing to do (an excluded passkey, or none to sign in with).
     */
    data object Dismiss : PasskeyAnswer
}
