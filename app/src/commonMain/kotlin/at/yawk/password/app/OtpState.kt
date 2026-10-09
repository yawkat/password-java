package at.yawk.password.app

import at.yawk.password.client.ClientValue
import at.yawk.password.model.OtpAccount

/**
 * State of the 2FA vault, separate from the password database ([UiState]): it has its own password (the "backup
 * password") and is opened from the unlock screen.
 */
sealed interface OtpState {
    /**
     * The 2FA vault is not shown.
     */
    data object Closed : OtpState

    /**
     * Waiting for the backup password.
     */
    data class Locked(val config: AppConfig, val error: String? = null) : OtpState

    /**
     * Deriving keys and loading the vault.
     */
    data class Unlocking(val config: AppConfig) : OtpState

    /**
     * Neither the server nor the local copy has a 2FA vault. The user may create an empty one after repeating the
     * backup password.
     */
    data class ConfirmCreate(val config: AppConfig) : OtpState

    /**
     * @property accounts Accounts in vault order.
     * @property localReason Why the accounts come from the local copy, or `null` if they are the server copy.
     * @property busy A modification or reload is running. Further modifications are refused until it is done.
     * @property status Transient status bar message.
     * @property error Error to show in a dialog until [OtpViewModel.dismissError].
     */
    data class Unlocked(
        val accounts: List<OtpAccount>,
        val localReason: ClientValue.LocalReason?,
        val busy: Boolean = false,
        val status: StatusMessage? = null,
        val error: ErrorMessage? = null,
    ) : OtpState {
        // compared by identity, like UiState.Unlocked: a reload gives equal but new account objects
        override fun equals(other: Any?) = other is Unlocked &&
            accounts === other.accounts &&
            localReason == other.localReason &&
            busy == other.busy &&
            status == other.status &&
            error == other.error

        override fun hashCode() = System.identityHashCode(accounts)
    }
}
