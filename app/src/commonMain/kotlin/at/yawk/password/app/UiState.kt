package at.yawk.password.app

import at.yawk.password.model.PasswordEntry

sealed interface UiState {
    /**
     * Waiting for the master password.
     *
     * @property error Why the last unlock attempt failed, if it did.
     */
    data class Locked(val config: AppConfig, val error: String? = null) : UiState

    /**
     * Deriving keys and loading the database.
     */
    data class Unlocking(val config: AppConfig) : UiState

    /**
     * Neither the server nor the local copy has a database. The user may create an empty one after repeating the
     * master password.
     */
    data class ConfirmCreate(val config: AppConfig) : UiState

    /**
     * @property entries Entries in database order. Entries are compared by identity, as in `PasswordStore`.
     * @property fromLocalStorage The server was unreachable and the data came from the local copy.
     * @property busy A modification or reload is running. Further modifications are refused until it is done.
     * @property offlineSaveConfirmed The user agreed to overwrite the server copy with the (offline) local copy.
     * @property status Transient status bar message.
     * @property error Error to show in a dialog until [PasswordViewModel.dismissError].
     */
    data class Unlocked(
        val entries: List<PasswordEntry>,
        val fromLocalStorage: Boolean,
        val busy: Boolean = false,
        val offlineSaveConfirmed: Boolean = false,
        val status: StatusMessage? = null,
        val error: ErrorMessage? = null,
    ) : UiState

    /**
     * Unrecoverable error, e.g. unreadable configuration.
     */
    data class Error(val message: String) : UiState
}

/**
 * Deliberately not a data class: showing the same text twice must still count as a new message.
 */
class StatusMessage(val text: String) {
    override fun toString() = text
}

data class ErrorMessage(val title: String, val text: String)
