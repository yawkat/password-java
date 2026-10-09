package at.yawk.password.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.input.TextFieldValue
import at.yawk.password.model.OtpAccount

/**
 * The pages of the unlocked 2FA vault, besides the account list.
 */
sealed interface OtpPage {
    /** The list of accounts */
    data object List : OtpPage

    /** One account, with its backup codes */
    data class Detail(val id: String) : OtpPage

    /**
     * The account editor.
     *
     * @property id The account being edited, or `null` for a new one.
     * @property original The fields as they were, to tell whether there are unsaved changes.
     */
    data class Edit(val id: String?, val original: OtpDraft) : OtpPage

    /** Bulk import of `otpauth://` URIs */
    data object Import : OtpPage
}

sealed interface OtpDialog {
    class ConfirmDelete(val account: OtpAccount) : OtpDialog
    class ConfirmDiscard(val onDiscard: () -> Unit) : OtpDialog
    class ConfirmOfflineSave(val onConfirm: () -> Unit) : OtpDialog
}

/**
 * UI state of the unlocked 2FA vault. It lives in [OtpViewModel] rather than the composition, so that recreating the
 * activity (Android) keeps drafts, and is replaced for every session.
 */
class OtpScreenState {
    var query by mutableStateOf(TextFieldValue(""))
    var page by mutableStateOf<OtpPage>(OtpPage.List)
    var draft by mutableStateOf(OtpDraft())
    /** The URI field of the editor */
    var uri by mutableStateOf("")
    /** Why the last link (pasted or scanned) could not be read */
    var uriError by mutableStateOf<String?>(null)
    /** The editor shows the QR code scanner */
    var scanning by mutableStateOf(false)
    var importText by mutableStateOf("")
    var dialog by mutableStateOf<OtpDialog?>(null)
    /** Whether the backup codes are shown on the detail page */
    var backupCodesShown by mutableStateOf(false)
    /** The user agreed to overwrite the server copy with the local copy */
    var offlineSaveConfirmed by mutableStateOf(false)

    val isModified: Boolean
        get() = when (val p = page) {
            is OtpPage.Edit -> draft != p.original || uri.isNotEmpty()
            OtpPage.Import -> importText.isNotBlank()
            else -> false
        }

    fun startEditing(account: OtpAccount?) {
        val draft = if (account == null) OtpDraft() else OtpDraft.of(account)
        this.draft = draft
        uri = ""
        uriError = null
        scanning = false
        page = OtpPage.Edit(account?.id, draft)
    }

    fun openDetail(account: OtpAccount) {
        backupCodesShown = false
        page = OtpPage.Detail(account.id)
    }

    /**
     * Fill in the editor from an `otpauth://` link, keeping the backup codes typed so far.
     */
    fun fillInFromUri(text: String) {
        OtpDraft.fromUri(text, draft.backupCodes).fold(
            onSuccess = {
                draft = it
                uri = ""
                uriError = null
            },
            onFailure = { uriError = it.message },
        )
    }

    fun startImport() {
        importText = ""
        page = OtpPage.Import
    }

    fun backToList() {
        page = OtpPage.List
        draft = OtpDraft()
        uri = ""
        uriError = null
        scanning = false
        importText = ""
        backupCodesShown = false
    }
}
