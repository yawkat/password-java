package at.yawk.password.app

import at.yawk.password.model.OtpAccount
import at.yawk.password.model.OtpAlgorithm
import at.yawk.password.otp.OtpAuthUri
import at.yawk.password.otp.Totp
import java.text.Collator

/**
 * The name an account is shown with: its issuer, else its label.
 */
fun accountTitle(account: OtpAccount): String =
    account.issuer.ifEmpty { account.label }.ifEmpty { "(unnamed)" }

/**
 * The second line of an account: its label, if the title is the issuer.
 */
fun accountSubtitle(account: OtpAccount): String = if (account.issuer.isEmpty()) "" else account.label

/**
 * The accounts whose issuer or label contains [query] (case-insensitive), sorted by title and label.
 */
fun filterAccounts(accounts: List<OtpAccount>, query: String): List<OtpAccount> {
    val collator = Collator.getInstance().apply { strength = Collator.SECONDARY }
    return accounts
        .filter { it.issuer.contains(query, ignoreCase = true) || it.label.contains(query, ignoreCase = true) }
        .sortedWith(compareBy<OtpAccount, String>(collator) { accountTitle(it) }.thenBy(collator) { it.label })
}

/**
 * A code split in two groups for reading, e.g. "123 456" or "123 4567".
 */
fun formatCode(code: String): String {
    val split = code.length / 2
    return code.substring(0, split) + " " + code.substring(split)
}

/**
 * The code of the account at [unixMillis], or `null` if the account is invalid (e.g. written by other software).
 */
fun codeOrNull(account: OtpAccount, unixMillis: Long): String? = try {
    Totp.code(account, unixMillis)
} catch (e: IllegalArgumentException) {
    null
}

/**
 * The letter on an account's avatar.
 */
fun avatarLetter(account: OtpAccount): String =
    account.issuer.ifEmpty { account.label }.firstOrNull { it.isLetterOrDigit() }?.uppercaseChar()?.toString() ?: "?"

/**
 * Hue (0 to 360) of an account's avatar, the same for the same issuer on every device.
 */
fun avatarHue(account: OtpAccount): Float {
    var hash = 0
    for (c in accountTitle(account).lowercase()) {
        hash = hash * 31 + c.code
    }
    return Math.floorMod(hash, 360).toFloat()
}

/**
 * The fields of the account editor, as text, and the account they describe.
 */
data class OtpDraft(
    val issuer: String = "",
    val label: String = "",
    val secret: String = "",
    val algorithm: OtpAlgorithm = OtpAlgorithm.SHA1,
    val digits: String = "6",
    val period: String = "30",
    val backupCodes: String = "",
) {
    // without the secret and the backup codes, so they never end up in logs
    override fun toString() = "OtpDraft(issuer=$issuer, label=$label)"

    /**
     * @param id The id of the account being edited, or `null` for a new one.
     * @return The account, or an error message for the user (never containing the secret).
     */
    fun toAccount(id: String?): Result<OtpAccount> {
        val account = OtpAccount()
        if (id != null) account.id = id
        account.issuer = issuer
        account.label = label
        account.secret = secret
        account.algorithm = algorithm
        account.digits = digits.trim().toIntOrNull() ?: return Result.failure(IllegalArgumentException("Invalid number of digits"))
        account.period = period.trim().toIntOrNull() ?: return Result.failure(IllegalArgumentException("Invalid period"))
        account.backupCodes = backupCodes
        if (secret.isBlank()) return Result.failure(IllegalArgumentException("Missing secret"))
        return try {
            Totp.check(account)
            Result.success(account)
        } catch (e: IllegalArgumentException) {
            Result.failure(e)
        }
    }

    companion object {
        fun of(account: OtpAccount) = OtpDraft(
            issuer = account.issuer,
            label = account.label,
            secret = account.secret.orEmpty(),
            algorithm = account.algorithm ?: OtpAlgorithm.SHA1,
            digits = account.digits.toString(),
            period = account.period.toString(),
            backupCodes = account.backupCodes,
        )

        /**
         * The fields of an `otpauth://` URI, keeping the backup codes typed so far.
         */
        fun fromUri(uri: String, backupCodes: String): Result<OtpDraft> = try {
            Result.success(of(OtpAuthUri.parse(uri)).copy(backupCodes = backupCodes))
        } catch (e: IllegalArgumentException) {
            Result.failure(e)
        }
    }
}

/**
 * One non-empty line of an import.
 *
 * @property account The account of the line, or `null` if it could not be read.
 * @property error Why the line could not be read. Never contains the line, which may hold a secret.
 * @property duplicate Whether the vault or an earlier line has an account with the same secret already, which is then
 * skipped.
 */
data class ImportLine(
    val lineNumber: Int,
    val account: OtpAccount?,
    val error: String?,
    val duplicate: ImportDuplicate? = null,
)

enum class ImportDuplicate {
    IN_VAULT,
    EARLIER_LINE,
}

/**
 * Read an import: one `otpauth://` URI per line, as written by the Authy extraction scripts and the plain text exports
 * of Aegis, Ente and others. Empty lines and lines starting with `#` are skipped.
 */
fun parseImport(text: String, existing: List<OtpAccount>): List<ImportLine> {
    val inVault = existing.mapNotNullTo(HashSet()) { it.secret }
    val imported = HashSet<String>()
    val lines = mutableListOf<ImportLine>()
    text.lineSequence().forEachIndexed { index, raw ->
        val line = raw.trim()
        if (line.isEmpty() || line.startsWith("#")) return@forEachIndexed
        lines += try {
            val account = OtpAuthUri.parse(line)
            val secret = account.secret.orEmpty()
            val duplicate = when {
                secret in inVault -> ImportDuplicate.IN_VAULT
                !imported.add(secret) -> ImportDuplicate.EARLIER_LINE
                else -> null
            }
            ImportLine(index + 1, account, null, duplicate)
        } catch (e: IllegalArgumentException) {
            ImportLine(index + 1, null, e.message ?: "Invalid line")
        }
    }
    return lines
}
