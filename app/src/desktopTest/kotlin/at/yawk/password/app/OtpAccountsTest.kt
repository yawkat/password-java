package at.yawk.password.app

import at.yawk.password.model.OtpAccount
import at.yawk.password.model.OtpAlgorithm
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OtpAccountsTest {
    private fun account(issuer: String, label: String = "", secret: String = "JBSWY3DPEHPK3PXP") = OtpAccount().apply {
        this.issuer = issuer
        this.label = label
        this.secret = secret
    }

    @Test
    fun import() {
        val existing = listOf(account("GitHub", secret = "GEZDGNBVGY3TQOJQ"))
        val lines = parseImport(
            """
            # exported from Authy
            otpauth://totp/GitHub:me?secret=GEZDGNBVGY3TQOJQ

            otpauth://totp/Cloudflare:me?secret=JBSWY3DPEHPK3PXP&digits=7&period=10
            otpauth://totp/Again?secret=jbsw y3dp ehpk 3pxp
            otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP
            not a uri JBSWY3DPEHPK3PXP
            """.trimIndent(),
            existing,
        )
        assertEquals(listOf(2, 4, 5, 6, 7), lines.map { it.lineNumber })
        assertEquals(ImportDuplicate.IN_VAULT, lines[0].duplicate)
        assertEquals("Cloudflare", lines[1].account?.issuer)
        assertEquals(7, lines[1].account?.digits)
        assertNull(lines[1].duplicate)
        // the same secret as an earlier line, in another spelling
        assertEquals(ImportDuplicate.EARLIER_LINE, lines[2].duplicate)
        assertNull(lines[3].account)
        assertTrue(lines[3].error!!.contains("hotp"))
        // errors never repeat the line, which may hold a secret
        assertFalse(lines[4].error!!.contains("JBSW"))
    }

    @Test
    fun filterAndSort() {
        val accounts = listOf(account("github", "b"), account("Amazon"), account("GitHub", "a"), account("", "zed"))
        assertEquals(
            listOf("Amazon", "GitHub", "github", "zed"),
            filterAccounts(accounts, "").map(::accountTitle),
        )
        assertEquals(listOf("a", "b"), filterAccounts(accounts, "HUB").map { it.label })
        assertEquals(listOf("zed"), filterAccounts(accounts, "ze").map { it.label })
    }

    @Test
    fun formatting() {
        assertEquals("123 456", formatCode("123456"))
        assertEquals("123 4567", formatCode("1234567"))
        assertEquals("1234 5678", formatCode("12345678"))
        assertEquals("(unnamed)", accountTitle(account("")))
        assertEquals("G", avatarLetter(account("github")))
        assertEquals("?", avatarLetter(account("")))
        assertEquals(avatarHue(account("GitHub")), avatarHue(account("github")))
        assertNull(codeOrNull(account("x", secret = "not base32!"), 0))
    }

    @Test
    fun copyNextCodeShortlyBeforeExpiry() {
        val account = account("x")
        assertEquals(codeOrNull(account, 0)!! to false, codeToCopy(account, 0))
        assertEquals(codeOrNull(account, 0)!! to false, codeToCopy(account, 30_000 - COPY_NEXT_CODE_MS))
        assertEquals(codeOrNull(account, 30_000)!! to true, codeToCopy(account, 30_000 - COPY_NEXT_CODE_MS + 1))
        assertNull(codeToCopy(account("x", secret = "not base32!"), 0))
    }

    @Test
    fun draft() {
        val draft = OtpDraft(issuer = "GitHub", label = "me", secret = "jbsw y3dp ehpk 3pxp", digits = "7", period = "10")
        val account = draft.toAccount("some-id").getOrThrow()
        assertEquals("some-id", account.id)
        assertEquals("JBSWY3DPEHPK3PXP", account.secret)
        assertEquals(7, account.digits)
        assertEquals(draft.copy(secret = "JBSWY3DPEHPK3PXP"), OtpDraft.of(account))

        assertEquals("Missing secret", OtpDraft(issuer = "x").toAccount(null).exceptionOrNull()?.message)
        assertEquals("Invalid period", draft.copy(period = "x").toAccount(null).exceptionOrNull()?.message)
        assertTrue(draft.copy(digits = "4").toAccount(null).isFailure)
        assertTrue(draft.copy(secret = "1").toAccount(null).isFailure)
        assertFalse(draft.toString().contains("JBSW", ignoreCase = true))

        val fromUri = OtpDraft.fromUri(
            "otpauth://totp/ACME:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256",
            backupCodes = "kept",
        ).getOrThrow()
        assertEquals("ACME", fromUri.issuer)
        assertEquals(OtpAlgorithm.SHA256, fromUri.algorithm)
        assertEquals("kept", fromUri.backupCodes)
        assertTrue(OtpDraft.fromUri("otpauth://hotp/x?secret=A", "").isFailure)
    }
}
