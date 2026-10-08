package at.yawk.password.otp;

import at.yawk.password.model.OtpAccount;
import java.nio.charset.StandardCharsets;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TotpTest {
    private static final byte[] SEED_SHA1 = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SEED_SHA256 = "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SEED_SHA512 =
            "1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.US_ASCII);

    @DataProvider
    public Object[][] rfc6238() {
        // RFC 6238, appendix B: 8 digits, 30 s
        return new Object[][]{
                {59L, "94287082", "46119246", "90693936"},
                {1111111109L, "07081804", "68084774", "25091201"},
                {1111111111L, "14050471", "67062674", "99943326"},
                {1234567890L, "89005924", "91819424", "93441116"},
                {2000000000L, "69279037", "90698825", "38618901"},
                {20000000000L, "65353130", "77737706", "47863826"},
        };
    }

    @Test(dataProvider = "rfc6238")
    public void vectors(long time, String sha1, String sha256, String sha512) {
        Assert.assertEquals(Totp.code(SEED_SHA1, OtpAlgorithm.SHA1, 8, 30, time), sha1);
        Assert.assertEquals(Totp.code(SEED_SHA256, OtpAlgorithm.SHA256, 8, 30, time), sha256);
        Assert.assertEquals(Totp.code(SEED_SHA512, OtpAlgorithm.SHA512, 8, 30, time), sha512);
    }

    /**
     * Expected values from Python's hmac module.
     */
    @Test
    public void account() {
        OtpAccount account = new OtpAccount();
        account.setSecret("JBSWY3DPEHPK3PXP");
        Assert.assertEquals(Totp.code(account, 1_700_000_000_000L), "324550");
        account.setDigits(10);
        Assert.assertEquals(Totp.code(account, 1_700_000_000_000L), "1802324550");
    }

    /**
     * The parameters of Authy's own tokens (e.g. Cloudflare): 7 digits, 10 s.
     */
    @Test
    public void authyParameters() {
        OtpAccount account = new OtpAccount();
        account.setSecret("JBSWY3DPEHPK3PXP");
        account.setDigits(7);
        account.setPeriod(10);
        Assert.assertEquals(Totp.code(account, 1_700_000_000_000L), "7876561");
        Assert.assertEquals(Totp.code(account, 1_700_000_009_999L), "7876561");
        Assert.assertEquals(Totp.code(account, 1_700_000_010_000L), "1067631");
        Assert.assertEquals(Totp.millisUntilNext(account, 1_700_000_003_000L), 7_000);
        Assert.assertEquals(Totp.millisUntilNext(account, 1_700_000_000_000L), 10_000);
    }

    @Test
    public void rejectsInvalidAccounts() {
        OtpAccount account = new OtpAccount();
        Assert.assertThrows(IllegalArgumentException.class, () -> Totp.code(account, 0));
        account.setSecret("JBSWY3DPEHPK3PXP");
        account.setDigits(5);
        Assert.assertThrows(IllegalArgumentException.class, () -> Totp.code(account, 0));
        account.setDigits(11);
        Assert.assertThrows(IllegalArgumentException.class, () -> Totp.code(account, 0));
        account.setDigits(6);
        account.setPeriod(0);
        Assert.assertThrows(IllegalArgumentException.class, () -> Totp.code(account, 0));
        account.setPeriod(30);
        account.setType("hotp");
        Assert.assertThrows(IllegalArgumentException.class, () -> Totp.code(account, 0));
    }
}
