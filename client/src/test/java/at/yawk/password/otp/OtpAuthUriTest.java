package at.yawk.password.otp;

import at.yawk.password.model.OtpAccount;
import at.yawk.password.model.OtpAlgorithm;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class OtpAuthUriTest {
    @Test
    public void googleExample() {
        OtpAccount account = OtpAuthUri.parse(
                "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");
        Assert.assertEquals(account.getIssuer(), "Example");
        Assert.assertEquals(account.getLabel(), "alice@google.com");
        Assert.assertEquals(account.getSecret(), "JBSWY3DPEHPK3PXP");
        Assert.assertEquals(account.getAlgorithm(), OtpAlgorithm.SHA1);
        Assert.assertEquals(account.getDigits(), 6);
        Assert.assertEquals(account.getPeriod(), 30);
    }

    @Test
    public void allParameters() {
        OtpAccount account = OtpAuthUri.parse(
                "OTPAUTH://TOTP/ACME%20Co%3A%20john.doe%40email.com?secret=hxdm%20vjec&issuer=ACME+Co" +
                "&algorithm=sha512&digits=8&period=60&image=https%3A%2F%2Fexample.com%2Fx.png");
        Assert.assertEquals(account.getIssuer(), "ACME Co");
        Assert.assertEquals(account.getLabel(), "john.doe@email.com");
        Assert.assertEquals(account.getSecret(), "HXDMVJEC");
        Assert.assertEquals(account.getAlgorithm(), OtpAlgorithm.SHA512);
        Assert.assertEquals(account.getDigits(), 8);
        Assert.assertEquals(account.getPeriod(), 60);
    }

    @Test
    public void issuerFromLabelOnly() {
        OtpAccount account = OtpAuthUri.parse("otpauth://totp/GitHub:yawkat?secret=JBSWY3DPEHPK3PXP");
        Assert.assertEquals(account.getIssuer(), "GitHub");
        Assert.assertEquals(account.getLabel(), "yawkat");
    }

    @Test
    public void noIssuer() {
        OtpAccount account = OtpAuthUri.parse("otpauth://totp/yawkat?secret=JBSWY3DPEHPK3PXP");
        Assert.assertEquals(account.getIssuer(), "");
        Assert.assertEquals(account.getLabel(), "yawkat");
    }

    @Test
    public void issuerWithColon() {
        OtpAccount account = OtpAuthUri.parse("otpauth://totp/a%3Ab:me?secret=JBSWY3DPEHPK3PXP&issuer=a%3Ab");
        Assert.assertEquals(account.getIssuer(), "a:b");
        Assert.assertEquals(account.getLabel(), "me");
    }

    @Test
    public void emptyIssuerKeepsLabel() {
        OtpAccount account = OtpAuthUri.parse("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=");
        Assert.assertEquals(account.getIssuer(), "");
        Assert.assertEquals(account.getLabel(), "GitHub:me");
    }

    @Test
    public void colonInLabelRoundTrip() {
        OtpAccount account = new OtpAccount();
        account.setLabel("work:me");
        account.setSecret("JBSWY3DPEHPK3PXP");
        assertRoundTrip(account);
    }

    @Test
    public void hashIsNotAFragment() {
        // the parameters after the '#' must not be dropped
        OtpAccount account = OtpAuthUri.parse(
                "otpauth://totp/Foo:bar?secret=JBSWY3DPEHPK3PXP&issuer=Foo#1&algorithm=SHA256&period=60");
        Assert.assertEquals(account.getIssuer(), "Foo#1");
        Assert.assertEquals(account.getAlgorithm(), OtpAlgorithm.SHA256);
        Assert.assertEquals(account.getPeriod(), 60);
        assertRejected("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=30#a", "Invalid period");
        assertRejected("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP#", "Base32");
    }

    @Test
    public void whitespace() {
        OtpAccount account = OtpAuthUri.parse("otpauth://totp/GitHub%20:%20me%20?secret=JBSWY3DPEHPK3PXP&issuer=GitHub+");
        Assert.assertEquals(account.getIssuer(), "GitHub");
        Assert.assertEquals(account.getLabel(), "me");
        account.setLabel(" me");
        assertRoundTrip(account);
    }

    @Test
    public void nonCanonicalSecret() {
        // random Base32 characters, with unused bits that are not zero (pyotp random_base32 and others)
        OtpAccount account = OtpAuthUri.parse("otpauth://totp/x?secret=jbswy3dpehpk3pxpjbswy3dpeh");
        Assert.assertEquals(account.getSecret(), "JBSWY3DPEHPK3PXPJBSWY3DPEE");
    }

    @Test
    public void invalidEncodings() {
        assertRejected("otpauth://totp/B%E4ckerei?secret=JBSWY3DPEHPK3PXP", "UTF-8");
        Assert.assertEquals(OtpAuthUri.parse("otpauth://totp/a\uD83D%41b?secret=JBSWY3DPEHPK3PXP").getLabel(),
                            "a\uD83DAb");
        assertRejected("otpauth://totp/\uD800%f?secret=JBSWY3DPEHPK3PXP", "percent");
    }

    @DataProvider
    public Object[][] leakyUris() {
        return new Object[][]{
                {"otpauth://totp?secret=JBSWY3DPEHPK3PXP&image=https://x/y.png"},
                {"otpauth://totp/x?algorithm=SHA1secret=JBSWY3DPEHPK3PXP"},
                {"otpauth://totp/x?period=30secret=JBSWY3DPEHPK3PXP"},
                {"otpauth://totp/x?digits=6secret=JBSWY3DPEHPK3PXP"},
                {"otpauth://totp/x?algorithm=SHA1;secret=JBSWY3DPEHPK3PXP"},
                {"otpauth://totp/x?period=30otpauth://totp/y?secret=JBSWY3DPEHPK3PXP"},
                {"otpauth://JBSWY3DPEHPK3PXP/x?secret=JBSWY3DPEHPK3PXP"},
                {"otpauth://totp/x?JBSWY3DPEHPK3PXP&JBSWY3DPEHPK3PXP&secret=A"},
        };
    }

    @Test(dataProvider = "leakyUris")
    public void secretNotInErrors(String uri) {
        IllegalArgumentException e = Assert.expectThrows(IllegalArgumentException.class, () -> OtpAuthUri.parse(uri));
        Assert.assertFalse(e.getMessage().toUpperCase().contains("JBSWY3DP"), e.getMessage());
    }

    @Test
    public void mangledSeparators() {
        assertRejected("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&amp;digits=8&amp;period=60", "';'");
        assertRejected("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=Foo;digits=8;period=60", "';'");
    }

    @Test
    public void authyToken() {
        OtpAccount account = OtpAuthUri.parse(
                "otpauth://totp/Cloudflare:me?secret=JBSWY3DPEHPK3PXP&digits=7&period=10");
        Assert.assertEquals(Totp.code(account, 1_700_000_000_000L), "7876561");
    }

    @Test
    public void roundTrip() {
        OtpAccount account = new OtpAccount();
        account.setIssuer("Bäckerei: Müller & Söhne");
        account.setLabel("me+test@example.com");
        account.setSecret("JBSWY3DPEHPK3PXP");
        account.setAlgorithm(OtpAlgorithm.SHA256);
        account.setDigits(7);
        account.setPeriod(10);
        Assert.assertTrue(OtpAuthUri.format(account).startsWith("otpauth://totp/B%C3%A4ckerei%3A%20M"));
        assertRoundTrip(account);
    }

    @Test
    public void formatLeavesOutDefaults() {
        OtpAccount account = new OtpAccount();
        account.setLabel("me");
        account.setSecret("JBSWY3DPEHPK3PXP");
        Assert.assertEquals(OtpAuthUri.format(account), "otpauth://totp/me?secret=JBSWY3DPEHPK3PXP");
    }

    @Test
    public void rejectsUnsupported() {
        assertRejected("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "Unsupported type hotp");
        assertRejected("otpauth://steam/x?secret=JBSWY3DPEHPK3PXP", "Unsupported type steam");
        assertRejected("otpauth://totp/Steam:x?secret=JBSWY3DPEHPK3PXP&encoder=steam", "Steam");
        assertRejected("otpauth-migration://offline?data=abc", "Google Authenticator");
        assertRejected("https://example.com", "Not an otpauth");
        assertRejected("otpauth://totp/x", "Missing secret");
        assertRejected("otpauth://totp/x?secret=", "Missing secret");
        assertRejected("otpauth://totp/x?secret=JBSWY3DP1", "Base32");
        assertRejected("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "Unsupported algorithm");
        assertRejected("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=x", "Invalid digits");
        assertRejected("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4", "digits");
        assertRejected("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0", "period");
        assertRejected("otpauth://totp/x?secret=A&secret=B", "Duplicate");
        assertRejected("otpauth://totp/x%G1?secret=JBSWY3DPEHPK3PXP", "percent");
    }

    private static void assertRoundTrip(OtpAccount account) {
        OtpAccount parsed = OtpAuthUri.parse(OtpAuthUri.format(account));
        parsed.setId(account.getId());
        Assert.assertEquals(parsed, account);
    }

    private static void assertRejected(String uri, String message) {
        IllegalArgumentException e = Assert.expectThrows(IllegalArgumentException.class, () -> OtpAuthUri.parse(uri));
        Assert.assertTrue(e.getMessage().contains(message), uri + ": " + e.getMessage());
    }
}
