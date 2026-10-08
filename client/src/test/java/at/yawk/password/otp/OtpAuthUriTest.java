package at.yawk.password.otp;

import at.yawk.password.model.OtpAccount;
import org.testng.Assert;
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
        Assert.assertEquals(OtpAuthUri.parse(OtpAuthUri.format(account)), account);
    }

    @Test
    public void fragmentIgnored() {
        OtpAccount account = OtpAuthUri.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=30#a");
        Assert.assertEquals(account.getSecret(), "JBSWY3DPEHPK3PXP");
    }

    @Test
    public void secretNotInErrors() {
        IllegalArgumentException e = Assert.expectThrows(IllegalArgumentException.class, () -> OtpAuthUri.parse(
                "otpauth://totp?secret=JBSWY3DPEHPK3PXP&image=https://x/y.png"));
        Assert.assertFalse(e.getMessage().toUpperCase().contains("JBSWY3DPEHPK3PXP"), e.getMessage());
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
        String uri = OtpAuthUri.format(account);
        Assert.assertTrue(uri.startsWith("otpauth://totp/B%C3%A4ckerei%3A%20M"), uri);
        Assert.assertEquals(OtpAuthUri.parse(uri), account);
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

    private static void assertRejected(String uri, String message) {
        IllegalArgumentException e = Assert.expectThrows(IllegalArgumentException.class, () -> OtpAuthUri.parse(uri));
        Assert.assertTrue(e.getMessage().contains(message), uri + ": " + e.getMessage());
    }
}
