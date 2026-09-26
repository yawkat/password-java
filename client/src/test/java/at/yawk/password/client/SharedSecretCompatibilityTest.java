package at.yawk.password.client;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Pins the shared secret sent to the server, so that existing server registrations keep working.
 *
 * <p>Generated with {@code com.lambdaworks:scrypt:1.4.0}:
 * {@code SCrypt.scrypt(passwd, "CuRdXw06VaLQhV9K".getBytes(), 1 << 14, 8, 1, 8)}. For every non-empty password the
 * native and pure-Java lambdaworks implementations agreed; the empty password could only be computed natively.
 */
public class SharedSecretCompatibilityTest {
    @DataProvider
    public Object[][] vectors() {
        return new Object[][]{
                {"", "9a993936bdab3d6f"},
                {"password", "7bf4b9aadb1057dc"},
                {"correct horse battery staple", "c689fe51c07c3766"},
                {"pässwörd ☃ 🔑", "7d14a4b2c99b0a19"},
        };
    }

    @Test(dataProvider = "vectors")
    public void sharedSecret(String password, String expected) {
        // same encoding as the gui unlock dialog
        byte[] secret = PasswordClient.deriveSharedSecret(password.getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals(HexFormat.of().formatHex(secret), expected);
    }
}
