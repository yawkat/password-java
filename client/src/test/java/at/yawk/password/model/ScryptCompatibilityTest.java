package at.yawk.password.model;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Pins the scrypt output so that existing databases stay decryptable across scrypt implementation changes.
 *
 * <p>The container vectors were generated with {@code com.lambdaworks:scrypt:1.4.0}
 * ({@code SCrypt.scrypt(passwd, salt, 1 << 16, 8, 1, 32)}, the parameters of the default container key in
 * {@code AesCodec}). For every non-empty password the native and the pure-Java ({@code SCrypt.scryptJ}) lambdaworks
 * implementations produced the same output. For the empty password only the native implementation could be used,
 * because {@code scryptJ} rejects an empty key.
 */
public class ScryptCompatibilityTest {
    private static final HexFormat HEX = HexFormat.of();

    private static final String SALT_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private static final String SALT_B = "8f3a1c55e2d07b946a21f0c3b5e8d49127ac6e03f59b1d8840c7e26a3b9f5d12";

    @DataProvider
    public Object[][] containerVectors() {
        return new Object[][]{
                {"", SALT_A, "82ca78749f24524d967d8be4261b258a647074d33325ebbf1dbd93825e9dc276"},
                {"", SALT_B, "8436017980a512bc6422e3ae5f826c3bcbb87780ebd156f08b0b8d0e16262e62"},
                {"password", SALT_A, "696fdb19d55e59b19a92dcfd4e3a9dc0418d3b50337b0c7c13ae55f5d8f2c0c5"},
                {"password", SALT_B, "c57bf2d941571c76f9fb8b701125dd6b38a6676b35f3986e6273922f1e6adcd4"},
                {"correct horse battery staple", SALT_A,
                        "fbb18fb6dc3deed09c2a8817bc9a0b6eca463706581f70ff5e47b8f2cf4a51e6"},
                {"correct horse battery staple", SALT_B,
                        "a829ac304f3b3633cb823529f0a28fb4a7605c4b9ff5d9e7232da6c339539b6b"},
                {"pässwörd ☃ 🔑", SALT_A,
                        "ce8fb377c629beb8ed48a45dd4fa5004525ee9112b4298a82b23f6b88d385a35"},
                {"pässwörd ☃ 🔑", SALT_B,
                        "118566caebcf424a50951bfa1cff1576059e6343ac2f4f12b9255287dc8876b7"},
        };
    }

    @Test(dataProvider = "containerVectors")
    public void containerKey(String password, String salt, String expected) {
        // same encoding as the gui unlock dialog
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        ScryptParameters params = new ScryptParameters(16, 8, 1, 32, HEX.parseHex(salt));
        Assert.assertEquals(HEX.formatHex(params.runScrypt(passwordBytes)), expected);
    }

    @Test
    public void utf8PasswordBytes() {
        Assert.assertEquals(
                HEX.formatHex("pässwörd ☃ 🔑".getBytes(StandardCharsets.UTF_8)),
                "70c3a4737377c3b6726420e2988320f09f9491");
    }

    /**
     * RFC 7914 section 12 test vectors. The last one (N=2^20) is omitted because it needs 1 GiB of memory.
     */
    @DataProvider
    public Object[][] rfc7914Vectors() {
        return new Object[][]{
                {"", "", 4, 1, 1,
                        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                        + "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"},
                {"password", "NaCl", 10, 8, 16,
                        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                        + "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"},
                {"pleaseletmein", "SodiumChloride", 14, 8, 1,
                        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
                        + "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"},
        };
    }

    @Test(dataProvider = "rfc7914Vectors")
    public void rfc7914(String password, String salt, int expN, int r, int p, String expected) {
        ScryptParameters params = new ScryptParameters(expN, r, p, 64, salt.getBytes(StandardCharsets.US_ASCII));
        Assert.assertEquals(HEX.formatHex(params.runScrypt(password.getBytes(StandardCharsets.US_ASCII))), expected);
    }
}
