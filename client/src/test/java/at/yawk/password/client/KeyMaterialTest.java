package at.yawk.password.client;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Pins the key derivation. The expected values come from independent implementations: the {@code argon2} CLI of
 * libargon2 ({@code printf password | argon2 <salt> -id -m 16 -t 4 -p 4 -l 32 -r}) and {@code openssl kdf HKDF} /
 * {@code openssl pkeyutl} for the rest. Changing them locks every user out, so this needs a new protocol version.
 */
public class KeyMaterialTest {
    /**
     * 32 ASCII zeros, as passed to the argon2 CLI.
     */
    static final byte[] SALT = "00000000000000000000000000000000".getBytes(StandardCharsets.US_ASCII);
    static final byte[] PASSWORD = "password".getBytes(StandardCharsets.UTF_8);

    private static final KeyMaterial KEYS = KeyMaterial.derive(PASSWORD, SALT);

    @Test
    public void publicKey() {
        // argon2id -> 992966328d1e9754d7349d795a9952ad811fbe51da7d344c4131abe7a479b89c
        //   -> HKDF (info at.yawk.password/v1/auth) -> Ed25519 seed d3324e23aa3379e801a1b2f2bdba2112210dfc4343bcad23b07fe0e6fafe91ab
        Assert.assertEquals(HexFormat.of().formatHex(KEYS.getPublicKey()),
                            "7c9d3f177b79c1cb0310b940a0a790df08eb95c70c24451066e374c987f315ae");
    }

    @Test
    public void signature() {
        // Ed25519 is deterministic
        Assert.assertEquals(HexFormat.of().formatHex(KEYS.sign("hello".getBytes(StandardCharsets.US_ASCII))),
                            "b041a31fdff0db3ae6ccafe3af276d31e15aad404f46cec09d11e0a0e73144bd" +
                            "8a86cb093c3f56407d3553e21e4c17a13cb45ba116f11bfbeece0bdc2830a304");
    }

    @Test
    public void containerKey() {
        byte[] blobSalt = new byte[32];
        Arrays.fill(blobSalt, (byte) 0x11);
        Assert.assertEquals(HexFormat.of().formatHex(KEYS.containerKey(blobSalt)),
                            "b04094e988db1e61354d27da74734dd1e3474dc6245e72550636895250fbd44d");
    }

    @Test
    public void rejectsBadSalt() {
        Assert.assertThrows(IllegalArgumentException.class, () -> KeyMaterial.derive(PASSWORD, new byte[16]));
    }
}
