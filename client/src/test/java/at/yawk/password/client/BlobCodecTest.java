package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class BlobCodecTest {
    private static final ObjectMapper OM = new ObjectMapper();
    private static final byte[] SALT = HashUtil.generateRandomBytes(AuthProtocol.SALT_LENGTH);
    private static final KeyMaterial KEYS = KeyMaterial.derive("password".getBytes(StandardCharsets.UTF_8), SALT);

    static DecryptedBlob<PasswordBlob> blob(long revision, String... namesAndValues) {
        PasswordBlob data = new PasswordBlob();
        for (int i = 0; i < namesAndValues.length; i += 2) {
            PasswordEntry entry = new PasswordEntry();
            entry.setName(namesAndValues[i]);
            entry.setValue(namesAndValues[i + 1]);
            data.getPasswords().add(entry);
        }
        DecryptedBlob<PasswordBlob> blob = new DecryptedBlob<>();
        blob.setData(data);
        blob.setRevision(revision);
        return blob;
    }

    @Test
    public void testRoundTrip() throws Exception {
        DecryptedBlob<PasswordBlob> blob = blob(7, "name", "password 1234567891u9u0oshsbv", "Bänk 🔑", "pässwörd€\t\u0001");
        byte[] encrypted = BlobCodec.encrypt(OM, KEYS, blob);
        Assert.assertEquals(BlobCodec.installSalt(encrypted), SALT);
        Assert.assertEquals(BlobCodec.decrypt(OM, KEYS, encrypted, PasswordBlob.class), blob);
        // fresh blob salt and nonce every time
        Assert.assertNotEquals(BlobCodec.encrypt(OM, KEYS, blob), encrypted);
    }

    @Test
    public void testPadding() throws Exception {
        int overhead = AuthProtocol.BLOB_HEADER_LENGTH + 16;
        Assert.assertEquals(BlobCodec.encrypt(OM, KEYS, blob(0)).length, overhead + BlobCodec.PADDING);
        Assert.assertEquals(BlobCodec.encrypt(OM, KEYS, blob(0, "a", "x".repeat(3000))).length,
                            overhead + BlobCodec.PADDING);
        Assert.assertEquals(BlobCodec.encrypt(OM, KEYS, blob(0, "a", "x".repeat(5000))).length,
                            overhead + 2 * BlobCodec.PADDING);
    }

    @DataProvider
    public Object[][] tamperedOffsets() {
        return new Object[][]{
                // blob salt (other key), nonce, and the associated data covers the rest of the header too
                { AuthProtocol.BLOB_INSTALL_SALT_OFFSET + AuthProtocol.SALT_LENGTH },
                { AuthProtocol.BLOB_HEADER_LENGTH - 1 },
                // ciphertext, tag
                { AuthProtocol.BLOB_HEADER_LENGTH },
                { -1 },
        };
    }

    @Test(dataProvider = "tamperedOffsets")
    public void testTamperedDoesNotDecrypt(int offset) throws Exception {
        byte[] encrypted = BlobCodec.encrypt(OM, KEYS, blob(1, "secret", "plaintext"));
        encrypted[offset < 0 ? encrypted.length + offset : offset] ^= 1;
        Exception e = Assert.expectThrows(WrongPasswordException.class, () -> BlobCodec.decrypt(OM, KEYS, encrypted, PasswordBlob.class));
        Assert.assertFalse(e.getMessage().contains("plaintext"));
    }

    @Test
    public void testWrongPassword() throws Exception {
        byte[] encrypted = BlobCodec.encrypt(OM, KEYS, blob(1));
        KeyMaterial other = KeyMaterial.derive("other".getBytes(StandardCharsets.UTF_8), SALT);
        Assert.expectThrows(WrongPasswordException.class, () -> BlobCodec.decrypt(OM, other, encrypted, PasswordBlob.class));
    }

    @Test
    public void testMalformed() throws Exception {
        byte[] encrypted = BlobCodec.encrypt(OM, KEYS, blob(1));

        byte[] version = encrypted.clone();
        version[AuthProtocol.BLOB_MAGIC.length] = 2;
        Exception e = Assert.expectThrows(Exception.class, () -> BlobCodec.decrypt(OM, KEYS, version, PasswordBlob.class));
        Assert.assertTrue(e.getMessage().contains("unsupported version"), e.getMessage());

        byte[] magic = encrypted.clone();
        magic[0] = 'X';
        Assert.assertNull(BlobCodec.installSalt(magic));
        Assert.expectThrows(Exception.class, () -> BlobCodec.decrypt(OM, KEYS, magic, PasswordBlob.class));

        byte[] truncated = java.util.Arrays.copyOf(encrypted, AuthProtocol.BLOB_HEADER_LENGTH + 5);
        Assert.expectThrows(Exception.class, () -> BlobCodec.decrypt(OM, KEYS, truncated, PasswordBlob.class));

        // keys of another registration
        byte[] otherSalt = encrypted.clone();
        otherSalt[AuthProtocol.BLOB_INSTALL_SALT_OFFSET] ^= 1;
        Assert.expectThrows(IllegalArgumentException.class, () -> BlobCodec.decrypt(OM, KEYS, otherSalt, PasswordBlob.class));
    }
}
