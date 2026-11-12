package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.OtpBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import at.yawk.password.model.SchemaVersions;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Map;
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
        Assert.assertEquals(BlobCodec.decrypt(OM, KEYS, encrypted, PasswordBlob.class, PasswordBlob.VERSIONS), blob);
        // fresh blob salt and nonce every time
        Assert.assertNotEquals(BlobCodec.encrypt(OM, KEYS, blob), encrypted);
        // version 0 is left out, so that clients that predate versions keep reading it
        String json = new String(OM.writeValueAsBytes(blob), StandardCharsets.UTF_8);
        Assert.assertFalse(json.contains("Version"), json);
    }

    private static final SchemaVersions KNOWN = new SchemaVersions(1, 1);

    private static DecryptedBlob<PasswordBlob> decryptRaw(String json) throws Exception {
        return BlobCodec.decrypt(OM, KEYS, BlobCodec.encrypt(OM, KEYS, rawBlob(json)), PasswordBlob.class, KNOWN);
    }

    @DataProvider
    public Object[][] unknownData() {
        return new Object[][]{
                {"\"future\":{\"x\":[1,2]}", "{\"passwords\":[]}"},
                {"", "{\"passwords\":[],\"future\":true}"},
                {"", "{\"passwords\":[{\"name\":\"a\",\"value\":\"b\",\"future\":1}]}"},
                {"", "{\"passwords\":[],\"passkeys\":[{\"rpId\":\"a\",\"future\":\"x\"}]}"},
        };
    }

    @Test(dataProvider = "unknownData")
    public void testUnknownDataOfKnownVersionIsRefused(String extraTopLevel, String data) {
        // a change that forgot to raise the writer version: refused rather than dropped on the next save
        String json = "{" + (extraTopLevel.isEmpty() ? "" : extraTopLevel + ",") + "\"data\":" + data +
                      ",\"revision\":1,\"minWriterVersion\":1}";
        Assert.expectThrows(UnreadableDatabaseException.class, () -> decryptRaw(json));
    }

    @Test(dataProvider = "unknownData")
    public void testUnknownDataOfNewerWriterVersionIsSkipped(String extraTopLevel, String data) throws Exception {
        String json = "{" + (extraTopLevel.isEmpty() ? "" : extraTopLevel + ",") + "\"data\":" + data +
                      ",\"revision\":1,\"minWriterVersion\":2}";
        DecryptedBlob<PasswordBlob> decrypted = decryptRaw(json);
        Assert.assertEquals(decrypted.getRevision(), 1);
        Assert.assertEquals(decrypted.getMinWriterVersion(), 2);
    }

    @Test
    public void testUnknownEnumValueOfNewerWriterVersion() throws Exception {
        String json = "{\"data\":{\"accounts\":[{\"issuer\":\"a\",\"algorithm\":\"SHA3\"}]},\"revision\":1,";
        Assert.expectThrows(UnreadableDatabaseException.class, () -> BlobCodec.decrypt(
                OM, KEYS, BlobCodec.encrypt(OM, KEYS, rawBlob(json + "\"minWriterVersion\":1}")), OtpBlob.class, KNOWN));
        DecryptedBlob<OtpBlob> decrypted = BlobCodec.decrypt(
                OM, KEYS, BlobCodec.encrypt(OM, KEYS, rawBlob(json + "\"minWriterVersion\":2}")), OtpBlob.class, KNOWN);
        Assert.assertEquals(decrypted.getData().getAccounts().get(0).getIssuer(), "a");
        Assert.assertNull(decrypted.getData().getAccounts().get(0).getAlgorithm());
    }

    @Test
    public void testMinReaderVersion() throws Exception {
        Assert.assertEquals(decryptRaw("{\"data\":{\"passwords\":[]},\"revision\":1,\"minReaderVersion\":1}")
                                    .getMinReaderVersion(), 1);
        // refused also when the writer version is newer, and with data that would be readable
        Assert.expectThrows(UnreadableDatabaseException.class, () -> decryptRaw(
                "{\"data\":{\"passwords\":[]},\"revision\":1,\"minReaderVersion\":2,\"minWriterVersion\":2}"));
    }

    /**
     * A blob that {@link BlobCodec#encrypt} writes as exactly {@code json}.
     */
    @SuppressWarnings("unchecked")
    private static DecryptedBlob<?> rawBlob(String json) throws Exception {
        Map<String, Object> map = OM.readValue(json, Map.class);
        return new DecryptedBlob<Object>() {
            @JsonValue
            Map<String, Object> json() {
                return map;
            }
        };
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
        Exception e = Assert.expectThrows(WrongPasswordException.class, () -> BlobCodec.decrypt(OM, KEYS, encrypted, PasswordBlob.class, PasswordBlob.VERSIONS));
        Assert.assertFalse(e.getMessage().contains("plaintext"));
    }

    @Test
    public void testWrongPassword() throws Exception {
        byte[] encrypted = BlobCodec.encrypt(OM, KEYS, blob(1));
        KeyMaterial other = KeyMaterial.derive("other".getBytes(StandardCharsets.UTF_8), SALT);
        Assert.expectThrows(WrongPasswordException.class, () -> BlobCodec.decrypt(OM, other, encrypted, PasswordBlob.class, PasswordBlob.VERSIONS));
    }

    @Test
    public void testMalformed() throws Exception {
        byte[] encrypted = BlobCodec.encrypt(OM, KEYS, blob(1));

        byte[] version = encrypted.clone();
        version[AuthProtocol.BLOB_MAGIC.length] = 2;
        Exception e = Assert.expectThrows(Exception.class, () -> BlobCodec.decrypt(OM, KEYS, version, PasswordBlob.class, PasswordBlob.VERSIONS));
        Assert.assertTrue(e.getMessage().contains("unsupported version"), e.getMessage());

        byte[] magic = encrypted.clone();
        magic[0] = 'X';
        Assert.assertNull(BlobCodec.installSalt(magic));
        Assert.expectThrows(Exception.class, () -> BlobCodec.decrypt(OM, KEYS, magic, PasswordBlob.class, PasswordBlob.VERSIONS));

        byte[] truncated = java.util.Arrays.copyOf(encrypted, AuthProtocol.BLOB_HEADER_LENGTH + 5);
        Assert.expectThrows(Exception.class, () -> BlobCodec.decrypt(OM, KEYS, truncated, PasswordBlob.class, PasswordBlob.VERSIONS));

        // keys of another registration
        byte[] otherSalt = encrypted.clone();
        otherSalt[AuthProtocol.BLOB_INSTALL_SALT_OFFSET] ^= 1;
        Assert.expectThrows(IllegalArgumentException.class, () -> BlobCodec.decrypt(OM, KEYS, otherSalt, PasswordBlob.class, PasswordBlob.VERSIONS));
    }
}
