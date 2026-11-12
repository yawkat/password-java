package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.OtpBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import at.yawk.password.model.SchemaVersions;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
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
        Assert.assertEquals(BlobCodec.decrypt(OM, KEYS, encrypted, PasswordBlob.class, PasswordBlob.VERSIONS), blob);
        // fresh blob salt and nonce every time
        Assert.assertNotEquals(BlobCodec.encrypt(OM, KEYS, blob), encrypted);
        // the versions are in the header, not in the JSON
        blob.setMinReaderVersion(3);
        blob.setMinWriterVersion(4);
        String json = new String(OM.writeValueAsBytes(blob), StandardCharsets.UTF_8);
        Assert.assertFalse(json.contains("Version"), json);
        DecryptedBlob<PasswordBlob> decrypted =
                BlobCodec.decrypt(OM, KEYS, BlobCodec.encrypt(OM, KEYS, blob), PasswordBlob.class, KNOWN_NEWER);
        Assert.assertEquals(decrypted, blob);
    }

    private static final SchemaVersions KNOWN = new SchemaVersions(1, 1);
    private static final SchemaVersions KNOWN_NEWER = new SchemaVersions(3, 4);

    private static byte[] payload(int reader, int writer, String json) {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(5 + bytes.length)
                .put(BlobCodec.VERSIONS_MARKER).putShort((short) reader).putShort((short) writer).put(bytes).array();
    }

    private static <T> DecryptedBlob<T> decryptPayload(byte[] payload, Class<T> dataClass) throws Exception {
        return BlobCodec.decrypt(OM, KEYS, BlobCodec.encryptPayload(KEYS, payload), dataClass, KNOWN);
    }

    @Test
    public void testPayloadWithoutHeader() throws Exception {
        // written before the header existed: versions 0 and 0
        DecryptedBlob<PasswordBlob> decrypted = decryptPayload(
                "{\"data\":{\"passwords\":[{\"name\":\"a\",\"value\":\"b\"}]},\"revision\":3}"
                        .getBytes(StandardCharsets.UTF_8), PasswordBlob.class);
        Assert.assertEquals(decrypted, blob(3, "a", "b"));
        Assert.assertEquals(decrypted.getMinWriterVersion(), 0);
    }

    @Test
    public void testUnknownPayloadFormat() {
        Assert.expectThrows(UnreadableDatabaseException.class,
                            () -> decryptPayload(new byte[]{2, 0, 0, 0, 0, '{', '}'}, PasswordBlob.class));
        Assert.expectThrows(UnreadableDatabaseException.class,
                            () -> decryptPayload(new byte[0], PasswordBlob.class));
    }

    @DataProvider
    public Object[][] unknownData() {
        return new Object[][]{
                {"{\"future\":{\"x\":[1,2]},\"data\":{\"passwords\":[]},\"revision\":1}"},
                {"{\"data\":{\"passwords\":[],\"future\":true},\"revision\":1}"},
                {"{\"data\":{\"passwords\":[{\"name\":\"a\",\"value\":\"b\",\"future\":1}]},\"revision\":1}"},
                {"{\"data\":{\"passwords\":[],\"passkeys\":[{\"rpId\":\"a\",\"future\":\"x\"}]},\"revision\":1}"},
        };
    }

    @Test(dataProvider = "unknownData")
    public void testUnknownDataOfKnownVersionIsRefused(String json) {
        // a change that forgot to raise the writer version: refused rather than dropped on the next save
        Assert.expectThrows(UnreadableDatabaseException.class,
                            () -> decryptPayload(payload(1, 1, json), PasswordBlob.class));
    }

    @Test(dataProvider = "unknownData")
    public void testUnknownDataOfNewerWriterVersionIsSkipped(String json) throws Exception {
        DecryptedBlob<PasswordBlob> decrypted = decryptPayload(payload(1, 2, json), PasswordBlob.class);
        Assert.assertEquals(decrypted.getRevision(), 1);
        Assert.assertEquals(decrypted.getMinWriterVersion(), 2);
        Assert.assertTrue(BlobCodec.isNewerWriter(decrypted.getMinWriterVersion(), KNOWN));
    }

    @Test
    public void testUnknownEnumValueOfNewerWriterVersion() throws Exception {
        String json = "{\"data\":{\"accounts\":[{\"issuer\":\"a\",\"algorithm\":\"SHA3\"}]},\"revision\":1}";
        Assert.expectThrows(UnreadableDatabaseException.class, () -> decryptPayload(payload(1, 1, json), OtpBlob.class));
        DecryptedBlob<OtpBlob> decrypted = decryptPayload(payload(1, 2, json), OtpBlob.class);
        Assert.assertEquals(decrypted.getData().getAccounts().get(0).getIssuer(), "a");
        Assert.assertNull(decrypted.getData().getAccounts().get(0).getAlgorithm());
    }

    @Test
    public void testMinReaderVersion() throws Exception {
        String json = "{\"data\":{\"passwords\":[]},\"revision\":1}";
        Assert.assertEquals(decryptPayload(payload(1, 1, json), PasswordBlob.class).getMinReaderVersion(), 1);
        // refused also when the writer version is newer, and with data that would be readable
        Assert.expectThrows(UnreadableDatabaseException.class, () -> decryptPayload(payload(2, 2, json), PasswordBlob.class));
        // unsigned
        Assert.expectThrows(UnreadableDatabaseException.class,
                            () -> decryptPayload(payload(0xffff, 0, json), PasswordBlob.class));
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
