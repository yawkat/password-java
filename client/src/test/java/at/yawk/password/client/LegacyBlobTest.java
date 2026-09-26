package at.yawk.password.client;

import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.PasswordEntry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * The migration reads databases of the old format.
 */
public class LegacyBlobTest {
    static final byte[] PASSWORD = "fixture-password".getBytes(StandardCharsets.UTF_8);

    /**
     * Written by the old AesCodec with Jackson 3.2.3, password "fixture-password".
     */
    static byte[] fixture() throws Exception {
        try (InputStream in = LegacyBlobTest.class.getResourceAsStream("jackson3-db.bin")) {
            return in.readAllBytes();
        }
    }

    @Test
    public void readsFixture() throws Exception {
        byte[] bytes = fixture();
        Assert.assertTrue(LegacyBlob.isLegacy(bytes));
        Assert.assertNull(BlobCodec.installSalt(bytes));
        DecryptedBlob decrypted = LegacyBlob.decrypt(new ObjectMapper(), PASSWORD, bytes);

        Assert.assertEquals(decrypted.getRevision(), 0);
        List<PasswordEntry> entries = decrypted.getData().getPasswords();
        Assert.assertEquals(entries.size(), 3);
        Assert.assertEquals(entries.get(0).getName(), "example.com");
        Assert.assertEquals(entries.get(0).getValue(), "hunter2\nuser@example.com\nnotes: \"quoted\", \\backslash\\");
        Assert.assertEquals(entries.get(1).getName(), "Bänk 🔑");
        Assert.assertEquals(entries.get(1).getValue(), "pässwörd€\t\u0001");
        Assert.assertEquals(entries.get(2).getName(), "empty");
        Assert.assertEquals(entries.get(2).getValue(), "");
    }

    @Test
    public void wrongPassword() throws Exception {
        Assert.expectThrows(WrongPasswordException.class,
                            () -> LegacyBlob.decrypt(new ObjectMapper(), "wrong".getBytes(), fixture()));
    }

    @Test
    public void rejectsOtherParameters() throws Exception {
        // expN, r, p, dkLen, salt length: anything but the defaults would let a crafted blob choose the work
        for (int field = 0; field < 5; field++) {
            byte[] bytes = fixture();
            ByteBuffer.wrap(bytes).putInt(field * 4, 20);
            Assert.assertFalse(LegacyBlob.isLegacy(bytes));
            Assert.expectThrows(Exception.class, () -> LegacyBlob.decrypt(new ObjectMapper(), PASSWORD, bytes));
        }
        // body length
        byte[] bytes = fixture();
        ByteBuffer.wrap(bytes).putInt(4 * 5 + 32 + 16, Integer.MAX_VALUE);
        Exception e = Assert.expectThrows(Exception.class,
                                          () -> LegacyBlob.decrypt(new ObjectMapper(), PASSWORD, bytes));
        Assert.assertTrue(e.getMessage().contains("bad length"), e.getMessage());
    }
}
