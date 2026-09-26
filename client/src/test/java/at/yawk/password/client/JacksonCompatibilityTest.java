package at.yawk.password.client;

import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import at.yawk.password.model.PasswordEntry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Databases written before the switch back to Jackson 2 (for Android) must still load.
 */
public class JacksonCompatibilityTest {
    @Test
    public void readsDatabaseWrittenByJackson3() throws Exception {
        byte[] bytes;
        // written by AesCodec with Jackson 3.2.3, password "fixture-password"
        try (InputStream in = getClass().getResourceAsStream("jackson3-db.bin")) {
            bytes = in.readAllBytes();
        }
        EncryptedBlob encrypted = new EncryptedBlob();
        encrypted.read(bytes);
        DecryptedBlob decrypted = AesCodec.decrypt(
                new ObjectMapper(), "fixture-password".getBytes(StandardCharsets.UTF_8), encrypted);

        List<PasswordEntry> entries = decrypted.getData().getPasswords();
        Assert.assertEquals(entries.size(), 3);
        Assert.assertEquals(entries.get(0).getName(), "example.com");
        Assert.assertEquals(entries.get(0).getValue(), "hunter2\nuser@example.com\nnotes: \"quoted\", \\backslash\\");
        Assert.assertEquals(entries.get(1).getName(), "Bänk 🔑");
        Assert.assertEquals(entries.get(1).getValue(), "pässwörd€\t\u0001");
        Assert.assertEquals(entries.get(2).getName(), "empty");
        Assert.assertEquals(entries.get(2).getValue(), "");

        // and survives a round trip through Jackson 2
        EncryptedBlob reencrypted = AesCodec.encrypt(
                new ObjectMapper(), "fixture-password".getBytes(StandardCharsets.UTF_8), decrypted);
        Assert.assertEquals(AesCodec.decrypt(
                new ObjectMapper(), "fixture-password".getBytes(StandardCharsets.UTF_8), reencrypted), decrypted);
    }
}
