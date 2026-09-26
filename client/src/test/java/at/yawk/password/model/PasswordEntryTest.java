package at.yawk.password.model;

import org.testng.Assert;
import org.testng.annotations.Test;

public class PasswordEntryTest {
    @Test
    public void toStringHidesValue() {
        PasswordEntry entry = new PasswordEntry();
        entry.setName("github");
        entry.setValue("hunter2\nuser: me");
        PasswordBlob blob = new PasswordBlob();
        blob.getPasswords().add(entry);
        DecryptedBlob decrypted = new DecryptedBlob();
        decrypted.setData(blob);

        for (Object o : new Object[]{entry, blob, decrypted}) {
            String string = o.toString();
            Assert.assertTrue(string.contains("github"), string);
            Assert.assertFalse(string.contains("hunter2"), string);
        }
    }
}
