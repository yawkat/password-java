package at.yawk.password.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.Assert;
import org.testng.annotations.Test;

public class OtpAccountTest {
    private static OtpBlob blob() {
        OtpAccount account = new OtpAccount();
        account.setIssuer("GitHub");
        account.setLabel("yawkat");
        account.setSecret("JBSWY3DPEHPK3PXP");
        account.setNotes("recovery email: hunter2@example.com");
        BackupCode code = new BackupCode();
        code.setCode("abcd-1234");
        account.getBackupCodes().add(code);
        OtpBlob blob = new OtpBlob();
        blob.getAccounts().add(account);
        return blob;
    }

    @Test
    public void toStringHidesSecrets() {
        OtpBlob blob = blob();
        for (Object o : new Object[]{blob, blob.getAccounts().get(0), blob.getAccounts().get(0).getBackupCodes().get(0)}) {
            String string = o.toString();
            Assert.assertFalse(string.contains("JBSWY3DPEHPK3PXP"), string);
            Assert.assertFalse(string.contains("abcd-1234"), string);
            Assert.assertFalse(string.contains("hunter2"), string);
        }
        Assert.assertTrue(blob.toString().contains("GitHub"));
    }

    @Test
    public void json() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(blob());
        Assert.assertEquals(json, "{\"accounts\":[{\"type\":\"totp\",\"issuer\":\"GitHub\",\"label\":\"yawkat\"," +
                                  "\"secret\":\"JBSWY3DPEHPK3PXP\",\"algorithm\":\"SHA1\",\"digits\":6," +
                                  "\"period\":30,\"backupCodes\":[{\"code\":\"abcd-1234\",\"used\":false}]," +
                                  "\"notes\":\"recovery email: hunter2@example.com\"}]}");
        Assert.assertEquals(mapper.readValue(json, OtpBlob.class), blob());
    }
}
