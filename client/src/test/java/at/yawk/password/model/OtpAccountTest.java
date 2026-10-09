package at.yawk.password.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.Assert;
import org.testng.annotations.Test;

public class OtpAccountTest {
    private static OtpBlob blob() {
        OtpAccount account = new OtpAccount();
        account.setId("6f1c0a52-8d0e-4c1e-9f3b-2a8f4d6e7b90");
        account.setIssuer("GitHub");
        account.setLabel("yawkat");
        account.setSecret("JBSWY3DPEHPK3PXP");
        account.setBackupCodes("abcd-1234\nefgh-5678");
        OtpBlob blob = new OtpBlob();
        blob.getAccounts().add(account);
        return blob;
    }

    @Test
    public void toStringHidesSecrets() {
        OtpBlob blob = blob();
        for (Object o : new Object[]{blob, blob.getAccounts().get(0)}) {
            String string = o.toString();
            Assert.assertFalse(string.contains("JBSWY3DPEHPK3PXP"), string);
            Assert.assertFalse(string.contains("abcd-1234"), string);
            Assert.assertTrue(string.contains("GitHub"), string);
        }
    }

    @Test
    public void json() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(blob());
        Assert.assertEquals(json, "{\"accounts\":[{\"id\":\"6f1c0a52-8d0e-4c1e-9f3b-2a8f4d6e7b90\",\"type\":\"totp\"," +
                                  "\"issuer\":\"GitHub\",\"label\":\"yawkat\",\"secret\":\"JBSWY3DPEHPK3PXP\"," +
                                  "\"algorithm\":\"SHA1\",\"digits\":6,\"period\":30," +
                                  "\"backupCodes\":\"abcd-1234\\nefgh-5678\"}]}");
        Assert.assertEquals(mapper.readValue(json, OtpBlob.class), blob());
    }

    @Test
    public void nullsBecomeEmpty() throws Exception {
        OtpAccount account = new ObjectMapper().readValue(
                "{\"secret\":\"JBSWY3DPEHPK3PXP\",\"issuer\":null,\"label\":null,\"backupCodes\":null}",
                OtpAccount.class);
        Assert.assertEquals(account.getIssuer(), "");
        Assert.assertEquals(account.getLabel(), "");
        Assert.assertEquals(account.getBackupCodes(), "");
    }

    @Test
    public void canonicalFields() {
        OtpAccount account = new OtpAccount();
        account.setSecret("jbsw y3dp-ehpk 3pxp====");
        account.setIssuer(" GitHub ");
        Assert.assertEquals(account.getSecret(), "JBSWY3DPEHPK3PXP");
        Assert.assertEquals(account.getIssuer(), "GitHub");
        // kept, so that a vault holding it still loads
        account.setSecret("not base32!");
        Assert.assertEquals(account.getSecret(), "not base32!");
    }

    @Test
    public void missingData() throws Exception {
        OtpBlob blob = new ObjectMapper().readValue("{\"accounts\":null}", OtpBlob.class);
        Assert.assertEquals(blob.getAccounts().size(), 0);
        blob = new ObjectMapper().readValue("{\"accounts\":[null,{\"issuer\":\"x\"},null]}", OtpBlob.class);
        Assert.assertEquals(blob.getAccounts().size(), 1);
        OtpAccount account = new ObjectMapper().readValue("{\"id\":null,\"secret\":\"JBSWY3DPEHPK3PXP\"}",
                                                          OtpAccount.class);
        Assert.assertNotNull(account.getId());
    }

    @Test
    public void distinctIds() {
        Assert.assertNotEquals(new OtpAccount().getId(), new OtpAccount().getId());
    }
}
