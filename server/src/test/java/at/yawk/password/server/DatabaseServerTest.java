package at.yawk.password.server;

import java.util.Set;
import org.testng.Assert;
import org.testng.annotations.Test;

public class DatabaseServerTest {
    @Test
    public void testTokenSetIsBounded() {
        Set<Integer> tokens = DatabaseServer.createTokenSet();
        for (int i = 0; i < DatabaseServer.MAX_OUTSTANDING_CHALLENGES + 100; i++) {
            tokens.add(i);
        }
        Assert.assertEquals(tokens.size(), DatabaseServer.MAX_OUTSTANDING_CHALLENGES);
        // oldest entries are evicted first, newest are kept
        Assert.assertFalse(tokens.contains(0));
        Assert.assertTrue(tokens.contains(DatabaseServer.MAX_OUTSTANDING_CHALLENGES + 99));
    }

    @Test
    public void testParseToken() {
        Assert.assertEquals(DatabaseServer.parseToken("0aFF"), new byte[]{ 0x0a, (byte) 0xff });
        Assert.assertNull(DatabaseServer.parseToken(null));
        Assert.assertNull(DatabaseServer.parseToken("xyz"));
        Assert.assertNull(DatabaseServer.parseToken("abc"));
    }
}
