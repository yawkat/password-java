package at.yawk.password.server;

import java.util.Set;
import org.testng.Assert;
import org.testng.annotations.Test;

public class DatabaseServerTest {
    @Test
    public void testTokenSetIsBounded() {
        Set<Integer> tokens = DatabaseState.createTokenSet();
        for (int i = 0; i < DatabaseState.MAX_OUTSTANDING_CHALLENGES + 100; i++) {
            tokens.add(i);
        }
        Assert.assertEquals(tokens.size(), DatabaseState.MAX_OUTSTANDING_CHALLENGES);
        // oldest entries are evicted first, newest are kept
        Assert.assertFalse(tokens.contains(0));
        Assert.assertTrue(tokens.contains(DatabaseState.MAX_OUTSTANDING_CHALLENGES + 99));
    }

    @Test
    public void testParseToken() {
        Assert.assertEquals(DatabaseState.parseToken("0aFF"), new byte[]{ 0x0a, (byte) 0xff });
        Assert.assertNull(DatabaseState.parseToken(null));
        Assert.assertNull(DatabaseState.parseToken("xyz"));
        Assert.assertNull(DatabaseState.parseToken("abc"));
    }
}
