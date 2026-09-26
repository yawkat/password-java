package at.yawk.password.server;

import at.yawk.password.AuthProtocol;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class DatabaseStateTest {
    private Path dir;

    @BeforeMethod
    public void createDirectory() throws Exception {
        dir = Files.createTempDirectory("password-state");
    }

    @AfterMethod
    public void deleteDirectory() throws Exception {
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path file : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(file);
            }
        }
    }

    @Test
    public void testNonceSetIsBounded() {
        Set<Integer> nonces = DatabaseState.createNonceSet();
        for (int i = 0; i < DatabaseState.MAX_REMEMBERED_NONCES + 100; i++) {
            nonces.add(i);
        }
        Assert.assertEquals(nonces.size(), DatabaseState.MAX_REMEMBERED_NONCES);
        // oldest entries are evicted first, newest are kept
        Assert.assertFalse(nonces.contains(0));
        Assert.assertTrue(nonces.contains(DatabaseState.MAX_REMEMBERED_NONCES + 99));
    }

    @Test
    public void testParseAuthHeader() {
        String nonce = "0123456789abcdef0123456789abcdef";
        String sig = "ab".repeat(AuthProtocol.SIGNATURE_LENGTH);
        DatabaseState.AuthHeader header = DatabaseState.parseAuthHeader("123 " + nonce + " " + sig.toUpperCase());
        Assert.assertNotNull(header);
        Assert.assertEquals(header.timestamp(), 123);
        Assert.assertEquals(header.nonceHex(), nonce);

        Assert.assertNull(DatabaseState.parseAuthHeader(null));
        Assert.assertNull(DatabaseState.parseAuthHeader(""));
        Assert.assertNull(DatabaseState.parseAuthHeader("123 " + nonce));
        Assert.assertNull(DatabaseState.parseAuthHeader("123 " + nonce + " " + sig + " "));
        Assert.assertNull(DatabaseState.parseAuthHeader("123  " + nonce + " " + sig));
        Assert.assertNull(DatabaseState.parseAuthHeader("-123 " + nonce + " " + sig));
        Assert.assertNull(DatabaseState.parseAuthHeader("+123 " + nonce + " " + sig));
        Assert.assertNull(DatabaseState.parseAuthHeader("99999999999999999999 " + nonce + " " + sig));
        Assert.assertNull(DatabaseState.parseAuthHeader("123 " + nonce.toUpperCase() + " " + sig));
        Assert.assertNull(DatabaseState.parseAuthHeader("123 " + nonce.substring(2) + " " + sig));
        Assert.assertNull(DatabaseState.parseAuthHeader("123 " + nonce + " " + sig.substring(2)));
        Assert.assertNull(DatabaseState.parseAuthHeader("123 " + nonce.replace('0', 'x') + " " + sig));
        // non-ASCII digits
        Assert.assertNull(DatabaseState.parseAuthHeader("١٢٣ " + nonce + " " + sig));
        Assert.assertNull(DatabaseState.parseAuthHeader("123 " + nonce.replace('0', '٠') + " " + sig));
    }

    @Test
    public void testBackoff() throws Exception {
        DatabaseState state = new DatabaseState(dir.toString());
        AtomicLong now = new AtomicLong(1_000_000_000L);
        state.clock = now::get;
        ServerAuth auth = new ServerAuth();
        Assert.assertTrue(state.registerIfUnregistered(auth.registration()));
        ServerAuth other = new ServerAuth();

        for (int i = 0; i < DatabaseState.FREE_FAILURES; i++) {
            DatabaseState.AuthHeader header =
                    DatabaseState.parseAuthHeader(other.header(now.get(), "GET", "/db", new byte[0]));
            Assert.assertEquals(state.preCheck(header), DatabaseState.PreCheck.OK);
            Assert.assertFalse(state.verify(header, "GET", "/db", new byte[0]));
        }
        // 1 s after the 5th failure, then doubling
        DatabaseState.AuthHeader good = DatabaseState.parseAuthHeader(auth.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertEquals(state.preCheck(good), DatabaseState.PreCheck.BACKOFF);
        now.addAndGet(1000);
        DatabaseState.AuthHeader bad = DatabaseState.parseAuthHeader(other.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertFalse(state.verify(bad, "GET", "/db", new byte[0]));
        now.addAndGet(1999);
        Assert.assertEquals(state.preCheck(good), DatabaseState.PreCheck.BACKOFF);
        now.addAndGet(1);
        good = DatabaseState.parseAuthHeader(auth.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertTrue(state.verify(good, "GET", "/db", new byte[0]));
        // success resets the count
        bad = DatabaseState.parseAuthHeader(other.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertFalse(state.verify(bad, "GET", "/db", new byte[0]));
        good = DatabaseState.parseAuthHeader(auth.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertEquals(state.preCheck(good), DatabaseState.PreCheck.OK);
    }

    @Test
    public void testBackoffIsCapped() throws Exception {
        DatabaseState state = new DatabaseState(dir.toString());
        AtomicLong now = new AtomicLong(1_000_000_000L);
        state.clock = now::get;
        Assert.assertTrue(state.registerIfUnregistered(new ServerAuth().registration()));
        ServerAuth other = new ServerAuth();
        for (int i = 0; i < 100; i++) {
            now.addAndGet(DatabaseState.MAX_BACKOFF_MILLIS);
            DatabaseState.AuthHeader bad =
                    DatabaseState.parseAuthHeader(other.header(now.get(), "GET", "/db", new byte[0]));
            Assert.assertEquals(state.preCheck(bad), DatabaseState.PreCheck.OK, "attempt " + i);
            Assert.assertFalse(state.verify(bad, "GET", "/db", new byte[0]));
        }
    }
}
