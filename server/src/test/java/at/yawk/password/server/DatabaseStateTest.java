package at.yawk.password.server;

import at.yawk.password.AuthProtocol;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
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
    public void testNonceMemory() {
        NonceMemory nonces = new NonceMemory(3, 60_000);
        long now = 1_000_000;
        nonces.add("a", now - 30_000, now);
        nonces.add("b", now + 40_000, now);
        Assert.assertTrue(nonces.contains("a"));

        // kept exactly as long as their requests are fresh, however much time has passed since they were added
        now += 30_000;
        nonces.add("c", now, now);
        Assert.assertTrue(nonces.contains("a"));
        now += 1;
        nonces.add("d", now, now);
        Assert.assertFalse(nonces.contains("a"));
        Assert.assertTrue(nonces.contains("b"));

        // a clock that goes back forgets nothing
        now -= 1_000_000;
        nonces.add("e", now, now);
        Assert.assertEquals(nonces.size(), 3);
        // full: the nonce closest to expiry (the oldest timestamp) goes first
        Assert.assertFalse(nonces.contains("c"));
        Assert.assertTrue(nonces.contains("b"));
        Assert.assertTrue(nonces.contains("d"));
        Assert.assertTrue(nonces.contains("e"));
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
            Assert.assertEquals(state.preCheck(header), DatabaseState.Verdict.OK);
            Assert.assertEquals(state.verify(header, "GET", "/db", new byte[0]), DatabaseState.Verdict.FORBIDDEN);
        }
        // 1 s after the 5th failure, then doubling
        DatabaseState.AuthHeader good = DatabaseState.parseAuthHeader(auth.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertEquals(state.preCheck(good), DatabaseState.Verdict.BACKOFF);
        now.addAndGet(1000);
        DatabaseState.AuthHeader bad = DatabaseState.parseAuthHeader(other.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertEquals(state.verify(bad, "GET", "/db", new byte[0]), DatabaseState.Verdict.FORBIDDEN);
        now.addAndGet(1999);
        Assert.assertEquals(state.preCheck(good), DatabaseState.Verdict.BACKOFF);
        now.addAndGet(1);
        good = DatabaseState.parseAuthHeader(auth.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertEquals(state.verify(good, "GET", "/db", new byte[0]), DatabaseState.Verdict.OK);
        // success resets the count
        bad = DatabaseState.parseAuthHeader(other.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertEquals(state.verify(bad, "GET", "/db", new byte[0]), DatabaseState.Verdict.FORBIDDEN);
        good = DatabaseState.parseAuthHeader(auth.header(now.get(), "GET", "/db", new byte[0]));
        Assert.assertEquals(state.preCheck(good), DatabaseState.Verdict.OK);
    }

    @Test
    public void testSlowBody() throws Exception {
        DatabaseState state = new DatabaseState(dir.toString());
        AtomicLong now = new AtomicLong(1_000_000_000L);
        state.clock = now::get;
        ServerAuth auth = new ServerAuth();
        Assert.assertTrue(state.registerIfUnregistered(auth.registration()));

        // the body took 90 s to arrive: still fine
        DatabaseState.AuthHeader slow = DatabaseState.parseAuthHeader(auth.header(now.get(), "PUT", "/db", new byte[0]));
        Assert.assertEquals(state.preCheck(slow), DatabaseState.Verdict.OK);
        now.addAndGet(90_000);
        Assert.assertEquals(state.verify(slow, "PUT", "/db", new byte[0]), DatabaseState.Verdict.OK);
        // and its nonce is still remembered, while a replay of it could complete
        Assert.assertEquals(state.verify(slow, "PUT", "/db", new byte[0]), DatabaseState.Verdict.FORBIDDEN);

        // too slow: stale, so the client can retry
        DatabaseState.AuthHeader tooSlow =
                DatabaseState.parseAuthHeader(auth.header(now.get(), "PUT", "/db", new byte[0]));
        now.addAndGet(DatabaseState.MAX_REQUEST_AGE_MILLIS + 1);
        Assert.assertEquals(state.verify(tooSlow, "PUT", "/db", new byte[0]), DatabaseState.Verdict.STALE);
    }

    @Test
    public void testInvalidRegistrationFailsStartup() throws Exception {
        Files.write(dir.resolve("verifier"), new byte[10]);
        Assert.assertThrows(java.io.IOException.class, () -> new DatabaseState(dir.toString()));
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
            Assert.assertEquals(state.preCheck(bad), DatabaseState.Verdict.OK, "attempt " + i);
            Assert.assertEquals(state.verify(bad, "GET", "/db", new byte[0]), DatabaseState.Verdict.FORBIDDEN);
        }
    }
}
