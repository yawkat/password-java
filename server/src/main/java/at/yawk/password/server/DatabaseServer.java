package at.yawk.password.server;

import at.yawk.password.FileLocalStorageProvider;
import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.MultiFileLocalStorageProvider;
import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.HexFormat;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.Value;
import net.jodah.expiringmap.ExpirationPolicy;
import net.jodah.expiringmap.ExpiringMap;
import spark.Request;
import spark.Spark;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
public class DatabaseServer {
    private final LocalStorageProvider databaseStorageProvider;
    private final LocalStorageProvider sharedSecretStorageProvider;

    /**
     * Upper bound on outstanding challenge tokens. /challenge is unauthenticated, so without a bound a client could
     * grow the heap until entries expire. When full, the oldest challenge is evicted, so under a flood a legitimate
     * client whose challenge was evicted gets a 403 on /db and has to retry. This trades unbounded memory growth for
     * a temporary authentication failure.
     */
    static final int MAX_OUTSTANDING_CHALLENGES = 10_000;

    private final Set<ByteArrayWrapper> tokens = createTokenSet();

    static <T> Set<T> createTokenSet() {
        return Collections.newSetFromMap(
                ExpiringMap.builder()
                        .expiration(1, TimeUnit.MINUTES)
                        .expirationPolicy(ExpirationPolicy.CREATED)
                        .maxSize(MAX_OUTSTANDING_CHALLENGES)
                        .build());
    }

    public static void main(String[] args) {
        OptionParser parser = new OptionParser();
        OptionSpec<File> directory = parser.accepts("d")
                .withRequiredArg()
                .ofType(File.class)
                .defaultsTo(new File("."));
        OptionSpec<Integer> port = parser.accepts("p")
                .withRequiredArg()
                .ofType(Integer.class)
                .defaultsTo(8080);
        OptionSet set = parser.parse(args);

        Spark.port(port.value(set));

        new DatabaseServer(
                new MultiFileLocalStorageProvider(directory.value(set)),
                new FileLocalStorageProvider(new File(directory.value(set), "shared-secret"))
        ).start();
    }

    @SneakyThrows(NoSuchAlgorithmException.class)
    private SecureRandom createSecureRandom() {
        return SecureRandom.getInstance("SHA1PRNG");
    }

    private boolean takeToken(Request request) {
        byte[] token = parseToken(request.headers("X-Auth-Token"));
        return token != null && tokens.remove(new ByteArrayWrapper(token));
    }

    /**
     * Parse the client-supplied hex token, returning {@code null} if it is missing or malformed.
     */
    static byte[] parseToken(String header) {
        if (header == null) {
            return null;
        }
        try {
            return HexFormat.of().parseHex(header);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public void start() {
        Spark.get("/challenge", (req, res) -> {
            byte[] sharedSecret = sharedSecretStorageProvider.load();
            if (sharedSecret == null) {
                res.status(404);
                return null;
            }

            byte[] challenge = HashUtil.generateRandomBytes(32);

            byte[] token = HashUtil.sha256(sharedSecret, challenge);
            tokens.add(new ByteArrayWrapper(token));

            return challenge;
        });
        Spark.put("/shared-secret", (req, res) -> {
            byte[] oldSecret = sharedSecretStorageProvider.load();
            //noinspection VariableNotUsedInsideIf
            if (oldSecret != null) {
                res.status(403);
                return null;
            }
            sharedSecretStorageProvider.save(req.bodyAsBytes());
            return "";
        });

        Spark.get("/db", (req, res) -> {
            if (!takeToken(req)) {
                res.status(403);
                return null;
            }

            byte[] db = databaseStorageProvider.load();
            if (db == null) {
                res.status(404);
                return null;
            }
            return db;
        });
        Spark.put("/db", (req, res) -> {
            if (!takeToken(req)) {
                res.status(403);
                return null;
            }

            byte[] db = req.bodyAsBytes();
            databaseStorageProvider.save(db);
            return "";
        });
    }

    @Value
    private static class ByteArrayWrapper {
        private final byte[] array;
    }
}
