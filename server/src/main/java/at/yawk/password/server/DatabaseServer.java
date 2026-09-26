package at.yawk.password.server;

import at.yawk.password.FileLocalStorageProvider;
import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.MultiFileLocalStorageProvider;
import at.yawk.password.PlatformDependent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
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

    private final Set<ByteArrayWrapper> tokens = Collections.newSetFromMap(
            ExpiringMap.builder()
                    .expiration(1, TimeUnit.MINUTES)
                    .build());

    public static void main(String[] args) throws IOException {
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

        File dataDirectory = directory.value(set);
        warnIfAccessibleByOthers(dataDirectory.toPath());

        FileLocalStorageProvider sharedSecretStorageProvider =
                new FileLocalStorageProvider(new File(dataDirectory, "shared-secret"));
        sharedSecretStorageProvider.restrictPermissions();

        new DatabaseServer(
                new MultiFileLocalStorageProvider(dataDirectory),
                sharedSecretStorageProvider
        ).start();
    }

    private static void warnIfAccessibleByOthers(Path dir) {
        if (!Files.isDirectory(dir) || !PlatformDependent.isPosix(dir)) {
            return;
        }
        Set<PosixFilePermission> perms;
        try {
            perms = Files.getPosixFilePermissions(dir);
        } catch (IOException e) {
            // only a warning, never fail startup
            return;
        }
        if (!perms.stream().allMatch(p -> p.name().startsWith("OWNER_"))) {
            System.err.println("Warning: data directory " + dir.toAbsolutePath() + " is accessible by other users ("
                               + PosixFilePermissions.toString(perms) + "), consider chmod 700");
        }
    }

    @SneakyThrows(NoSuchAlgorithmException.class)
    private SecureRandom createSecureRandom() {
        return SecureRandom.getInstance("SHA1PRNG");
    }

    private boolean takeToken(Request request) {
        String header = request.headers("X-Auth-Token");
        return header != null && tokens.remove(new ByteArrayWrapper(HexFormat.of().parseHex(header)));
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
