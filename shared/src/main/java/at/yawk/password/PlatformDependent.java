package at.yawk.password;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;
import org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement;

/**
 * @author yawkat
 */
@IgnoreJRERequirement
public class PlatformDependent {
    private static boolean hasJdk8 = true;

    /**
     * Get the current ISO-8601 timestamp, either with joda-time or jdk8.
     */
    static String nowTimestamp() {
        if (hasJdk8) {
            try {
                return Instant.now().toString();
            } catch (NoClassDefFoundError ignored) {
                hasJdk8 = false;
            }
        }
        return org.joda.time.Instant.now().toString();
    }

    static void setOwnerOnlyPermissions(File file) throws IOException {
        if (hasJdk8) {
            try {
                Set<PosixFilePermission> perms = EnumSet.of(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
                Files.setPosixFilePermissions(file.toPath(), perms);
            } catch (NoClassDefFoundError ignored) {
                hasJdk8 = false;
            }
        }
    }

    static void symlinkOrCopy(File source, File target) throws IOException {
        if (hasJdk8) {
            try {
                Files.createSymbolicLink(target.toPath(), source.toPath());
                return;
            } catch (NoClassDefFoundError ignored) {
                hasJdk8 = false;
            }
        }

        try {
            Process process = new ProcessBuilder("ln", "-sf", "--", source.toString(), target.toString()).start();
            if (process.waitFor() == 0) {
                return;
            }
        } catch (IOException | InterruptedException ignored) {}

        // atomic copy
        File tmp = File.createTempFile("link", null, target.getParentFile());
        try (InputStream in = new FileInputStream(source);
             OutputStream out = new FileOutputStream(tmp)) {
            FileLocalStorageProvider.copy(in, out);
        }
        if (!tmp.renameTo(target)) {
            throw new IOException("Failed to rename temp file to target");
        }
    }

    public static String printHexBinary(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append("0123456789abcdef".charAt((b >>> 4) & 0xf));
            builder.append("0123456789abcdef".charAt(b & 0xf));
        }
        return builder.toString();
    }
}
