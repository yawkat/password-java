package at.yawk.password;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;

/**
 * @author yawkat
 */
public class PlatformDependent {
    /**
     * Get the current ISO-8601 timestamp.
     */
    static String nowTimestamp() {
        return Instant.now().toString();
    }

    static void setOwnerOnlyPermissions(File file) throws IOException {
        Set<PosixFilePermission> perms = EnumSet.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        Files.setPosixFilePermissions(file.toPath(), perms);
    }

    static void symlinkOrCopy(File source, File target) throws IOException {
        try {
            Files.createSymbolicLink(target.toPath(), source.toPath());
            return;
        } catch (UnsupportedOperationException ignored) {}

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
