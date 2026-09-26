package at.yawk.password;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
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

    private static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    public static boolean isPosix(Path path) {
        return path.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    /**
     * File attributes for creating an owner-only ({@code rw-------}) file, or none if the file system does not support
     * POSIX permissions.
     */
    private static FileAttribute<?>[] ownerOnlyAttributes(Path path) {
        if (isPosix(path)) {
            return new FileAttribute<?>[]{ PosixFilePermissions.asFileAttribute(OWNER_ONLY) };
        } else {
            // e.g. Windows: the new file inherits the directory's ACL, so it is not necessarily owner-only there.
            return new FileAttribute<?>[0];
        }
    }

    /**
     * Write the data to the file and force it to disk.
     */
    private static void writeAndSync(Path path, Set<? extends OpenOption> options, byte[] data,
                                     FileAttribute<?>... attributes) throws IOException {
        try (FileChannel channel = FileChannel.open(path, options, attributes)) {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
    }

    /**
     * Restrict the permissions of an existing file to {@code rw-------}. Does nothing on non-POSIX file systems.
     */
    static void setOwnerOnlyPermissions(File file) throws IOException {
        Path path = file.toPath();
        if (isPosix(path)) {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        }
    }

    /**
     * Create a new file (failing if it already exists) with owner-only permissions from the start, and write the
     * given data to it.
     */
    static void createOwnerOnly(File file, byte[] data) throws IOException {
        Path path = file.toPath();
        writeAndSync(path, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), data,
                     ownerOnlyAttributes(path));
    }

    /**
     * Atomically replace the given file with the given data. The data is first written to a temporary file with
     * owner-only permissions in the same directory, which is then moved to the target.
     */
    static void writeOwnerOnlyAtomically(File file, byte[] data) throws IOException {
        Path target = file.toPath().toAbsolutePath();
        Path dir = target.getParent();
        Path tmp = Files.createTempFile(dir, target.getFileName().toString(), ".tmp", ownerOnlyAttributes(dir));
        try {
            // sync before the move so a crash cannot leave an empty or truncated target
            writeAndSync(tmp, EnumSet.of(StandardOpenOption.WRITE), data);
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /**
     * Point {@code target} at {@code source} via a symlink, or, if that is not possible, write a copy of
     * {@code sourceData} (the content of {@code source}) to it.
     */
    static void symlinkOrCopy(File source, File target, byte[] sourceData) throws IOException {
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
        writeOwnerOnlyAtomically(target, sourceData);
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
