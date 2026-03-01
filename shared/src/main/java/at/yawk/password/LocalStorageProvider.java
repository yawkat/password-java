package at.yawk.password;

import java.io.IOException;
import org.jetbrains.annotations.Nullable;

/**
 * @author yawkat
 */
public interface LocalStorageProvider {
    LocalStorageProvider NOOP = new LocalStorageProvider() {
        @Override
        public void save(byte[] data) {}

        @Nullable
        @Override
        public byte[] load() {
            return null;
        }
    };

    void save(byte[] data) throws IOException;

    @Nullable
    byte[] load() throws IOException;
}
