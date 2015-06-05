package at.yawk.password;

import java.io.IOException;
import javax.annotation.Nullable;

/**
 * @author yawkat
 */
public class MemoryStorageProvider implements LocalStorageProvider {
    @Nullable
    private byte[] data = null;

    @Override
    public void save(byte[] data) throws IOException {
        this.data = data;
    }

    @Nullable
    @Override
    public byte[] load() throws IOException {
        return data;
    }
}
