package at.yawk.password.client;

import at.yawk.password.LocalStorageProvider;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.PasswordBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;

/**
 * Client of the password vault, unlocked with the master password. Unlike the 2FA vault, it existed in the format of
 * the old protocol, so it also reads a local copy in that format, to migrate it.
 *
 * @author yawkat
 */
@Slf4j
public class PasswordClient extends VaultClient<PasswordBlob> {
    private final byte[] password;

    /**
     * @param password The UTF-8 encoded master password. Not copied: the caller may wipe it once the client is not
     * used anymore.
     */
    public PasswordClient(String url, LocalStorageProvider localStorage, byte[] password) {
        super(url, "", localStorage, VaultKey.ofPassword(password), PasswordBlob.class);
        this.password = password;
    }

    @Nullable
    @Override
    DecryptedBlob<PasswordBlob> decryptLegacy(byte[] local) throws Exception {
        if (!LegacyBlob.isLegacy(local)) {
            return null;
        }
        log.info("Local copy is in the legacy format, it will be migrated on the next save");
        return LegacyBlob.decrypt(new ObjectMapper(), password, local);
    }
}
