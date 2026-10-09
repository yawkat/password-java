package at.yawk.password.client;

import at.yawk.password.LocalStorageProvider;
import at.yawk.password.model.PasswordBlob;

/**
 * Client of the password vault, unlocked with the master password.
 *
 * @author yawkat
 */
public class PasswordClient extends VaultClient<PasswordBlob> {
    /**
     * @param password The UTF-8 encoded master password. Not copied: the caller may wipe it once the client is not
     * used anymore.
     */
    public PasswordClient(String url, LocalStorageProvider localStorage, byte[] password) {
        super(url, "", localStorage, VaultKey.ofPassword(password), PasswordBlob.class);
    }
}
