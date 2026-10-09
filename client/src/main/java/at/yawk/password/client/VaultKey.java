package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.jetbrains.annotations.Nullable;

/**
 * What a {@link VaultClient} gets its keys from: the password, or a key exported from an unlocked client with
 * {@link VaultClient#exportKey()}. The Android app keeps the exported key of the 2FA vault in the Keystore, so that a
 * fingerprint opens the vault without its password.
 *
 * <p>Thread safe, so that several clients can share one.
 *
 * @author yawkat
 */
public final class VaultKey {
    /**
     * Length of an exported key: install salt, then root key.
     */
    public static final int EXPORTED_LENGTH = AuthProtocol.SALT_LENGTH + KeyMaterial.ROOT_KEY_LENGTH;

    @Nullable private final byte[] password;
    /**
     * Keys derived from the password so far, by install salt, or the one key of an exported key.
     */
    private final List<KeyMaterial> keys = new ArrayList<>();

    private VaultKey(@Nullable byte[] password) {
        this.password = password;
    }

    /**
     * @param password The UTF-8 encoded password. Not copied: the caller may wipe it once the client is not used
     * anymore.
     */
    public static VaultKey ofPassword(byte[] password) {
        return new VaultKey(password);
    }

    /**
     * @param exported A key from {@link VaultClient#exportKey()}. Copied, so the caller can wipe it right away.
     */
    public static VaultKey ofExportedKey(byte[] exported) {
        if (exported.length != EXPORTED_LENGTH) {
            throw new IllegalArgumentException("Invalid exported key length");
        }
        byte[] rootKey = Arrays.copyOfRange(exported, AuthProtocol.SALT_LENGTH, EXPORTED_LENGTH);
        VaultKey key = new VaultKey(null);
        key.keys.add(KeyMaterial.fromRootKey(Arrays.copyOf(exported, AuthProtocol.SALT_LENGTH), rootKey));
        Arrays.fill(rootKey, (byte) 0);
        return key;
    }

    /**
     * @throws WrongPasswordException if this is an exported key of another install salt, e.g. because the vault on
     * the server was reset and created again
     */
    synchronized KeyMaterial keysFor(byte[] installSalt) throws WrongPasswordException {
        for (KeyMaterial derived : keys) {
            if (derived.hasInstallSalt(installSalt)) {
                return derived;
            }
        }
        if (password == null) {
            throw new WrongPasswordException("This vault was created with another key, unlock it with its password");
        }
        KeyMaterial derived = KeyMaterial.derive(password, installSalt);
        keys.add(derived);
        return derived;
    }

    /**
     * Whether this key may register the vault on the server. An exported key may not: the vault it belongs to was
     * registered already, so an unregistered server means that the vault was reset (e.g. to change its password), and
     * registering the old key again would take it back.
     */
    boolean mayRegister() {
        return password != null;
    }

    /**
     * @return Keys for a vault that doesn't exist yet, with a new install salt. Only for a key that
     * {@link #mayRegister}.
     */
    KeyMaterial keysForNewVault() throws WrongPasswordException {
        return keysFor(HashUtil.generateRandomBytes(AuthProtocol.SALT_LENGTH));
    }
}
