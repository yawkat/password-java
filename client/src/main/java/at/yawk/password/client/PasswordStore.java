package at.yawk.password.client;

import at.yawk.password.model.Passkey;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.UnaryOperator;
import org.jetbrains.annotations.Nullable;

/**
 * Holds the decrypted password database and persists modifications through a {@link PasswordClient}, see
 * {@link VaultStore}. Entries are treated as immutable and identified by object identity.
 *
 * @author yawkat
 */
public final class PasswordStore extends VaultStore<PasswordBlob> {
    private PasswordStore(VaultClient<PasswordBlob> client, PasswordBlob blob,
                          @Nullable ClientValue.LocalReason localReason) {
        super(client, blob, localReason);
    }

    /**
     * Load the database using the given client.
     *
     * @return The store, or {@code null} if there is no database yet (neither remote nor local).
     */
    @Nullable
    public static PasswordStore open(PasswordClient client) throws Exception {
        ClientValue<PasswordBlob> value = client.load();
        if (value.getValue() == null) {
            return null;
        }
        return new PasswordStore(client, value.getValue(), value.getLocalReason());
    }

    /**
     * Create an empty store. Nothing is saved until the first modification.
     */
    public static PasswordStore createEmpty(PasswordClient client) {
        return new PasswordStore(client, new PasswordBlob(), null);
    }

    @Override
    PasswordBlob emptyData() {
        return new PasswordBlob();
    }

    public List<PasswordEntry> getEntries() {
        return Collections.unmodifiableList(getData().getPasswords());
    }

    public PasswordEntry add(String name, String value) throws Exception {
        PasswordEntry entry = entry(name, value);
        modifyEntries(entries -> {
            entries.add(entry);
            return entries;
        });
        return entry;
    }

    public PasswordEntry update(PasswordEntry old, String name, String value) throws Exception {
        PasswordEntry entry = entry(name, value);
        modifyEntries(entries -> {
            entries.set(indexOf(entries, old), entry);
            return entries;
        });
        return entry;
    }

    public void delete(PasswordEntry old) throws Exception {
        modifyEntries(entries -> {
            entries.remove(indexOf(entries, old));
            return entries;
        });
    }

    private void modifyEntries(UnaryOperator<List<PasswordEntry>> operation) throws Exception {
        modify(blob -> {
            PasswordBlob copy = new PasswordBlob();
            copy.setPasswords(operation.apply(new ArrayList<>(blob.getPasswords())));
            copy.setPasskeys(new ArrayList<>(blob.getPasskeys()));
            return copy;
        });
    }

    /**
     * The passkeys, in the order they were added. Like entries, they are immutable: don't modify them.
     */
    public List<Passkey> getPasskeys() {
        return Collections.unmodifiableList(getData().getPasskeys());
    }

    /**
     * Add a passkey, e.g. one made by {@link at.yawk.password.passkey.PasskeyAuthenticator#create}. A passkey of the
     * same relying party and user handle is replaced: a relying party that creates a passkey for an account replaces
     * the old one, as an authenticator that stores one discoverable credential per account does.
     */
    public void addPasskey(Passkey passkey) throws Exception {
        modifyPasskeys(passkeys -> {
            passkeys.removeIf(p -> p.getRpId().equals(passkey.getRpId()) &&
                                   p.getUserHandle().equals(passkey.getUserHandle()));
            passkeys.add(passkey);
            return passkeys;
        });
    }

    /**
     * Delete the passkey with the id of {@code passkey}, if there is one.
     */
    public void deletePasskey(Passkey passkey) throws Exception {
        modifyPasskeys(passkeys -> {
            passkeys.removeIf(p -> p.getId().equals(passkey.getId()));
            return passkeys;
        });
    }

    private void modifyPasskeys(UnaryOperator<List<Passkey>> operation) throws Exception {
        modify(blob -> {
            PasswordBlob copy = new PasswordBlob();
            copy.setPasswords(new ArrayList<>(blob.getPasswords()));
            copy.setPasskeys(operation.apply(new ArrayList<>(blob.getPasskeys())));
            return copy;
        });
    }

    private static int indexOf(List<PasswordEntry> entries, PasswordEntry entry) {
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i) == entry) {
                return i;
            }
        }
        throw new IllegalStateException("Entry is not part of this store: " + entry.getName());
    }

    private static PasswordEntry entry(String name, String value) {
        PasswordEntry entry = new PasswordEntry();
        entry.setName(name);
        entry.setValue(value);
        return entry;
    }

    /**
     * @return The first line of an entry value, which by convention is the password.
     */
    public static String firstLine(@Nullable String value) {
        if (value == null) {
            return "";
        }
        int end = 0;
        while (end < value.length() && value.charAt(end) != '\n' && value.charAt(end) != '\r') {
            end++;
        }
        return value.substring(0, end);
    }
}
