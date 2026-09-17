package at.yawk.password.gui;

import at.yawk.password.client.ClientValue;
import at.yawk.password.client.PasswordClient;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.UnaryOperator;
import org.jetbrains.annotations.Nullable;

/**
 * Holds the decrypted password database and persists modifications through a {@link PasswordClient}.
 * <p>
 * The blob is copy-on-write: every modification builds a new blob, saves it, and only replaces the current state
 * once the save succeeded. Entries are treated as immutable and identified by object identity. Mutating methods
 * block (scrypt, network) and must not be called from the UI thread; {@link #getEntries()} may be called from any
 * thread.
 *
 * @author yawkat
 */
class PasswordStore {
    private final PasswordClient client;
    private volatile PasswordBlob blob;
    private volatile boolean fromLocalStorage;

    private PasswordStore(PasswordClient client, PasswordBlob blob, boolean fromLocalStorage) {
        this.client = client;
        this.blob = blob;
        this.fromLocalStorage = fromLocalStorage;
    }

    /**
     * Load the database using the given client.
     *
     * @return The store, or {@code null} if there is no database yet (neither remote nor local).
     */
    @Nullable
    static PasswordStore open(PasswordClient client) throws Exception {
        ClientValue<PasswordBlob> value = client.load();
        if (value.getValue() == null) {
            return null;
        }
        return new PasswordStore(client, value.getValue(), value.isFromLocalStorage());
    }

    /**
     * Create an empty store. Nothing is saved until the first modification.
     */
    static PasswordStore createEmpty(PasswordClient client) {
        return new PasswordStore(client, new PasswordBlob(), false);
    }

    List<PasswordEntry> getEntries() {
        return Collections.unmodifiableList(blob.getPasswords());
    }

    /**
     * @return Whether the current data was loaded from the local copy because the server was unreachable.
     */
    boolean isFromLocalStorage() {
        return fromLocalStorage;
    }

    void reload() throws Exception {
        ClientValue<PasswordBlob> value = client.load();
        blob = value.getValue() == null ? new PasswordBlob() : value.getValue();
        fromLocalStorage = value.isFromLocalStorage();
    }

    PasswordEntry add(String name, String value) throws Exception {
        PasswordEntry entry = entry(name, value);
        modify(entries -> {
            entries.add(entry);
            return entries;
        });
        return entry;
    }

    PasswordEntry update(PasswordEntry old, String name, String value) throws Exception {
        PasswordEntry entry = entry(name, value);
        modify(entries -> {
            entries.set(indexOf(entries, old), entry);
            return entries;
        });
        return entry;
    }

    void delete(PasswordEntry old) throws Exception {
        modify(entries -> {
            entries.remove(indexOf(entries, old));
            return entries;
        });
    }

    private synchronized void modify(UnaryOperator<List<PasswordEntry>> operation) throws Exception {
        PasswordBlob copy = new PasswordBlob();
        copy.setPasswords(operation.apply(new ArrayList<>(blob.getPasswords())));
        client.save(copy);
        blob = copy;
        // the remote now has our state, whatever it had before
        fromLocalStorage = false;
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
    static String firstLine(@Nullable String value) {
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
