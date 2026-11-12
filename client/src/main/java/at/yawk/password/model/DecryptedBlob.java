package at.yawk.password.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AccessLevel;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

/**
 * The JSON content of an encrypted blob: the vault's data ({@link PasswordBlob} or {@link OtpBlob}) and its revision.
 *
 * @author yawkat
 */
@Data
public class DecryptedBlob<T> {
    /**
     * The highest {@link #getMinReaderVersion()} this client can open.
     */
    public static final int READER_VERSION = 1;

    private T data;
    /**
     * Incremented on every save. A client refuses to replace its local copy with a remote copy of a lower revision,
     * so a server can't silently roll the database back to a version older than the one the client has. Legacy
     * databases have none (0).
     */
    private long revision;
    /**
     * Clients with a lower {@link #READER_VERSION} refuse to open the database. Only raised for changes that an older
     * client must not ignore; for other new fields, it opens the database read-only (see {@link #readOnly()}). Left
     * out of the JSON while 0, so that clients that predate it keep opening the database.
     */
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    private int minReaderVersion;
    /**
     * Not part of the JSON: whether it had fields that this client doesn't know, which a save would drop. Without
     * bean accessors and annotations, so that Jackson doesn't know the name either, and a field of that name in the
     * JSON still counts as unknown. Not part of equality either: it says how the blob was read, not what it holds.
     */
    @EqualsAndHashCode.Exclude
    @Getter(AccessLevel.NONE)
    @Setter(AccessLevel.NONE)
    private boolean readOnly;

    public boolean readOnly() {
        return readOnly;
    }

    public void markReadOnly() {
        readOnly = true;
    }
}
