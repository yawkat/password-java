package at.yawk.password.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

/**
 * The JSON content of an encrypted blob: the vault's data ({@link PasswordBlob} or {@link OtpBlob}) and its revision.
 *
 * @author yawkat
 */
@Data
public class DecryptedBlob<T> {
    private T data;
    /**
     * Incremented on every save. A client refuses to replace its local copy with a remote copy of a lower revision,
     * so a server can't silently roll the database back to a version older than the one the client has. Legacy
     * databases have none (0).
     */
    private long revision;
    /**
     * The {@link SchemaVersions#getReader()} of the client that saved it. Left out of the JSON while 0, so that clients
     * that predate it keep opening the database.
     */
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    private int minReaderVersion;
    /**
     * The {@link SchemaVersions#getWriter()} of the client that saved it. Left out of the JSON while 0, like
     * {@link #minReaderVersion}.
     */
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    private int minWriterVersion;
}
