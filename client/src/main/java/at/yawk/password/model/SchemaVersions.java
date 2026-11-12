package at.yawk.password.model;

import lombok.Value;

/**
 * The schema versions of a vault's data that this client knows, see SPEC.md, "Schema versions". Each vault has its
 * own, so that a change to one vault doesn't affect what older clients can do with the other.
 *
 * @author yawkat
 */
@Value
public class SchemaVersions {
    /**
     * Raised with changes that a client must not ignore even when it only reads, e.g. a field that changes how a code
     * is computed. A client refuses data with a higher {@link DecryptedBlob#getMinReaderVersion()}.
     */
    int reader;
    /**
     * Raised with every change to the data, e.g. a new field. A client opens data with a higher
     * {@link DecryptedBlob#getMinWriterVersion()} read-only, skipping what it doesn't know, since saving would drop
     * it.
     */
    int writer;
}
