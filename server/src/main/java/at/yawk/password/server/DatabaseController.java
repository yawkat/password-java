package at.yawk.password.server;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Put;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import java.io.IOException;

/**
 * HTTP API of the database server. Request and response bodies are raw bytes; error responses have no body.
 *
 * @author yawkat
 */
@Controller
@ExecuteOn(TaskExecutors.BLOCKING) // storage access is blocking file IO, keep it off the event loop
class DatabaseController {
    private static final String AUTH_TOKEN_HEADER = "X-Auth-Token";
    // An empty request body binds as null and is stored as an empty value, as before. The Micronaut
    // processor warns about @Nullable byte[] ("primitive types"), but the null case is handled. Optional<byte[]>
    // would avoid the warning, but makes Micronaut decode the form content type that HttpURLConnection sends.
    private static final byte[] EMPTY = new byte[0];

    private final DatabaseState state;

    DatabaseController(DatabaseState state) {
        this.state = state;
    }

    /**
     * Returns a new challenge, or 404 if no shared secret has been set yet.
     */
    @Get(uri = "/challenge", produces = MediaType.APPLICATION_OCTET_STREAM)
    HttpResponse<byte[]> challenge() throws IOException {
        byte[] challenge = state.createChallenge();
        return challenge == null ? HttpResponse.notFound() : HttpResponse.ok(challenge);
    }

    /**
     * Sets the shared secret. Returns 403 if it is already set.
     */
    @Put(uri = "/shared-secret", consumes = MediaType.ALL)
    HttpResponse<?> putSharedSecret(@Nullable @Body byte[] secret) throws IOException {
        return state.setSharedSecretIfUnset(secret == null ? EMPTY : secret) ?
                HttpResponse.ok() : HttpResponse.status(HttpStatus.FORBIDDEN);
    }

    /**
     * Returns the database, 403 if the token is missing or invalid, or 404 if no database has been saved yet.
     */
    @Get(uri = "/db", produces = MediaType.APPLICATION_OCTET_STREAM)
    HttpResponse<byte[]> getDatabase(@Nullable @Header(AUTH_TOKEN_HEADER) String token) throws IOException {
        if (!state.takeToken(token)) {
            return HttpResponse.status(HttpStatus.FORBIDDEN);
        }
        byte[] db = state.loadDatabase();
        return db == null ? HttpResponse.notFound() : HttpResponse.ok(db);
    }

    /**
     * Saves the database. Returns 403 if the token is missing or invalid.
     */
    @Put(uri = "/db", consumes = MediaType.ALL)
    HttpResponse<?> putDatabase(@Nullable @Header(AUTH_TOKEN_HEADER) String token, @Nullable @Body byte[] db)
            throws IOException {
        if (!state.takeToken(token)) {
            return HttpResponse.status(HttpStatus.FORBIDDEN);
        }
        state.saveDatabase(db == null ? EMPTY : db);
        return HttpResponse.ok();
    }
}
