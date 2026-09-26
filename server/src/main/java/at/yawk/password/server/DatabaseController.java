package at.yawk.password.server;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Put;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import java.io.IOException;

/**
 * HTTP API of the database server, see SPEC.md. Request and response bodies are raw bytes.
 *
 * <p>Authorization starts in {@link SignatureFilter} and {@link UnregisteredFilter}, before the body is read. The
 * signature covers the body, so it is verified here.
 *
 * @author yawkat
 */
@Controller
@ExecuteOn(TaskExecutors.BLOCKING) // storage access is blocking file IO, keep it off the event loop
class DatabaseController {
    // An empty request body binds as null. The Micronaut processor warns about @Nullable byte[] ("primitive types"),
    // but the null case is handled. Optional<byte[]> would avoid the warning, but makes Micronaut decode the form
    // content type that HttpURLConnection sends.
    private static final byte[] EMPTY = new byte[0];

    private final DatabaseState state;

    DatabaseController(DatabaseState state) {
        this.state = state;
    }

    /**
     * Returns the version and install salt, or 404 if the server is not registered yet.
     */
    @Get(uri = "/salt", produces = MediaType.APPLICATION_OCTET_STREAM)
    HttpResponse<byte[]> salt() throws IOException {
        byte[] salt = state.getSaltResponse();
        return salt == null ? HttpResponse.notFound() : HttpResponse.ok(salt);
    }

    /**
     * Registers the install salt and public key. Returns 403 if the server is registered already, 400 if the
     * registration is malformed.
     */
    @Put(uri = "/register", consumes = MediaType.ALL)
    @UnregisteredFilter.Required
    HttpResponse<?> register(@Nullable @Body byte[] registration) throws IOException {
        try {
            return state.registerIfUnregistered(registration == null ? EMPTY : registration) ?
                    HttpResponse.ok() : HttpResponse.status(HttpStatus.FORBIDDEN);
        } catch (IllegalArgumentException e) {
            return HttpResponse.badRequest();
        }
    }

    /**
     * Returns the database, 403 if the signature is missing or invalid, or 404 if no database has been saved yet.
     */
    @Get(uri = "/db", produces = MediaType.APPLICATION_OCTET_STREAM)
    @SignatureFilter.Required
    HttpResponse<byte[]> getDatabase(HttpRequest<?> request) throws IOException {
        if (!SignatureFilter.verify(state, request, EMPTY)) {
            return HttpResponse.status(HttpStatus.FORBIDDEN);
        }
        byte[] db = state.loadDatabase();
        return db == null ? HttpResponse.notFound() : HttpResponse.ok(db);
    }

    /**
     * Saves the database. Returns 403 if the signature is missing or invalid, 400 if the body is not a database of
     * this registration.
     */
    @Put(uri = "/db", consumes = MediaType.ALL)
    @SignatureFilter.Required
    HttpResponse<?> putDatabase(HttpRequest<?> request, @Nullable @Body byte[] db) throws IOException {
        byte[] body = db == null ? EMPTY : db;
        if (!SignatureFilter.verify(state, request, body)) {
            return HttpResponse.status(HttpStatus.FORBIDDEN);
        }
        if (!state.isValidDatabase(body)) {
            return HttpResponse.badRequest();
        }
        state.saveDatabase(body);
        return HttpResponse.ok();
    }
}
