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
 * HTTP API of the database server, see SPEC.md. Request and response bodies are raw bytes. Every route exists for
 * both vaults (see {@link Vaults}), the 2FA vault's below {@code /totp}.
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

    private final Vaults vaults;

    DatabaseController(Vaults vaults) {
        this.vaults = vaults;
    }

    /**
     * Returns the version and install salt, or 404 if the vault is not registered yet.
     */
    @Get(uris = { "/salt", "/totp/salt" }, produces = MediaType.APPLICATION_OCTET_STREAM)
    HttpResponse<byte[]> salt(HttpRequest<?> request) {
        byte[] salt = vaults.forPath(request.getPath()).getSaltResponse();
        return salt == null ? HttpResponse.notFound() : HttpResponse.ok(salt);
    }

    /**
     * Registers the install salt and public key. Returns 403 if the vault is registered already, 400 if the
     * registration is malformed.
     */
    @Put(uris = { "/register", "/totp/register" }, consumes = MediaType.ALL)
    @UnregisteredFilter.Required
    HttpResponse<?> register(HttpRequest<?> request, @Nullable @Body byte[] registration) throws IOException {
        DatabaseState state = vaults.forPath(request.getPath());
        try {
            return state.registerIfUnregistered(registration == null ? EMPTY : registration) ?
                    HttpResponse.ok() : HttpResponse.status(HttpStatus.FORBIDDEN);
        } catch (IllegalArgumentException e) {
            return HttpResponse.badRequest();
        }
    }

    /**
     * Returns the database, 401/403/429 if the request is rejected (see {@link SignatureFilter}), or 404 if no
     * database of this registration has been saved yet.
     */
    @Get(uris = { "/db", "/totp/db" }, produces = MediaType.APPLICATION_OCTET_STREAM)
    @SignatureFilter.Required
    @SuppressWarnings("unchecked")
    HttpResponse<byte[]> getDatabase(HttpRequest<?> request) throws IOException {
        DatabaseState state = vaults.forPath(request.getPath());
        HttpResponse<?> rejection = SignatureFilter.verify(state, request, EMPTY);
        if (rejection != null) {
            return (HttpResponse<byte[]>) rejection;
        }
        byte[] db = state.loadDatabase();
        return db == null ? HttpResponse.notFound() : HttpResponse.ok(db);
    }

    /**
     * Saves the database. Returns 401/403/429 if the request is rejected (see {@link SignatureFilter}), 400 if the body
     * is not a database of this registration.
     */
    @Put(uris = { "/db", "/totp/db" }, consumes = MediaType.ALL)
    @SignatureFilter.Required
    HttpResponse<?> putDatabase(HttpRequest<?> request, @Nullable @Body byte[] db) throws IOException {
        DatabaseState state = vaults.forPath(request.getPath());
        byte[] body = db == null ? EMPTY : db;
        HttpResponse<?> rejection = SignatureFilter.verify(state, request, body);
        if (rejection != null) {
            return rejection;
        }
        if (!state.isValidDatabase(body)) {
            return HttpResponse.badRequest();
        }
        state.saveDatabase(body);
        return HttpResponse.ok();
    }
}
