package at.yawk.password.server;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import java.io.IOException;

/**
 * Rejects unauthorized requests before their body is read. {@code @Body byte[]} buffers the whole body before the
 * controller runs, so if the controller checked the token, any unauthenticated client could make the server buffer
 * up to the request size limit per connection.
 *
 * <p>A rejected request's body is never read. Micronaut discards it, or closes the connection.
 *
 * @author yawkat
 */
@ServerFilter(patterns = { "/db", "/shared-secret" }, methods = { HttpMethod.GET, HttpMethod.PUT })
class AuthFilter {
    /**
     * Request attribute that marks a {@code /db} request whose token this filter has consumed.
     */
    static final String AUTHENTICATED_ATTRIBUTE = "at.yawk.password.server.authenticated";

    private static final String AUTH_TOKEN_HEADER = "X-Auth-Token";

    private final DatabaseState state;

    AuthFilter(DatabaseState state) {
        this.state = state;
    }

    @RequestFilter
    @ExecuteOn(TaskExecutors.BLOCKING) // checking the shared secret reads a file
    @Nullable
    HttpResponse<?> filter(HttpRequest<?> request) throws IOException {
        switch (request.getPath()) {
            case "/db" -> {
                // the token is consumed here, exactly once; the controller only checks the attribute
                if (!state.takeToken(request.getHeaders().get(AUTH_TOKEN_HEADER))) {
                    return HttpResponse.status(HttpStatus.FORBIDDEN);
                }
                request.setAttribute(AUTHENTICATED_ATTRIBUTE, true);
            }
            case "/shared-secret" -> {
                // fast path; the controller repeats the check atomically with the save
                if (request.getMethod() == HttpMethod.PUT && state.isSharedSecretSet()) {
                    return HttpResponse.status(HttpStatus.FORBIDDEN);
                }
            }
            default -> {
            }
        }
        return null; // continue
    }

    static boolean isAuthenticated(HttpRequest<?> request) {
        return request.getAttribute(AUTHENTICATED_ATTRIBUTE, Boolean.class).orElse(false);
    }
}
