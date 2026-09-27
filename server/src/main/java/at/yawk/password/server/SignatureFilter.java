package at.yawk.password.server;

import at.yawk.password.AuthProtocol;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.FilterMatcher;
import io.micronaut.http.annotation.ServerFilter;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * First half of the request signature check for routes annotated with {@link Required}: everything that doesn't need
 * the body (header syntax, timestamp, replayed nonce, backoff), so that such requests are rejected before their body
 * is read. The signature itself covers the body, so the controller checks it with {@link #verify}.
 *
 * @author yawkat
 */
@ServerFilter(patterns = { "/db", "/db/" })
@SignatureFilter.Required
class SignatureFilter extends RouteAnnotationFilter {
    private static final String HEADER_ATTRIBUTE = SignatureFilter.class.getName() + ".header";

    private final DatabaseState state;

    SignatureFilter(DatabaseState state) {
        super(Required.class);
        this.state = state;
    }

    @Override
    @Nullable
    protected HttpResponse<?> filterRoute(HttpRequest<?> request) {
        DatabaseState.AuthHeader header =
                DatabaseState.parseAuthHeader(request.getHeaders().get(AuthProtocol.AUTH_HEADER));
        HttpResponse<?> rejection = rejection(state, state.preCheck(header));
        if (rejection == null) {
            request.setAttribute(HEADER_ATTRIBUTE, header);
        }
        return rejection;
    }

    /**
     * Verify the signature of a request that this filter accepted.
     *
     * @return The response to reject the request with, or {@code null} if it is authentic. Also rejected if this
     * filter did not run.
     */
    @Nullable
    static HttpResponse<?> verify(DatabaseState state, HttpRequest<?> request, byte[] body) {
        DatabaseState.AuthHeader header =
                request.getAttribute(HEADER_ATTRIBUTE, DatabaseState.AuthHeader.class).orElse(null);
        if (header == null) {
            return HttpResponse.status(HttpStatus.FORBIDDEN);
        }
        return rejection(state, state.verify(header, request.getMethodName(), request.getPath(), body));
    }

    @Nullable
    private static HttpResponse<?> rejection(DatabaseState state, DatabaseState.Verdict verdict) {
        return switch (verdict) {
            case OK -> null;
            case FORBIDDEN -> HttpResponse.status(HttpStatus.FORBIDDEN);
            // the Date header lets the client correct its clock. Set it explicitly, from the clock the check used
            case STALE -> HttpResponse.status(HttpStatus.UNAUTHORIZED).header(HttpHeaders.DATE,
                    DateTimeFormatter.RFC_1123_DATE_TIME.format(
                            Instant.ofEpochMilli(state.clock.getAsLong()).atZone(ZoneOffset.UTC)));
            case BACKOFF -> HttpResponse.status(HttpStatus.TOO_MANY_REQUESTS);
        };
    }

    /**
     * Marks routes that require a signed request.
     */
    @FilterMatcher
    @Documented
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE, ElementType.METHOD })
    @interface Required {
    }
}
