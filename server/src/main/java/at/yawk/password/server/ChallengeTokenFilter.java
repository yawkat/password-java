package at.yawk.password.server;

import io.micronaut.core.annotation.Nullable;
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

/**
 * Checks and consumes the {@code X-Auth-Token} challenge token of routes annotated with {@link Required}, before the
 * body is read. With the check in the controller, the {@code @Body byte[]} of an unauthenticated request would be
 * buffered before it is rejected.
 *
 * @author yawkat
 */
@ServerFilter(patterns = { "/db", "/db/" })
@ChallengeTokenFilter.Required
class ChallengeTokenFilter extends RouteAnnotationFilter {
    private static final String AUTH_TOKEN_HEADER = "X-Auth-Token";
    private static final String AUTHENTICATED_ATTRIBUTE = ChallengeTokenFilter.class.getName() + ".authenticated";

    private final DatabaseState state;

    ChallengeTokenFilter(DatabaseState state) {
        super(Required.class);
        this.state = state;
    }

    @Override
    @Nullable
    protected HttpResponse<?> filterRoute(HttpRequest<?> request) {
        // consumes the token, so it can only be used once. Only this filter consumes tokens.
        if (!state.takeToken(request.getHeaders().get(AUTH_TOKEN_HEADER))) {
            return HttpResponse.status(HttpStatus.FORBIDDEN);
        }
        request.setAttribute(AUTHENTICATED_ATTRIBUTE, true);
        return null; // continue
    }

    /**
     * Whether this filter accepted the request. Controllers use this as a safeguard against the filter not running.
     */
    static boolean isAuthenticated(HttpRequest<?> request) {
        return request.getAttribute(AUTHENTICATED_ATTRIBUTE, Boolean.class).orElse(false);
    }

    /**
     * Marks routes that require a valid challenge token.
     */
    @FilterMatcher
    @Documented
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE, ElementType.METHOD })
    @interface Required {
    }
}
