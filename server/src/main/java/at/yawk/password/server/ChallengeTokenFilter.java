package at.yawk.password.server;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.FilterMatcher;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.web.router.RouteAttributes;
import java.lang.annotation.Annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Checks and consumes the {@code X-Auth-Token} challenge token of routes annotated with {@link Required}.
 *
 * <p>This runs as a filter because filters run before the body is bound. With the check in the controller, the
 * {@code @Body byte[]} of an unauthenticated request would be buffered before it is rejected. A rejected request's
 * body is never read.
 *
 * <p>The filter is matched to routes by annotation, not by path, so it applies to exactly the annotated controller
 * methods.
 *
 * @author yawkat
 */
@ServerFilter(ServerFilter.MATCH_ALL_PATTERN)
@ChallengeTokenFilter.Required
class ChallengeTokenFilter {
    private static final String AUTH_TOKEN_HEADER = "X-Auth-Token";
    private static final String AUTHENTICATED_ATTRIBUTE = ChallengeTokenFilter.class.getName() + ".authenticated";

    private final DatabaseState state;

    ChallengeTokenFilter(DatabaseState state) {
        this.state = state;
    }

    @RequestFilter
    @Nullable
    HttpResponse<?> filter(HttpRequest<?> request) {
        if (!appliesTo(request, Required.class)) {
            return null;
        }
        // consumes the token, so it can only be used once. Only this filter consumes tokens.
        if (!state.takeToken(request.getHeaders().get(AUTH_TOKEN_HEADER))) {
            return HttpResponse.status(HttpStatus.FORBIDDEN);
        }
        request.setAttribute(AUTHENTICATED_ATTRIBUTE, true);
        return null; // continue
    }

    /**
     * Whether {@code request} was routed to a method annotated with {@code annotation}. Micronaut matches filters to
     * {@link FilterMatcher} annotations only when a route matched; otherwise (e.g. an unknown path or method, which
     * then gets a 404 or 405) it applies the filter by its path pattern alone.
     */
    static boolean appliesTo(HttpRequest<?> request, Class<? extends Annotation> annotation) {
        return RouteAttributes.getRouteMatch(request)
                .map(match -> match.getRouteInfo().getAnnotationMetadata().hasStereotype(annotation))
                .orElse(false);
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
