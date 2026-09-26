package at.yawk.password.server;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.FilterMatcher;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.web.router.RouteAttributes;
import java.io.IOException;
import java.lang.annotation.Annotation;

/**
 * Base class for filters that apply to the controller methods annotated with a {@link FilterMatcher} annotation.
 *
 * <p>Filters run after routing but before the body is bound, so they can reject a request without reading its body.
 *
 * <p>Micronaut only honors the {@link FilterMatcher} annotation when a route matched. Otherwise, e.g. for an unknown
 * method that will get a 405, it applies the filter by its path patterns alone. So {@link #filter} also checks the
 * matched route's annotation, and {@link #filterRoute} only sees requests routed to an annotated method. Subclasses
 * should still restrict their {@code @ServerFilter} patterns to the annotated paths.
 *
 * @author yawkat
 */
abstract class RouteAnnotationFilter {
    private final Class<? extends Annotation> annotation;

    RouteAnnotationFilter(Class<? extends Annotation> annotation) {
        this.annotation = annotation;
    }

    @RequestFilter
    @ExecuteOn(TaskExecutors.BLOCKING) // subclasses may do blocking IO, like the controller
    @Nullable
    public final HttpResponse<?> filter(HttpRequest<?> request) throws IOException {
        boolean routedToAnnotated = RouteAttributes.getRouteMatch(request)
                .map(match -> match.getRouteInfo().getAnnotationMetadata().hasStereotype(annotation))
                .orElse(false);
        return routedToAnnotated ? filterRoute(request) : null;
    }

    /**
     * Filter a request routed to an annotated method.
     *
     * @return A response to reject the request with, or {@code null} to continue.
     */
    @Nullable
    protected abstract HttpResponse<?> filterRoute(HttpRequest<?> request) throws IOException;
}
