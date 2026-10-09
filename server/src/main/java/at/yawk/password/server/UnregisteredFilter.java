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
 * Rejects requests to routes annotated with {@link Required} with 403 once their vault is registered, before their
 * body is read. The controller repeats the check atomically with registering.
 *
 * @author yawkat
 */
@ServerFilter(patterns = { "/register", "/register/", "/totp/register", "/totp/register/" })
@UnregisteredFilter.Required
class UnregisteredFilter extends RouteAnnotationFilter {
    private final Vaults vaults;

    UnregisteredFilter(Vaults vaults) {
        super(Required.class);
        this.vaults = vaults;
    }

    @Override
    @Nullable
    protected HttpResponse<?> filterRoute(HttpRequest<?> request) {
        return vaults.forPath(request.getPath()).isRegistered() ? HttpResponse.status(HttpStatus.FORBIDDEN) : null;
    }

    /**
     * Marks routes that are only allowed while the server is not registered.
     */
    @FilterMatcher
    @Documented
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE, ElementType.METHOD })
    @interface Required {
    }
}
