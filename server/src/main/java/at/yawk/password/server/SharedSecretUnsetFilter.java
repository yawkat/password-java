package at.yawk.password.server;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.FilterMatcher;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import java.io.IOException;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Rejects requests to routes annotated with {@link Required} with 403 once the shared secret is set, before their
 * body is read. See {@link ChallengeTokenFilter} for why this is a filter. The controller repeats the check atomically
 * with setting the secret.
 *
 * @author yawkat
 */
@ServerFilter(ServerFilter.MATCH_ALL_PATTERN)
@SharedSecretUnsetFilter.Required
class SharedSecretUnsetFilter {
    private final DatabaseState state;

    SharedSecretUnsetFilter(DatabaseState state) {
        this.state = state;
    }

    @RequestFilter
    @ExecuteOn(TaskExecutors.BLOCKING) // reads the shared secret file
    @Nullable
    HttpResponse<?> filter(HttpRequest<?> request) throws IOException {
        if (!ChallengeTokenFilter.appliesTo(request, Required.class)) {
            return null;
        }
        return state.isSharedSecretSet() ? HttpResponse.status(HttpStatus.FORBIDDEN) : null;
    }

    /**
     * Marks routes that are only allowed while no shared secret is set.
     */
    @FilterMatcher
    @Documented
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE, ElementType.METHOD })
    @interface Required {
    }
}
