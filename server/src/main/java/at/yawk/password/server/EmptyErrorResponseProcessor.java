package at.yawk.password.server;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.server.exceptions.response.ErrorContext;
import io.micronaut.http.server.exceptions.response.ErrorResponseProcessor;
import jakarta.inject.Singleton;

/**
 * Sends error responses (unknown routes, oversized bodies, internal errors) with just the status and no body. The
 * default processor renders JSON or HTML error bodies, which would need a JSON module, and the client never reads
 * error bodies anyway.
 *
 * @author yawkat
 */
@Singleton
@Replaces(ErrorResponseProcessor.class)
class EmptyErrorResponseProcessor implements ErrorResponseProcessor<Object> {
    @SuppressWarnings("unchecked")
    @Override
    public MutableHttpResponse<Object> processResponse(ErrorContext errorContext, MutableHttpResponse<?> baseResponse) {
        return (MutableHttpResponse<Object>) baseResponse;
    }
}
