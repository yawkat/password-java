package at.yawk.password.server;

import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.ResponseFilter;
import io.micronaut.http.annotation.ServerFilter;

/**
 * Security headers for the emergency web client, a read-only page that unlocks the database in the browser, for when
 * no device with the app is at hand. Micronaut serves its files from {@code web/} (see {@code application.properties}).
 * The page runs the same protocol as the apps, so the server still never receives the master password, but whoever
 * controls the server could serve a page that sends it elsewhere. See the README.
 *
 * <p>Applies to every response, the API included, where the headers do no harm, so that no path of the page can miss
 * them.
 *
 * @author yawkat
 */
@ServerFilter(ServerFilter.MATCH_ALL_PATTERN)
class WebHeadersFilter {
    /**
     * Only same-origin scripts, styles and requests, plus compiling the Argon2id WebAssembly module.
     */
    static final String CONTENT_SECURITY_POLICY = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; " +
                                                  "style-src 'self'; connect-src 'self'; img-src 'self'; " +
                                                  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    @ResponseFilter
    void addHeaders(MutableHttpResponse<?> response) {
        response.getHeaders()
                .set("Content-Security-Policy", CONTENT_SECURITY_POLICY)
                .set("X-Content-Type-Options", "nosniff")
                .set("Referrer-Policy", "no-referrer")
                .set("Cross-Origin-Opener-Policy", "same-origin")
                .set("X-Robots-Tag", "noindex")
                // always fetch the current version, and keep nothing in the cache of a borrowed device
                .set("Cache-Control", "no-store");
    }
}
