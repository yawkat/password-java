package at.yawk.password.server;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Map;

/**
 * Serves the emergency web client (resources under {@code web/}): a read-only page that unlocks the database in the
 * browser, for when no device with the app is at hand. It runs the same protocol as the apps, so the server still
 * never receives the master password, but whoever controls the server could serve a page that sends it elsewhere.
 * See the README.
 *
 * @author yawkat
 */
@Controller
class WebController {
    /**
     * Only same-origin scripts, styles and requests, plus compiling the Argon2id WebAssembly module.
     */
    static final String CONTENT_SECURITY_POLICY = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; " +
                                                  "style-src 'self'; connect-src 'self'; img-src 'self'; " +
                                                  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    private static final MediaType JAVASCRIPT = MediaType.of("text/javascript;charset=utf-8");

    private final byte[] index = load("index.html");
    /**
     * The files below {@code /web/}.
     */
    private final Map<String, Asset> assets = Map.of(
            "app.js", new Asset(load("app.js"), JAVASCRIPT),
            "app.css", new Asset(load("app.css"), MediaType.of("text/css;charset=utf-8")),
            // copied from the hash-wasm webjar by the build
            "argon2.js", new Asset(load("argon2.js"), JAVASCRIPT)
    );

    private record Asset(byte[] content, MediaType type) {
    }

    private static byte[] load(String name) {
        try (InputStream in = WebController.class.getClassLoader().getResourceAsStream("web/" + name)) {
            if (in == null) {
                throw new IllegalStateException("Missing resource web/" + name);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Get(uri = "/")
    HttpResponse<byte[]> index() {
        return respond(index, MediaType.of("text/html;charset=utf-8"));
    }

    @Get(uri = "/web/{name}")
    HttpResponse<byte[]> asset(@PathVariable String name) {
        Asset asset = assets.get(name);
        return asset == null ? HttpResponse.notFound() : respond(asset.content(), asset.type());
    }

    private static HttpResponse<byte[]> respond(byte[] content, MediaType type) {
        return HttpResponse.ok(content)
                .contentType(type)
                .header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
                .header("X-Content-Type-Options", "nosniff")
                .header("Referrer-Policy", "no-referrer")
                .header("Cross-Origin-Opener-Policy", "same-origin")
                .header("X-Robots-Tag", "noindex")
                // always fetch the current version, and keep nothing in the cache of a borrowed device
                .header("Cache-Control", "no-store");
    }
}
