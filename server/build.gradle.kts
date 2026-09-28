plugins {
    alias(libs.plugins.micronaut.application)
    `java-test-fixtures`
}

micronaut {
    version = libs.versions.micronaut.platform.get()
    runtime("netty")
    testRuntime("none")
    processing {
        incremental(true)
        annotations("at.yawk.password.server.*")
    }
}

// Deployed as the application plugin's distribution (installDist: lib/*.jar plus start scripts) rather than a fat
// jar, since Micronaut doesn't support shading well.
application {
    mainClass = "at.yawk.password.server.DatabaseServer"
}

// the Argon2id script of hash-wasm, copied out of its webjar into the resources of the web client (web/)
val hashWasm by configurations.creating {
    isCanBeConsumed = false
    isTransitive = false
}

dependencies {
    hashWasm(libs.hash.wasm)
    api(project(":shared"))
    implementation(libs.jopt.simple)
    // JSON for Micronaut's default error responses
    runtimeOnly(libs.micronaut.serde.jackson)
    runtimeOnly(libs.logback.classic)

    // TestServer, which the server and client tests use to run the real server on a random port
    testFixturesApi(libs.micronaut.http.server)
    testImplementation(libs.micronaut.http.client)
}

tasks.processResources {
    from({ hashWasm.map { zipTree(it) } }) {
        include("META-INF/resources/webjars/hash-wasm/*/dist/argon2.umd.min.js")
        include("META-INF/resources/webjars/hash-wasm/*/LICENSE")
        eachFile {
            // everything in web/ is served, so keep the license out of it
            path = if (name == "LICENSE") "META-INF/licenses/hash-wasm/LICENSE" else "web/argon2.js"
        }
        includeEmptyDirs = false
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 25
}
