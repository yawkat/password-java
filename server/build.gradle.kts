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

dependencies {
    api(project(":shared"))
    implementation(libs.jopt.simple)
    implementation(libs.expiringmap)
    // JSON for Micronaut's default error responses
    runtimeOnly(libs.micronaut.serde.jackson)
    runtimeOnly(libs.logback.classic)

    // TestServer, which the server and client tests use to run the real server on a random port
    testFixturesApi(libs.micronaut.http.server)
    testImplementation(libs.micronaut.http.client)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 25
}
