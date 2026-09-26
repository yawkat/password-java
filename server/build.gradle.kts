plugins {
    alias(libs.plugins.micronaut.application)
    alias(libs.plugins.shadow)
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

application {
    mainClass = "at.yawk.password.server.DatabaseServer"
}

dependencies {
    api(project(":shared"))
    implementation(libs.jopt.simple)
    implementation(libs.expiringmap)
    runtimeOnly(libs.logback.classic)
    // The netty server references io.micronaut.json classes while routing any request, even with no JSON mapper
    // present. This is only the abstraction, no serde or Jackson.
    runtimeOnly(libs.micronaut.json.core)

    // TestServer, which the server and client tests use to run the real server on a random port
    testFixturesApi(libs.micronaut.http.server)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 25
}

tasks.shadowJar {
    // Merge META-INF/services files that several jars provide (e.g. Micronaut's TypeConverterRegistrar) instead
    // of keeping only one. Micronaut 4 bean definitions under META-INF/micronaut/** are one file per bean, so they
    // don't collide and need no merging.
    mergeServiceFiles()
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}
