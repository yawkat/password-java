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

    // TestServer, which the client and gui tests use to run the real server on a random port
    testFixturesApi(libs.micronaut.http.server)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 25
}

tasks.shadowJar {
    // Micronaut finds its bean definitions and other services through META-INF/services and
    // META-INF/micronaut/**, so entries from different jars have to be merged instead of overwriting each other
    mergeServiceFiles()
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}
