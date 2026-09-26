plugins {
    `java-test-fixtures`
}

dependencies {
    api(project(":shared"))
    implementation(libs.bouncycastle.bcprov)

    testFixturesCompileOnly(libs.jetbrains.annotations)

    // Needed for testing
    testImplementation(project(":server"))
    testImplementation(libs.spark.core)
}

// main and testFixtures stay consumable by Android (D8). The tests depend on :server, which targets 25, so they are
// compiled for 25 as well; Gradle derives the requested JVM version of the test classpaths from this setting.
tasks.compileJava {
    options.release = 17
}
tasks.compileTestFixturesJava {
    options.release = 17
}
tasks.compileTestJava {
    options.release = 25
}
