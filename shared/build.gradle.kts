dependencies {
    api(libs.jackson.databind)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 17
}
