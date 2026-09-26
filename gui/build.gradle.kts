plugins {
    alias(libs.plugins.shadow)
}

dependencies {
    implementation(project(":client"))
    implementation(libs.qtjambi)
    runtimeOnly(libs.qtjambi.native.linux.x64)
    runtimeOnly(libs.slf4j.simple)

    testImplementation(testFixtures(project(":client")))
    testImplementation(project(":server"))
    testImplementation(libs.spark.core)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 25
}

tasks.jar {
    manifest {
        attributes(
            "Main-Class" to "at.yawk.password.gui.PasswordGui",
            "Enable-Native-Access" to "ALL-UNNAMED",
        )
    }
}

tasks.shadowJar {
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "include/**")
}

tasks.assemble {
    dependsOn(tasks.shadowJar)
}
