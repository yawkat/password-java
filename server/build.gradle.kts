plugins {
    alias(libs.plugins.shadow)
}

dependencies {
    api(project(":shared"))
    implementation(libs.jopt.simple)
    implementation(libs.spark.core)
    implementation(libs.expiringmap)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 25
}

tasks.jar {
    manifest {
        attributes("Main-Class" to "at.yawk.password.server.DatabaseServer")
    }
}

tasks.shadowJar {
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}

tasks.assemble {
    dependsOn(tasks.shadowJar)
}
