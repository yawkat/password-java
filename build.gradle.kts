plugins {
    alias(libs.plugins.lombok) apply false
    alias(libs.plugins.micronaut.application) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.compose) apply false
}

subprojects {
    group = "at.yawk.password"

    // the Kotlin Multiplatform app configures itself
    if (name == "app") {
        return@subprojects
    }

    apply(plugin = "java-library")
    apply(plugin = "io.freefair.lombok")

    val libs = rootProject.libs
    extensions.configure<io.freefair.gradle.plugins.lombok.LombokExtension> {
        version = libs.versions.lombok
    }

    dependencies {
        "compileOnly"(libs.jetbrains.annotations)
        "testCompileOnly"(libs.jetbrains.annotations)
        "api"(libs.slf4j.api)
        "testImplementation"(libs.testng)
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
    }

    tasks.withType<Test>().configureEach {
        useTestNG()
    }
}
