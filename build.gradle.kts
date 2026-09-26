buildscript {
    // The Android Gradle Plugin is only put on the build classpath when the Android build is enabled, so that
    // -Ppassword.android=false (the nix build) neither needs an Android SDK nor resolves any AGP artifacts. The plugins
    // block below is unconditional, so AGP can't go there. It is added here rather than in :app or :android because AGP
    // must be loaded once, by a class loader shared by all projects using it; subprojects inherit this one.
    //
    // AGP comes in as a dependency of the included build-logic build (see settings.gradle.kts), which holds the typed
    // configuration of :app's Android target. The conditions must match those of settings.gradle.kts: the Android
    // build needs the app.
    if (providers.gradleProperty("password.app").orNull != "false" &&
        providers.gradleProperty("password.android").orNull != "false"
    ) {
        repositories {
            google {
                content {
                    includeGroupByRegex("com\\.android.*")
                    includeGroupByRegex("com\\.google.*")
                    includeGroupByRegex("androidx\\..*")
                }
            }
            mavenCentral()
        }
        dependencies {
            classpath("at.yawk.password.gradle:build-logic")
        }
    }
}

plugins {
    alias(libs.plugins.lombok) apply false
    alias(libs.plugins.micronaut.application) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.compose) apply false
}

subprojects {
    group = "at.yawk.password"

    // the Kotlin Multiplatform app and the Android app configure themselves
    if (name == "app" || name == "android") {
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
