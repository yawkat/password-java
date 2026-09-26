import java.nio.file.FileSystems
import java.nio.file.Files
import org.jetbrains.compose.desktop.tasks.AbstractJarsFlattenTask
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.compose)
}

// The Android target needs the Android SDK and AGP, which the root project only puts on the build classpath when the
// Android build is enabled. This script must also compile without AGP, so it can't refer to AGP's types, and the
// target is added by a plugin from build-logic instead (AndroidTargetPlugin).
if (providers.gradleProperty("password.android").orNull != "false") {
    apply(plugin = "password.android-target")
}

kotlin {
    jvm("desktop") {
        compilerOptions {
            jvmTarget = JvmTarget.JVM_17
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.compose.runtime)
            implementation(libs.compose.foundation)
            implementation(libs.compose.material3)
            implementation(libs.androidx.lifecycle.viewmodel.compose)
            implementation(libs.kotlinx.coroutines.core)
            // :client is a plain JVM (Java) library. That is fine here although commonMain is shared between the
            // desktop and the Android target: both are JVM targets, so Kotlin analyzes their shared code against the
            // JDK and compiles it only as part of each target (compileCommonMainKotlinMetadata is skipped), and
            // JVM-only dependencies work. Adding a non-JVM target would require moving this to the target source sets.
            implementation(project(":client"))
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
        getByName("desktopMain").dependencies {
            implementation(compose.desktop.currentOs)
            implementation(libs.kotlinx.coroutines.swing)
            runtimeOnly(libs.slf4j.simple)
        }
    }
}

dependencies {
    "desktopTestImplementation"(testFixtures(project(":client")))
}

tasks.named<Test>("desktopTest") {
    useTestNG()
    // Dispatchers.Main is the Swing EDT (kotlinx-coroutines-swing), which works without a display
    systemProperty("java.awt.headless", "true")
}

// packageUberJarForCurrentOS (registered by the compose plugin after evaluation)
tasks.withType<AbstractJarsFlattenTask>().configureEach {
    // Signatures of signed dependencies (BouncyCastle) are invalid in the merged jar and make the JVM refuse to
    // start it. The flatten task has no exclude option, so remove them afterwards.
    doLast {
        FileSystems.newFileSystem(flattenedJar.get().asFile.toPath()).use { fs ->
            Files.list(fs.getPath("META-INF")).use { entries ->
                entries.filter { Regex(".*\\.(SF|DSA|RSA|EC)").matches(it.fileName.toString()) }
                    .toList()
                    .forEach(Files::delete)
            }
        }
    }
}

compose.desktop {
    application {
        mainClass = "at.yawk.password.app.MainKt"

        buildTypes.release.proguard {
            isEnabled = false
        }

        nativeDistributions {
            // packageUberJarForCurrentOS writes build/compose/jars/<packageName>-<os>-<arch>-<packageVersion>.jar
            packageName = "password-gui"
            packageVersion = "1.0.0"
        }
    }
}
