import java.nio.file.FileSystems
import java.nio.file.Files
import org.jetbrains.compose.desktop.tasks.AbstractJarsFlattenTask
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.compose)
}

kotlin {
    jvm("desktop") {
        compilerOptions {
            jvmTarget = JvmTarget.JVM_17
        }
    }
    // The Android target (#20) is added here as `androidLibrary { ... }`, see the plan.

    sourceSets {
        commonMain.dependencies {
            implementation(libs.compose.runtime)
            implementation(libs.compose.foundation)
            implementation(libs.compose.material3)
            implementation(libs.androidx.lifecycle.viewmodel.compose)
            implementation(libs.kotlinx.coroutines.core)
            // :client is a plain JVM (Java) library. With a single (JVM) target, commonMain is compiled only as part
            // of that target, so this works as is. Once an Android target shares commonMain, it may have to move to
            // the target source sets instead.
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
