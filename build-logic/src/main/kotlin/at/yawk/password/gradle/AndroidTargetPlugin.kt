package at.yawk.password.gradle

import com.android.build.api.dsl.KotlinMultiplatformAndroidLibraryTarget
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.plugins.ExtensionAware
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.getByType
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

/**
 * Adds the Android target to the Kotlin Multiplatform app (`:app`).
 *
 * This lives in a plugin, instead of `app/build.gradle.kts`, because that script also has to compile when the Android
 * build is disabled and AGP is not on the classpath. The plugin is only on the classpath (and applied) when it is
 * enabled.
 */
class AndroidTargetPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val libs = project.extensions.getByType<VersionCatalogsExtension>().named("libs")
        fun version(name: String) = libs.findVersion(name).get().requiredVersion
        fun library(name: String) = libs.findLibrary(name).get()

        project.pluginManager.apply("com.android.kotlin.multiplatform.library")
        // lint for the Android target (the KMP library plugin has none of its own), run by `check`
        project.pluginManager.apply("com.android.lint")

        val kotlin = project.extensions.getByName("kotlin") as ExtensionAware
        kotlin.extensions.configure<KotlinMultiplatformAndroidLibraryTarget>("android") {
            namespace = "at.yawk.password.app"
            compileSdk = version("android-compileSdk").toInt()
            minSdk = version("android-minSdk").toInt()
            buildToolsVersion = version("android-buildTools")
            compilerOptions {
                jvmTarget.set(JvmTarget.JVM_17)
            }
            // JVM unit tests of the Android platform code (src/androidHostTest), run by `check`
            withHostTest {
                // android.util.Log and friends do nothing instead of throwing
                isReturnDefaultValues = true
            }
        }

        project.dependencies.apply {
            add("androidMainImplementation", library("androidx-activity-compose"))
            add("androidMainImplementation", library("kotlinx-coroutines-android"))
            add("androidMainImplementation", library("androidx-camera-camera2"))
            add("androidMainImplementation", library("androidx-camera-lifecycle"))
            add("androidMainImplementation", library("androidx-camera-view"))
            add("androidMainImplementation", library("zxing-core"))
            add("androidHostTestImplementation", "org.jetbrains.kotlin:kotlin-test-junit")
        }
    }
}
