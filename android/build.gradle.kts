import at.yawk.password.build.Java17ApiBackport
import com.android.build.api.instrumentation.InstrumentationScope
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// The Android app: a thin shell around :app's Android target. AGP compiles the Kotlin sources itself (built-in Kotlin);
// the plugin comes from the root project's build classpath and is only there when the Android build is enabled.
plugins {
    id("com.android.application")
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "at.yawk.password.android"
    compileSdk = libs.versions.android.compileSdk.get().toInt()
    buildToolsVersion = libs.versions.android.buildTools.get()

    defaultConfig {
        // the same as the old app (github.com/yawkat/password-android), so it updates in place
        applicationId = "at.yawk.password.android"
        minSdk = libs.versions.android.minSdk.get().toInt()
        targetSdk = libs.versions.android.compileSdk.get().toInt()
        versionCode = 2
        versionName = "2.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // There is no release signing configuration in this repository. Sign the release APK yourself
            // (apksigner), or install the debug build.
        }
    }

    packaging {
        resources {
            // Multi-release jar contents (BouncyCastle, Jackson) and other metadata D8/ART don't use
            excludes += listOf(
                "META-INF/versions/**",
                "META-INF/*.version",
                "META-INF/LICENSE*",
                "META-INF/NOTICE*",
                "META-INF/DEPENDENCIES",
                "META-INF/INDEX.LIST",
            )
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

androidComponents {
    onVariants { variant ->
        // Jackson 3 calls Java 17 methods that only exist since API 34, see Java17ApiBackport
        variant.instrumentation.transformClassesWith(Java17ApiBackport::class.java, InstrumentationScope.ALL) {}
    }
}

dependencies {
    implementation(project(":app"))
    implementation(libs.androidx.activity.compose)
}
