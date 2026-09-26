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

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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

    lint {
        // Also check our code in :app's Android target. NewApi (APIs above minSdk) is an error by default, and errors
        // fail `lint`, which `check` (and so `build`) runs.
        checkDependencies = true
        error += "NewApi"
        abortOnError = true
    }

    // The instrumented tests decrypt the database fixture of :client's tests
    sourceSets.named("androidTest") {
        resources.directories += "../client/src/test/resources"
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

dependencies {
    implementation(project(":app"))
    implementation(libs.androidx.activity.compose)

    androidTestImplementation(project(":client"))
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
}
