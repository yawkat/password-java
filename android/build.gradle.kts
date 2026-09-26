import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// The Android app: a thin shell around :app's Android target. AGP compiles the Kotlin sources itself (built-in Kotlin);
// the plugin comes from the root project's build classpath and is only there when the Android build is enabled.
plugins {
    id("com.android.application")
    alias(libs.plugins.kotlin.compose)
    // fails `check` if the APKs call platform methods that are missing at minSdk (build-logic/.../ApiLevelCheck.kt)
    id("password.android-api-check")
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

apiLevelCheck {
    // References above minSdk that can't be reached (or work anyway) on older Android versions. Each needs a reason.
    allowed.putAll(
        mapOf(
            // Jackson loads its java.beans support (@ConstructorProperties, @Transient) reflectively and skips it
            // when the classes are missing, as they are on Android
            "java/beans/*" to "Jackson's optional java.beans support, only used when java.beans exists",
            // kotlinx.coroutines and kotlinx.serialization check whether ClassValue works and fall back otherwise
            "java/lang/ClassValue.<init>()V" to "only used when available",
            // declared by StringBuilder itself only since API 37, but inherited from AbstractStringBuilder before
            "java/lang/StringBuilder.getChars(II[CI)V" to "inherited on older versions",
            // the debug agent of kotlinx.coroutines, only loaded as a JVM agent
            "java/lang/instrument/*" to "JVM agent code, never loaded on Android",
            // BouncyCastle's LDAP certificate store; only SCrypt is used
            "javax/naming/*" to "BouncyCastle LDAP support, never used",
        ),
    )
}

dependencies {
    implementation(project(":app"))
    implementation(libs.androidx.activity.compose)
}
