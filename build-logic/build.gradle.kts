plugins {
    `kotlin-dsl`
}

group = "at.yawk.password.build"

dependencies {
    // also puts AGP on the main build's classpath, since the root project depends on this build
    implementation(libs.android.gradle.plugin)
}

gradlePlugin {
    plugins {
        register("androidTarget") {
            id = "password.android-target"
            implementationClass = "at.yawk.password.build.AndroidTargetPlugin"
        }
    }
}
