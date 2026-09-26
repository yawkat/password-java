rootProject.name = "password"

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        // Compose Multiplatform depends on androidx artifacts that are only published there
        google {
            content {
                includeGroupByRegex("androidx\\..*")
                // the Android build: AGP resolves its tools (aapt2, R8, ...) through the project repositories
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
            }
        }
    }
}

include("shared", "client", "server")

// The desktop app bundles skiko natives for the build platform. -Ppassword.app=false leaves it out, e.g. for the nix
// build on platforms other than x86_64-linux.
if (providers.gradleProperty("password.app").orNull != "false") {
    include("app")

    // The Android app (and the Android target of :app) need the Android SDK. -Ppassword.android=false leaves them out,
    // e.g. for the nix build.
    if (providers.gradleProperty("password.android").orNull != "false") {
        include("android")
        // AGP and the plugin adding the Android target to :app, see build.gradle.kts
        includeBuild("build-logic")
    }
}
