rootProject.name = "password"

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        // Compose Multiplatform depends on androidx artifacts that are only published there
        google()
    }
}

include("shared", "client", "server")

// The desktop app bundles skiko natives for the build platform. -Ppassword.app=false leaves it out, e.g. for the nix
// build on platforms other than x86_64-linux.
if (providers.gradleProperty("password.app").orNull != "false") {
    include("app")
}
