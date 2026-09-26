rootProject.name = "password"

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

include("shared", "client", "server", "gui")
