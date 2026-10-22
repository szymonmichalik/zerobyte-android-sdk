// A plain Kotlin/JVM library: it runs on Android (API 28+, where the platform
// has ChaCha20-Poly1305) and on any JVM 11+, with no runtime dependency
// beyond the Kotlin standard library.
plugins {
    kotlin("jvm")
    `java-library`
    `maven-publish`
}

group = "cloud.zerobyte"
version = "1.1.0"

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
}

dependencies {
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.json:json:20260814")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "skipped", "failed") }
}

publishing {
    publications {
        create<MavenPublication>("release") {
            artifactId = "zerobyte"
            from(components["java"])
            pom {
                name.set("ZeroByte")
                description.set("End-to-end encrypted relay between paired devices (Relay Protocol v1).")
                url.set("https://docs.zerobyte.cloud/sdk/android/")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        id.set("szymonmichalik")
                        name.set("Szymon Michalik")
                        url.set("https://github.com/szymonmichalik")
                    }
                }
                scm {
                    url.set("https://github.com/zerobyte-cloud/zerobyte-android-sdk")
                    connection.set("scm:git:https://github.com/zerobyte-cloud/zerobyte-android-sdk.git")
                    developerConnection.set("scm:git:ssh://git@github.com/zerobyte-cloud/zerobyte-android-sdk.git")
                }
            }
        }
    }
}
