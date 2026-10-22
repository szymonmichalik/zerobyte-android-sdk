// The watch and signal WebSockets over OkHttp. A separate artifact, so the
// core library keeps no runtime dependency beyond the Kotlin standard library.
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
    api(project(":zerobyte"))
    api("com.squareup.okhttp3:okhttp:5.5.1")
    testImplementation(kotlin("test-junit5"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "skipped", "failed") }
}

publishing {
    publications {
        create<MavenPublication>("release") {
            artifactId = "zerobyte-okhttp"
            from(components["java"])
            pom {
                name.set("ZeroByte OkHttp")
                description.set("The watch and signal WebSockets of a ZeroByte relay, over OkHttp.")
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
