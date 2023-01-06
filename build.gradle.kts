plugins {
    id("java")
    id("com.github.johnrengelman.shadow") version "7.0.0"
    application
    kotlin("jvm") version "1.6.0"
}

group = "net.valdemarf"
version = "1.0"

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(17))
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("junit", "junit", "4.12")
}

application {
    mainClass.set("net.valdemarf.RSA")
}


tasks {
    compileJava {
        options.encoding = Charsets.UTF_8.name() // We want UTF-8 for everything
        options.compilerArgs.add("-deprecation") // Warns for deprecation usage

        // Set the release flag. This configures what version bytecode the compiler will emit, as well as what JDK APIs are usable.
        // See https://openjdk.java.net/jeps/247 for more information.
        options.release.set(17)
    }

    processResources {
        eachFile {
            expand("version" to project.version)
        }
    }

    wrapper<Wrapper>() {
        gradleVersion = "7.3.3"
    }

    application {
        mainClass.set("net.valdemarf.RSA")
    }
}