plugins {
    id("com.android.library")
}

android {
    namespace = "com.mqvpn.sdk.native_"
    compileSdk = 37
    // Pin the NDK used for the JNI wrapper build. Without this, AGP falls
    // back to its bundled default, which breaks environments that provision
    // a specific NDK via ndk.dir (e.g. the F-Droid buildserver). Keep in
    // sync with `ndk:` in fdroiddata's metadata/com.mqvpn.app.yml.
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        externalNativeBuild {
            cmake {
                // Reproducible-build hygiene for the JNI wrapper: strip the
                // checkout path from __FILE__/debug info, and drop the linker
                // build-id (it hashes pre-strip debug info, which embeds
                // paths). Together with the -ffile-prefix-map flags in
                // scripts/build_android.sh this makes the APK byte-identical
                // across build directories.
                cFlags("-ffile-prefix-map=${rootProject.projectDir.parentFile}=/mqvpn")
                arguments("-DCMAKE_SHARED_LINKER_FLAGS=-Wl,--build-id=none")
            }
        }

        ndk {
            // Only ABIs with prebuilt .a files (build_android.sh output)
            abiFilters += listOf("arm64-v8a")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/jni/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
