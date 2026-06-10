plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.admirepowered.pulse"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.admirepowered.pulse"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
        jniLibs.keepDebugSymbols += "**/libpulsecore.so"
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

val cleanReleaseArtProfileOutputs by tasks.registering {
    doLast {
        delete(
            layout.buildDirectory.dir("intermediates/dex_metadata_directory/release").get().asFile,
            layout.buildDirectory.dir("outputs/apk/release/baselineProfiles").get().asFile,
        )
    }
}

tasks.configureEach {
    if (
        name == "mergeReleaseArtProfile" ||
        name == "compileReleaseArtProfile" ||
        name == "mergeReleaseStartupProfile" ||
        name == "stripReleaseDebugSymbols"
    ) {
        enabled = false
    }
}

tasks.matching { it.name == "assembleRelease" }.configureEach {
    finalizedBy(cleanReleaseArtProfileOutputs)
}
