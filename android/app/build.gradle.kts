plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.pulse.proxy"
    compileSdk = 35
    lint {
        disable = "ExpiredTargetSdkVersion"
        checkReleaseBuilds = false
    }
    defaultConfig {
        applicationId = "com.pulse.proxy"
        minSdk = 21
        targetSdk = 28
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("debug")
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
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
        compose = true
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs(
                "src/main/jniLibs",
                layout.buildDirectory.dir("generated/vlessJniLibs")
            )
            assets.srcDirs("src/main/assets", "src/main/jniLibs")
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += "**/*.so"
            keepDebugSymbols += "**/vless_proxy"
        }
    }
}

val prepareVlessProxyJniLibs by tasks.registering(Copy::class) {
    from("src/main/jniLibs") {
        include("**/vless_proxy")
        eachFile {
            name = "libvless_proxy.so"
        }
    }
    includeEmptyDirs = false
    into(layout.buildDirectory.dir("generated/vlessJniLibs"))
}

tasks.named("preBuild") {
    dependsOn(prepareVlessProxyJniLibs)
}

// Disable stripReleaseDebugSymbols to avoid WSL1 memory issues
tasks.configureEach {
    if (name.contains("strip") && name.contains("Debug")) {
        enabled = false
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.datastore)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
}
