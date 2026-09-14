@file:Suppress("UnstableApiUsage", "UseVersionCatalog")
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.ksp.plugin)
}

android {
    namespace = "com.yourcompany.pqzkesim"
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/java")
        }
    }
    compileSdk = 34

    ndkVersion = "26.3.11579264"

    defaultConfig {
        applicationId = "com.yourcompany.pqzkesim"
        minSdk = 28
        targetSdk = 34
        versionCode = 2
        versionName = "2.0"

        externalNativeBuild {
            cmake {
                cppFlags += ""
                abiFilters += "arm64-v8a"
                // 强制链接 C++ 共享库
                arguments("-DANDROID_STL=c++_shared")
            }
        }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // ========== 新增：安全权限配置（生物识别 + StrongBox 硬件安全） ==========
        manifestPlaceholders["android.permission.USE_BIOMETRIC"] = "true"
        manifestPlaceholders["android.permission.USE_STRONGBOX"] = "true"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    // ========== 新增：证书资源配置（GSMA 证书存放目录） ==========
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/java")
            // 固定资源目录，兼容证书/布局/图片
            res.srcDirs("src/main/res")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }

    buildFeatures {
        // ✅ 必须显式开启，否则项目里找不到 BuildConfig 类
        buildConfig = true
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    implementation("com.google.android.material:material:1.9.0")

    // ==================== 网络请求 ====================
    // OkHttp 网络请求库（用于身份认证、服务器通信）
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // ==================== 生物特征/安全认证 ====================
    // 系统生物识别（指纹/人脸，用于TEE模拟、身份认证）
    implementation("androidx.biometric:biometric:1.2.0-alpha05")

    // ==================== 协程 & 异步任务 ====================
    // Kotlin 协程（异步处理网络、认证流程）
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1")

    // ==================== 生命周期 & 组件支持 ====================
    // 生命周期感知（页面状态管理、数据存活）
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-livedata-ktx:2.8.7")
    // Java8 特性支持（配合OpenCV、生命周期使用）
    implementation("androidx.lifecycle:lifecycle-common-java8:2.6.1")

    // ==================== MVVM 架构组件 ====================
    // Room 数据库（认证日志持久化）
    val roomVersion = "2.8.4"
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion")
    // DataStore Preferences（替代 SharedPreferences）
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    // Navigation Component（底部导航 + Fragment 管理）
    val navVersion = "2.7.7"
    implementation("androidx.navigation:navigation-fragment-ktx:$navVersion")
    implementation("androidx.navigation:navigation-ui-ktx:$navVersion")

    // ==================== OpenCV 视觉相关 ====================
    // 本地 libs 目录依赖（jar/aar）
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar", "*.aar"))))
    //  OpenCV 计算机视觉库（本地模块）
    implementation(project(":opencv"))

    // ==================== UI 界面与布局组件 ====================
    // Material Design 官方组件库（含底部导航、按钮、卡片、弹窗等）
    implementation("com.google.android.material:material:1.9.0")
    // 卡片布局（圆角/阴影效果，material已包含，保留兼容）
    implementation("androidx.cardview:cardview:1.0.0")

    // ==================== 图片裁剪（头像） ====================
    implementation("com.github.yalantis:ucrop:2.2.8")

    // ==================== 页面导航（Fragment 路由） ====================
    // Navigation 页面导航管理（底部导航切换页面）
    implementation("androidx.navigation:navigation-fragment-ktx:2.7.7")
    implementation("androidx.navigation:navigation-ui-ktx:2.7.7")
}