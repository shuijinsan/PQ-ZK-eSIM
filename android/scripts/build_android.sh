#!/bin/bash
echo "=== 构建 Android PQ-ZK-eSIM Demo ==="
./gradlew assembleRelease
echo "构建完成！APK 位于 app/build/outputs/apk/release/"
