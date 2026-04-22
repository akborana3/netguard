#!/bin/bash
set -e

echo "Building APK..."

# Ensure gradle wrapper exists, or generate it
if [ ! -f "gradlew" ]; then
    gradle wrapper
fi

chmod +x gradlew
./gradlew assembleDebug

echo "Build complete. APK is located at:"
find app/build/outputs/apk -name "*.apk"

echo "Starting HTTP server on port 7860 to serve the APK..."
cd app/build/outputs/apk/debug
python3 -m http.server 7860
