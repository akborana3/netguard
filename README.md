# NetGuard-like Android Firewall

A production-level Android firewall app using `VpnService` that can fully block internet access per app without root.

## Features
- **VPN Intercept:** Uses Android VPNService to intercept and filter network traffic.
- **Split Tunneling:** Blocked apps have their traffic routed to the VPN interface (where it is dropped and logged). Allowed apps bypass the VPN entirely and connect directly to the internet.
- **Per-App Controls:** Toggle Wi-Fi and Mobile Data access for every installed app.
- **Time-based Rules:** Schedule when an app should have its internet blocked.
- **DNS / Ad Blocking:** Intercepts DNS queries and blocks known ad domains.
- **Traffic Logs:** View a live feed of blocked connections.
- **Modern UI:** Material 3 dashboard, search, and tab navigation.

---

## 🤖 Hugging Face APK Build Instructions

This project includes a fully automated Dockerized build environment specifically designed to be hosted on **Hugging Face Spaces**. It compiles the Android APK and serves it via a built-in HTTP server.

### Step 1: Create a Hugging Face Space
1. Go to [Hugging Face Spaces](https://huggingface.co/spaces) and click **Create new Space**.
2. **Space name:** `android-firewall-build`
3. **License:** MIT (or any)
4. **Select the Space SDK:** Choose **Docker**.
5. **Choose Docker template:** Select **Blank**.
6. Click **Create Space**.

### Step 2: Upload Project Files
Upload the entire contents of this repository to your new Space. You can do this in two ways:
- **Git:** Clone the Hugging Face repository and push the files via command line.
- **UI:** Click on the **Files** tab in your Space, click **Add file**, and drag-and-drop the files (maintain the folder structure).

### Step 3: Trigger the Build
Once the files are uploaded, Hugging Face will automatically detect the `Dockerfile` and begin building the environment.
- The build process will download the Android SDK, install Gradle, and compile the APK.
- You can watch the progress in the **Logs** tab of your Space.
- **Note:** The build may take several minutes to complete.

### Step 4: Download the APK
Once the build is complete, the `build_apk.sh` script will automatically start a Python HTTP server on port 7860.
1. The Hugging Face Space will transition to the **Running** state.
2. In the "App" tab of your Space, you will see a directory listing.
3. Click on **app-debug.apk** to download the compiled application directly to your device or computer.
