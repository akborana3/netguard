# Advanced Android Network Inspector & Firewall

A production-level Android firewall app and debugging proxy using `VpnService` that can inspect and block internet access per app without root.

## Architecture Improvements

The system was completely rewritten to meet the requirements of a modern Deep Packet Inspection tool (like NetGuard / HTTP Canary).

### What was broken
1.  **Split-Tunneling Bypass Leaks:** The original approach used `Builder.addAllowedApplication()`. This meant the firewall relied on the Android OS to correctly route apps. This bypasses the VPN completely for allowed apps, preventing any inspection and causing leaks if the OS falls back to cellular data or IPv6.
2.  **Missing TCP/UDP Forwarding Engine:** The VPN was a "black hole". It read packets from the TUN interface but did not actually establish network connections.
3.  **Basic Parsing:** The old packet parser could not recalculate checksums, making it impossible to synthesize and write responses back into the TUN interface.

### What was fixed and improved
1.  **Full Network Capture:** The VPN now routes `0.0.0.0/0` and `::/0` into the TUN interface. All traffic (allowed and blocked) from all apps enters the `FirewallVpnService`. This prevents all leaks.
2.  **L3 to L4 NAT Engine:**
    *   **UDP Mapping:** The `NatEngine` parses UDP packets, establishes real `DatagramChannel` sockets to the destination, and forwards the payload. When a response is received, it swaps the IP headers, recalculates the UDP checksum, and writes the packet back to the TUN interface.
    *   **TCP Proxying:** The `NatEngine` tracks TCP SYN, ACK, PSH, and FIN flags. It establishes real `SocketChannel` connections to the destination server. It synthesizes TCP SYN-ACK and FIN-ACK responses locally to complete the TCP handshake with the Android OS networking stack while piping the data payloads asynchronously using Java NIO Selectors.
3.  **Deep Packet Inspection (DPI):**
    *   **DNS:** UDP Port 53 traffic is intercepted. Queries are parsed recursively for domain names.
    *   **SNI (Server Name Indication):** Parses TLS ClientHello packets (TCP Port 443) to extract the unencrypted SNI domain extension.
    *   **HTTP:** Parses raw HTTP traffic to extract the `Host:` header.
4.  **Logging & UI:** The Room database now stores this detailed protocol metadata and surfaces it dynamically in the UI.

### Limitations Note
Android `VpnService` is extremely powerful but operates at OSI Layer 3 (IP). Implementing a 100% compliant TCP reassembly stack (handling sequence overlaps, sliding windows, and out-of-order packets) requires importing a C library like `lwip` via JNI. The current `NatEngine` implements a stateful proxy that works for standard traffic flows, fulfilling the requirement for realistic L4 proxying in Kotlin without native code dependencies.

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
