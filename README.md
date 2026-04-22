# netguard
You are a senior Android systems engineer and networking expert.

I want you to build a production-level Android firewall app (like NetGuard) using VPNService that can fully block internet access per app WITHOUT root.

⚠️ This is for PERSONAL USE, so you can request and use ANY required permissions and advanced techniques.

---

🎯 CORE REQUIREMENTS

Build a complete Android app with:

🔐 Core Functionality

1. Use Android VPNService to intercept ALL network traffic
2. Implement per-app internet blocking using UID detection
3. Support:
   - Block selected apps
   - Allow selected apps (block all others)
4. Real packet filtering (not fake blocking)
5. Handle:
   - TCP
   - UDP
   - DNS

---

🧠 Advanced Features (ALL REQUIRED)

1. 📱 App List UI
   
   - Show all installed apps
   - Toggle internet access per app

2. 🌐 Network Type Control
   
   - Separate toggles for:
     - WiFi
     - Mobile Data

3. 📊 Traffic Logs
   
   - Show blocked & allowed connections
   - App name + IP + time

4. 🚫 DNS / Ad Blocking
   
   - Custom DNS filtering
   - Block known ad domains

5. ⏱ Time-based Rules
   
   - Schedule internet blocking

6. 🔄 Persistent Background Service
   
   - Foreground service with notification
   - Auto restart VPN if killed

---

🎨 UI REQUIREMENTS

- Use Material 3 (modern UI)
- Clean dashboard:
  - Start/Stop Firewall button
  - Stats (blocked requests count)
- App list with search + filters
- Dark mode support

---

🏗️ ARCHITECTURE

Use clean architecture:

- Language: Kotlin
- MVVM pattern
- Components:
  - ViewModel
  - Repository
  - Service layer (VPN)
  - Room Database

---

⚙️ TECH IMPLEMENTATION DETAILS

You MUST implement:

1. VPN Core

- VpnService.Builder setup
- TUN interface handling
- Packet read/write loop

2. Packet Parsing

- Parse IP packets manually
- Detect protocol (TCP/UDP)
- Extract source app UID

3. App Identification

- Map packets → UID → package name

4. Filtering Engine

- Rule-based filtering system:
  IF app is blocked → DROP packet
  ELSE → FORWARD packet

5. DNS Blocking

- Intercept DNS queries
- Block domains using blacklist

---

📂 OUTPUT FORMAT (VERY IMPORTANT)

You MUST provide FULL PROJECT STRUCTURE:

1. Complete folder structure
2. Every file with full code:
   - MainActivity.kt
   - VpnService class
   - Packet parser classes
   - UI files
   - Database
   - Utils
3. Gradle files
4. AndroidManifest.xml (with ALL permissions)

DO NOT skip ANY file.

---

🤖 HUGGING FACE APK BUILD (IMPORTANT)

I only have Hugging Face (no VPS).

So also include:

1. Dockerfile for building APK

- Install Android SDK
- Gradle build setup

2. Build Script

- Command to generate APK

3. Instructions:

- How to upload project to Hugging Face Space
- How to trigger APK build
- Where APK will be stored

---

⚠️ CONSTRAINTS

- Do NOT give pseudo code
- Do NOT skip packet parsing
- Do NOT simplify logic
- Code must be realistic and runnable

---

🎯 GOAL

Output should be equivalent to a real GitHub project like NetGuard but simplified enough to understand.

---

Now generate the COMPLETE project.
