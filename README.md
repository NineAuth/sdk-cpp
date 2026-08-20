﻿<div align="center">
  <img src="https://github.com/Deedzera/NineAuth/blob/main/assets/capa-sdk-cpp.png" alt="NineAuth C++ SDK" width="120" height="120" />
  <br /><br />
  <p><strong>NineAuth C++17 Native SDK &amp; Reference Implementation</strong></p>
  <p>Production-ready native C++ client designed for Windows applications, game loaders, game engines (Unreal Engine), and commercial desktop tools.</p>
  <br />
  <a href="https://nineauth.xyz">Website</a>
  &nbsp;&middot;&nbsp;
  <a href="https://nineauth.xyz/docs">Documentation</a>
  &nbsp;&middot;&nbsp;
  <a href="https://nineauth.xyz/dashboard">Dashboard</a>
</div>

---

## 📋 Overview

The **NineAuth C++ SDK** provides a high-performance, synchronous native client engineered specifically for low-level desktop environments where memory safety, predictable execution, and zero exception overhead are critical.

### Key Capabilities

- ⚡ **Zero Exception Overhead:** Built using a monadic `Result<T>` pattern. 100% compatible with `-fno-exceptions` and `/EHa-` compiler flags.
- 🔒 **Cryptographic Anti-Replay:** Automatically attaches 128-bit cryptographic nonces (`BCryptGenRandom`) and UTC ISO 8601 timestamps to every sensitive payload.
- 💻 **Native HWID Fingerprinting:** Integrated Windows `MachineGuid` SHA-256 hardware identifier without external dependencies.
- 🎟️ **License Engine & Entitlements:** Instant server-side license binding with 0ms in-memory entitlement lookups (`HasEntitlement`).
- 📦 **Static Linking Friendly:** Zero DLL hell — compiles directly into your native `.exe` or `.dll` payload.

---

## 🛠️ Prerequisites & Build Setup

- **Operating System:** Windows 10 / 11 (x64 / x86 / ARM64)
- **Compiler:** Microsoft Visual Studio 2022 (MSVC v143) or Clang-CL with C++17 support
- **Build System:** CMake 3.21+ (included with Visual Studio) or standard `.vcxproj` / `.sln`

---

## 🚀 Quick Start & Building

### Option A: Build via Command Line (CMake)

Open **Developer Command Prompt for VS 2022** and run:

```bat
REM 1. Configure CMake project (automatically resolves dependencies)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

REM 2. Compile static binary
cmake --build build --config Release

REM 3. Run the compiled application
.\build\Release\NineAuthCppExample.exe
```

### Option B: Open in Visual Studio 2022

1. Open `NineAuth-CPP.slnx` (or `NineAuth-CPP-EXAMPLE.vcxproj`) in Visual Studio 2022.
2. Select **Release / x64** configuration.
3. Open `MainWindow.hpp` and set your `APPLICATION_ID`.
4. Press **F5** to build and run.

---

## 💡 Code Recipes & Integration Patterns

### 1. Initialization

Configure client options with your `ApplicationId` from the [NineAuth Dashboard](https://nineauth.xyz/dashboard):

```cpp
#include "client.hpp"

nineauth::Options options;
options.application_id = "app_xxxxxxxxxxxxxxxx";
options.base_url = "https://api.nineauth.xyz"; // Production runtime API

nineauth::NineAuthClient client(options);

auto initResult = client.Initialize();
if (!initResult.success) {
    std::printf("Failed to connect: [%s] %s\n", 
        initResult.error_code.c_str(), 
        initResult.error_message.c_str());
    return;
}
```

---

### 2. User Registration

Register a new user account directly from your client:

```cpp
auto regResult = client.Register("user@example.com", "SecurePassword123!");

if (!regResult.success) {
    std::printf("Registration error: [%s] %s\n", 
        regResult.error_code.c_str(), 
        regResult.error_message.c_str());
    return;
}

std::printf("User registered with ID: %s\n", regResult.value.c_str());
```

---

### 3. User Login with HWID Binding

Authenticate user credentials and bind the session to the local hardware fingerprint:

```cpp
std::string hwid = GetDeviceFingerprint(); // Native SHA-256 fingerprint

auto loginResult = client.Login("user@example.com", "SecurePassword123!", hwid);

if (!loginResult.success) {
    std::printf("Login failed: [%s] %s\n", 
        loginResult.error_code.c_str(), 
        loginResult.error_message.c_str());
    return;
}

std::printf("Login successful! Session established.\n");
```

---

### 4. Activating a License Key

Bind a license key to the current device hardware:

```cpp
auto actResult = client.ActivateLicense("NINE-XXXX-XXXX-XXXX", hwid);

if (!actResult.success) {
    std::printf("Activation failed: [%s] %s\n", 
        actResult.error_code.c_str(), 
        actResult.error_message.c_str());
    return;
}

const auto& info = actResult.value;
std::printf("License active! Status: %s | Max Seats: %d\n", 
    info.status.c_str(), info.max_seats);
```

---

### 5. Validating Session & Entitlement Lookups (0ms Latency)

Check permissions locally in memory or validate remotely with the server:

```cpp
// 1. Remote session validation (synchronizes active entitlements)
auto valResult = client.ValidateSession();
if (!valResult.success || !valResult.value.valid) {
    std::printf("Access revoked: %s\n", valResult.value.reason.c_str());
    return;
}

// 2. Fast local in-memory entitlement check (0ms overhead)
if (client.HasEntitlement("premium_module")) {
    LaunchPremiumModule();
}
```

---

### 6. Resetting Device Association (License Transfer)

Allow users to reset their HWID association when upgrading hardware:

```cpp
auto resetResult = client.ResetDevice("NINE-XXXX-XXXX-XXXX", newHwid);

if (resetResult.success) {
    std::printf("HWID reset successful. License can now be activated on new machine.\n");
} else {
    std::printf("Reset failed: [%s] %s\n", 
        resetResult.error_code.c_str(), 
        resetResult.error_message.c_str());
}
```

---

### 7. Secure Logout

Revoke the session token on the backend and wipe all credentials from memory:

```cpp
client.Logout();
```

---

## 🔒 Native Hardware Fingerprinting (Win32)

The SDK reference generates a stable device hash using Windows native CryptoAPI/BCrypt without third-party libraries:

```cpp
#include <windows.h>
#include <bcrypt.h>
#include <string>

std::string GetDeviceFingerprint() {
    char guid[256] = {0};
    DWORD size = sizeof(guid);
    HKEY hKey;
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Microsoft\\Cryptography", 
        0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, (LPBYTE)guid, &size);
        RegCloseKey(hKey);
    }
    
    // Hash MachineGuid with SHA-256 via BCrypt...
    return ComputeSHA256(guid);
}
```

---

## 📁 File Structure

```text
NineAuth-CPP-EXAMPLE/
├── main.cpp                  ← WinMain entry point and Win32 message loop
├── MainWindow.hpp            ← Window declaration and configuration constants
├── MainWindow.cpp            ← Win32 GUI event handlers and SDK integration
├── client.hpp / client.cpp   ← Core NineAuthClient implementation
├── options.hpp               ← Configuration structures
├── models.hpp                ← Data models (LicenseInfo, SessionState, etc.)
├── result.hpp                ← Exception-free Result<T> container
└── CMakeLists.txt            ← CMake build configuration
```

---

<div align="center">
  <sub>NineAuth C++ SDK · <a href="https://nineauth.xyz">nineauth.xyz</a></sub>
</div>
