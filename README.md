# softether-vpn-macos-client

This repository contains a macOS host application, a Packet Tunnel System Extension (`.systemextension`), and a shared framework.
The project uses Xcode configuration files (`.xcconfig`) to keep environment-specific identifiers configurable from a single place.

## Requirements

- Xcode (tested with Xcode 26.2)
- A valid Apple Developer Team for code signing (required to run Network Extensions / System Extensions)
- macOS with System Extensions enabled (for runtime testing)

## Project structure

- **Host App** — macOS application target
- **System Extension** — Packet Tunnel system extension target (`.systemextension`)
- **Framework** — shared code used by multiple targets

## Configuration

The project uses two configuration layers:

- `Config.xcconfig` — base configuration with placeholder values
- `Config.local.xcconfig` — optional local overrides for your environment

`Config.xcconfig` may include local overrides if present:

```xcconfig
#include? "Config.local.xcconfig"
```

## Setup

### 1) Create local overrides (optional)

Create `Config.local.xcconfig` next to `Config.xcconfig` and override the values you need.

Template:

```xcconfig
// Code signing
DEVELOPMENT_TEAM = <YOUR_TEAM_ID>

// Bundle IDs
BUNDLE_ID_APP  = <YOUR_APP_BUNDLE_ID>
BUNDLE_ID_EXT  = <YOUR_SYSTEM_EXTENSION_BUNDLE_ID>
BUNDLE_ID_FWMK = <YOUR_FRAMEWORK_BUNDLE_ID>

// Keychain/App Group
KEYCHAIN_ACCESS_GROUP = <YOUR_KEYCHAIN_ACCESS_GROUP>
APP_GROUP_ID          = <YOUR_APP_GROUP_ID>

// OIDC / AppAuth redirect
OIDC_REDIRECT_SCHEME = <YOUR_REDIRECT_SCHEME>
OIDC_URL_IDENTIFIER  = <YOUR_URL_IDENTIFIER>

// Unified logging subsystems
LOG_SUBSYSTEM_APP = <YOUR_LOG_SUBSYSTEM_APP>
LOG_SUBSYSTEM_EXT = <YOUR_LOG_SUBSYSTEM_EXT>

// Versioning (optional)
APP_MARKETING_VERSION  = 1.0.0
APP_BUILD_NUMBER       = 1
EXT_MARKETING_VERSION  = 1.0.0
EXT_BUILD_NUMBER       = 1
FWMK_MARKETING_VERSION = 1.0.0
FWMK_BUILD_NUMBER      = 1
```

### 2) Configure URL Types for the OIDC redirect scheme (AppAuth)

The Host App target must declare the redirect scheme in:

Target → **Info** → **URL Types** → **URL Schemes**

Use:

- `$(OIDC_REDIRECT_SCHEME)`

This must match the redirect scheme configured in your OIDC provider and used by AppAuth.

### 3) Code signing

System Extensions require proper signing.

In Xcode:
- Select the **Host App**, **System Extension**, and **Framework** targets
- Ensure the correct **Team** is set (or provided via `DEVELOPMENT_TEAM`)
- Build and run the Host App target

## Running

1. Open `SimpleTunnel.xcodeproj`
2. Select the Host App scheme
3. Build & Run
4. If macOS prompts you, approve/allow the System Extension in **System Settings**

## Package dependencies

This project uses Swift Package Manager (SPM). Key dependency:

- **AppAuth** (OIDC/OAuth 2.0 client library)

## Notes (Network Extension)

- The Network Extension must be code signed to build and run.
- In some workflows, macOS requires the host app to be installed (e.g., under `/Applications`) for the System Extension to load and activate reliably. If the extension does not load when launching from Xcode/DerivedData, install the signed app build into `/Applications` and run it from there.
