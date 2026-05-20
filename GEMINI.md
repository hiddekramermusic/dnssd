# Project Instructions: dnssd-cpp

This project is a C++11 library for DNS Service Discovery (DNS-SD), providing an easy-to-use interface for browsing and advertising services across different platforms.

## Architecture

The library uses a backend-based architecture to support multiple DNS-SD implementations:

- **Bonjour (mDNSResponder):** The default backend for macOS and optionally Windows (via Bonjour SDK).
- **WinDNS:** A native Windows backend using `Windns.h`, enabled with the CMake flag `-DUSE_WINDNS=ON`.

### Key Components

- `dnssd::Browser`: Interface for discovering services.
- `dnssd::Advertiser`: Interface for registering/advertising services.
- `dnssd::ServiceDescription`: Data structure representing a discovered or registered service.
- `dnssd::TxtRecord`: Helper for managing DNS-SD TXT records.

## Coding Standards & Conventions

- **C++ Standard:** C++11 or higher.
- **Naming:**
    - Classes: `PascalCase` (e.g., `BrowserBase`, `ServiceDescription`).
    - Methods/Functions: `camelCase` (e.g., `browseFor`, `onServiceDiscovered`).
    - Namespaces: `dnssd`.
- **Async Pattern:** Most callbacks are asynchronous and executed on background threads managed by the backends. Thread safety should be considered in user-provided callbacks.
- **Headers:** Public API headers are in `include/dnssd/`. Backend-specific implementation headers are in `include/dnssd/bonjour/` and `include/dnssd/windns/`.
- **Logging:** Use the `DNSSD_LOG_DEBUG(msg)` macro for debug logging. It is active only when `DNSSD_DEBUG` is defined.

## Build System (CMake)

- **Options:**
    - `DNSSD_NO_EXAMPLES`: Set to `ON` to skip building example applications.
    - `USE_WINDNS`: Set to `ON` to use the native Windows WinDNS API instead of Bonjour.
- **Dependencies (Windows):**
    - **Bonjour SDK:** Required if `USE_WINDNS` is `OFF`.
    - **Native Libraries:** If using WinDNS, link against `ws2_32`, `dnsapi`, and `iphlpapi`.

## Platform-Specific Implementation Details

### WinDNS Backend

- **TXT Record Updates:** WinDNS does not support dynamic record updates. The library handles TXT record updates by deregistering and reregistering the service.
- **TXT Record Polling:** The WinDNS API lacks a subscription mechanism for record changes. `WindnsBrowser` provides `setTxtPollIntervalMs` to periodically re-resolve services and detect TXT record changes from remote peers (like macOS Bonjour services).

## Workflow & Testing

- **Verification:** Use the example applications in `examples/` (`dnssd-browser` and `dnssd-advertiser`) to verify functionality.
- **Formatting:** Adhere to the provided `.clang-format` configuration.
- **Compatibility:** Always ensure changes maintain interoperability between Bonjour (macOS/iOS/Windows) and WinDNS (Windows) backends.
