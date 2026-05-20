# Implementation Plan: Avahi Backend Support

This document outlines the plan for adding an Avahi backend to the `dnssd-cpp` library, enabling native DNS-SD support on Linux (and optionally macOS for Avahi users).

## 1. Objectives

- Implement `dnssd::Advertiser` and `dnssd::Browser` using the Avahi Client API.
- Ensure seamless integration with the existing backend architecture (Bonjour and WinDNS).
- Provide a new CMake option `USE_AVAHI` to enable the backend.
- Maintain consistency in naming, behavior, and thread safety.

## 2. Architecture

The Avahi backend will reside in:
- `include/dnssd/avahi/` (Headers)
- `src/avahi/` (Implementation)

It will follow the established pattern:
- `AvahiAdvertiser` inheriting from `AdvertiserBase`.
- `AvahiBrowser` inheriting from `BrowserBase`.

### Core Components

- **Avahi Client:** Managed via `AvahiClient` and `AvahiSimplePoll`.
- **Service Advertising:** Uses `AvahiEntryGroup` to register and update services.
- **Service Browsing:** Uses `AvahiServiceBrowser` to discover service types and `AvahiServiceResolver` to resolve instance details (host, port, TXT).

## 3. Implementation Steps

### Phase 1: Build System Updates

1. **FindAvahi.cmake:** Create a Find module for Avahi (Client and Common libraries).
2. **CMakeLists.txt:**
    - Add `USE_AVAHI` option (default `OFF`).
    - Logic to include Avahi source files and link libraries when `USE_AVAHI` is `ON`.
    - Define `USE_AVAHI` macro for conditional compilation in `include/dnssd/Advertiser.h` and `Browser.h`.

### Phase 2: Header Definitions

1. `include/dnssd/avahi/Avahi.h`: Common Avahi includes and utility types.
2. `include/dnssd/avahi/AvahiAdvertiser.h`: Class definition for the advertiser.
3. `include/dnssd/avahi/AvahiBrowser.h`: Class definition for the browser.
4. Update `include/dnssd/Advertiser.h` and `include/dnssd/Browser.h` to include Avahi headers when `USE_AVAHI` is defined.

### Phase 3: Advertiser Implementation (`src/avahi/AvahiAdvertiser.cpp`)

1. Initialize `AvahiSimplePoll` and `AvahiClient`.
2. Implement `registerService`:
    - Create `AvahiEntryGroup`.
    - Add service with `avahi_entry_group_add_service`.
    - Handle TXT records using `AvahiStringList`.
3. Implement `updateTxtRecord`:
    - Use `avahi_entry_group_update_service_txt`.
4. Implement `unregisterService`:
    - Free `AvahiEntryGroup`.
5. Error handling and callbacks.

### Phase 4: Browser Implementation (`src/avahi/AvahiBrowser.cpp`)

1. Initialize `AvahiSimplePoll` and `AvahiClient`.
2. Implement `browseFor`:
    - Create `AvahiServiceBrowser`.
3. Implement `AvahiServiceBrowser` callback:
    - Handle `AVAHI_BROWSER_NEW` (discover) and `AVAHI_BROWSER_REMOVE` (remove).
    - For new services, create `AvahiServiceResolver`.
4. Implement `AvahiServiceResolver` callback:
    - Extract host, port, and TXT records.
    - Fire `onServiceResolved` and `onAddressAdded` (if addresses are available).
5. Background thread management:
    - Use `AvahiSimplePoll` in a dedicated thread to handle Avahi events.

### Phase 5: Verification & Testing

1. **Compilation:** Verify build on Linux with Avahi installed.
2. **Examples:** Run `dnssd-browser` and `dnssd-advertiser` examples.
3. **Interoperability:** Test discovery between Avahi (Linux) and Bonjour (macOS/Windows).

## 4. Considerations

- **Threading:** Avahi's `SimplePoll` requires a dedicated thread for processing events.
- **TXT Records:** Avahi uses `AvahiStringList` for TXT records; conversion logic from `dnssd::TxtRecord` will be needed.
- **Dependencies:** Users on Linux will need `libavahi-client-dev` and `libavahi-common-dev`.
