# DNS Service Discovery for C++

This library provides an interface which allows to use dns-sd in an easy way.

## Prerequisites

* C++11 (or higher)
* CMake (3.15 or higher)

### MacOS
  
* XCode

### Linux

* Avahi - Native DNS-SD support for Linux.
  * Ubuntu/Debian: `sudo apt-get install libavahi-client-dev libavahi-common-dev`
  * Fedora/RHEL/CentOS: `sudo dnf install avahi-devel`

### Windows

This library can either use the builtin Windns.h headers, or use the Bonjour SDK by Apple.

By default the Bonjour SDK is selected, but you can switch to Windns by setting 'USE_WINDNS' as a CMake flag.
In case you're using Windns, you do not need the Bonjour dependency.

* Bonjour SDK (Apple) - If 'USE_WINDNS' is not enabled 
This library uses the Bonjour SDK and expects it to be in the default install location (ie C:\Program Files\Bonjour SDK).

## How to use

### Browsing

    #include <dnssd/Browser.h>

    dnssd::Browser browser;

    browser.onServiceDiscoveredAsync ([] (const dnssd::ServiceDescription& serviceDescription) {
        std::cout << "Service discovered: " << serviceDescription.description() << std::endl;
    });

    browser.onServiceRemovedAsync ([] (const dnssd::ServiceDescription& serviceDescription) {
        std::cout << "Service removed: " << serviceDescription.description() << std::endl;
    });

    browser.onBrowseErrorAsync ([] (const dnssd::Result& error) {
        std::cout << "Error: " << error.description() << std::endl;
    });

    // Start browsing
    if (auto error = browser.browseFor ("_http._tcp"))
    {
        std::cout << "Result: " << error.description() << std::endl;
    };
    
### Advertising

    #include <dnssd/Advertiser.h>

    dnssd::Advertiser advertiser;
    advertiser.onAdvertiserErrorAsync ([] (const dnssd::Result& error) 
    {
        std::cout << "Error: " << error.description() << std::endl;
    });

    dnssd::TxtRecord txtRecord = {{"key1", "value1"}, {"key2", "value2"}};

    // Register service
    if (auto error = advertiser.registerService ("_http._tcp", 80, txtRecord))
    {
        std::cout << "Result: " << error.description() << std::endl;
    }

## How to build

## As subdirectory

The easiest way of using this library is to include it as subdirectory in your CMake project:

    add_subdirectory(./path/to/this/directory)
    
And to link your targets to the library:

    target_link_libraries(target PRIVATE dnssd-cpp)
    
## As separate build

If you don't use CMake for building then this way will produce a separate library:

    mkdir build 
    cd build
    cmake ..
    cmake --build .

### Linux (Avahi)

To build with Avahi support on Linux:

    mkdir build
    cd build
    cmake .. -DUSE_AVAHI=ON
    cmake --build .
    
After this you end up with two test command line utilities and a libray.

## Windns notes

### Libraries to link for Windns

You need to link the following libraries on windows to use Windns: ws2_32.lib dnsapi.lib iphlpapi.lib

### TXT record update broadcasting (advertiser)
Windns has some slight differences compared to Bonjour in how they handle updating records, as dynamic record updates are not supported.
Instead, this library deregisters the current service, and reregisters the service with the new TXT record.

### TXT record update detection (browser)

The Windns API has no record-change subscription mechanism equivalent to Bonjour's `DNSServiceQueryRecord`. As a result, TXT record updates announced by remote peers (e.g. a Bonjour service on macOS) are not detected automatically.

To work around this, `WindnsBrowser` (and the `Browser` example when built with `USE_WINDNS`) provides opt-in periodic re-resolution via `setTxtPollIntervalMs`. 
When enabled, the browser re-issues `DnsServiceResolve` for every known service at the given interval and fires `onServiceResolved` if the TXT record has changed.

```cpp
dnssd::Browser browser;
browser.setTxtPollIntervalMs(2000); // re-resolve every 2 seconds; 0 = disabled (default)
browser.browseFor("_http._tcp");
```
Choose the interval based on how quickly you need to detect changes, and based on the performance you get.

If you do not use this polling loop, Bonjour updates the PTR record at a higher interval (30 seconds or more), and at that point any updated TXT records will be found by the Windns browser. 

### TXT polling in the browser example (WinDNS)

Build with Windns enabled, then pass `polling_interval=<ms>` on the command line:

```bash
cmake -B build -S . -DUSE_WINDNS=ON
cmake --build build
.\build\dnssd-browser.exe _http._tcp polling_interval=1000
```
