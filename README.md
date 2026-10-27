# DNS Service Discovery for C++

This library provides an interface which allows to use dns-sd in an easy way.

## Prerequisites

* C++11 (or higher)
* CMake (3.15 or higher)

### MacOS
  
* XCode

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
    
After this you end up with two test command line utilities and a libray.

## Windns notes

### Libraries to link for Windns

You need to link the following libraries on windows to use Windns: ws2_32.lib dnsapi.lib iphlpapi.lib

### Registration lifetime (advertiser)

`registerService` returns before Windns has finished the registration. If `unregisterService` is called, or the advertiser is destroyed, while the registration is still pending, the registration is cancelled.

A Windns registration lasts until it is deregistered or the process exits. Destroying the advertiser deregisters the service.

### TXT record update broadcasting (advertiser)
Windns has some slight differences compared to Bonjour in how they handle updating records, as dynamic record updates are not supported.
Instead, this library deregisters the current service, and reregisters the service with the new TXT record.
The Windns browser reports the update through `onServiceResolved` with the new TXT record; the service is not removed.

If `updateTxtRecord` is called while a registration is still pending, the pending registration is cancelled and the service is registered with the new TXT record.

### Service removal (browser)

A service is removed, and `onServiceRemoved` fires, in these cases:

- The browser receives a goodbye packet (a PTR record with TTL 0) for it. This happens when the advertiser deregisters the service.
- The liveness check fails. Every 5 seconds the browser re-resolves each known service. A resolve that is still unanswered at the next check counts as a failure, and so does a resolve that returns an error. After 3 failures in a row the service is removed. A service that disappears without a goodbye packet (for example when the advertising process is killed) is removed about 15–20 seconds later.
- The service has not been seen within the TTL of its PTR record.

The liveness check always runs, also when TXT polling is disabled. The interval and the number of failures are the constants `kLivenessInterval` and `kMaxResolveFailures` in `WindnsBrowser.h`.

`onServiceDiscovered` fires as soon as the PTR record is seen, before the service is resolved. `hostTarget` is empty and `port` is 0 until `onServiceResolved` has fired.

### Browse results (browser)

Besides PTR records, a browse result can contain SRV, TXT, A and AAAA records. The browser applies them to the matching services directly: SRV and TXT records by instance name, A and AAAA records by the host target of the service.

If a browse reports an error, it is reported through `onBrowseError` with the service type in the message, and the browse is cancelled. `browseFor` can then be called again for that service type to restart it.

### Addresses (browser)

`DnsServiceResolve` returns at most one IPv4 and one IPv6 address. To find all addresses of a service, the browser also queries the A and AAAA records of the host target: when the host target is first known or changes, and after that at most once every `kLivenessInterval`. Addresses from the resolve are reported with the interface index of the resolve, addresses from browse results and address queries with interface index 0. An address is removed when an A or AAAA record with TTL 0 is received for it.

### TXT record update detection (browser)

The Windns API has no record-change subscription mechanism equivalent to Bonjour's `DNSServiceQueryRecord`. As a result, TXT record updates announced by remote peers (e.g. a Bonjour service on macOS) are not detected automatically.

To work around this, `WindnsBrowser` (and the `Browser` example when built with `USE_WINDNS`) re-resolves every known service periodically. The interval is set with `setTxtPollIntervalMs`; passing 0 disables TXT polling.
`onServiceResolved` fires once the host target and port are known, from a resolve or from a browse result, and after that only when the host target, port or TXT record has changed.

If you use the default constructor of the WindnsBrowser the interval is set to 1000ms. The background thread starts when you start browsing for a service, and runs until the browser is destroyed.

If you want to change it you can either use the constructor, or change the interval on the fly (thread safe).

- Constructor:
```cpp
dnssd::Browser browser { 2000 }; // re-resolve every two seconds
browser.browseFor("_http._tcp");
```

- On the fly:
```cpp
dnssd::Browser browser;
browser.setTxtPollIntervalMs (2000); // re-resolve every 2 seconds
browser.browseFor("_http._tcp");
```

- Disabling: 
```cpp
dnssd::Browser browser { 0 };
browser.browseFor("_http._tcp");
```

You can disable or re-enable TXT polling at any moment. The liveness check keeps running either way:
```cpp
dnssd::Browser browser { 2000 };
browser.browseFor("_http._tcp");
/// Do some work
browser.setTxtPollIntervalMs (0); // Stops TXT polling
```

Choose the interval based on how quickly you need to detect changes, and based on the performance you get, 1000 ms is the reasonable default.

If you choose to not use this polling loop, Bonjour updates the PTR record at a higher interval (30 seconds or more),
and at that point any updated TXT records will be found by the Windns browser through the PTR update. 