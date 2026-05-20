cmake_minimum_required(VERSION 3.15)

project(dnssd-cpp VERSION 0.0.1)

option(DNSSD_NO_EXAMPLES "Disable examples" OFF)
option(USE_WINDNS "Use Windns.h API instead of Bonjour on Windows" OFF)
option(USE_AVAHI "Use Avahi API instead of Bonjour" OFF)

if (WIN32)
    if (NOT BONJOUR_SDK_ROOT AND NOT USE_WINDNS)
        set(BONJOUR_SDK_ROOT "" CACHE PATH
            "Path to Bonjour SDK (Windows only). Leave empty for auto-detection.")

        set_property(CACHE BONJOUR_SDK_ROOT PROPERTY
            HELPSTRING "Path to Bonjour SDK installation directory")
    endif ()
endif ()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 11)

add_library(dnssd-cpp STATIC
    include/dnssd/Browser.h
    include/dnssd/Advertiser.h

    include/dnssd/common/AdvertiserBase.h
    include/dnssd/common/BrowserBase.h
    include/dnssd/common/TxtRecord.h
    include/dnssd/common/Util.h

    src/ServiceDescription.cpp
    src/common/Result.cpp
    src/common/Log.cpp
)

if (NOT (WIN32 AND USE_WINDNS) AND NOT USE_AVAHI)
target_sources(dnssd-cpp PRIVATE
    include/dnssd/bonjour/Bonjour.h
    include/dnssd/bonjour/BonjourAdvertiser.h
    include/dnssd/bonjour/BonjourBrowser.h
    include/dnssd/bonjour/ScopedDnsServiceRef.h
    include/dnssd/bonjour/Service.h
    include/dnssd/bonjour/SharedConnection.h

    src/bonjour/Bonjour.cpp
    src/bonjour/BonjourAdvertiser.cpp
    src/bonjour/BonjourBrowser.cpp
    src/bonjour/BonjourTxtRecord.cpp
    src/bonjour/ScopedDnsServiceRef.cpp
    src/bonjour/Service.cpp
    src/bonjour/SharedConnection.cpp
)
elseif(USE_AVAHI)
target_sources(dnssd-cpp PRIVATE
    include/dnssd/avahi/Avahi.h
    include/dnssd/avahi/AvahiAdvertiser.h
    include/dnssd/avahi/AvahiBrowser.h

    src/avahi/AvahiAdvertiser.cpp
    src/avahi/AvahiBrowser.cpp
)
else()
target_sources(dnssd-cpp PRIVATE
    include/dnssd/windns/Windns.h
    include/dnssd/windns/WindnsAdvertiser.h
    include/dnssd/windns/WindnsBrowser.h
    include/dnssd/windns/WindnsDiscoveredService.h
    include/dnssd/windns/WindnsUtil.h

    src/windns/WindnsAdvertiser.cpp
    src/windns/WindnsBrowser.cpp
    src/windns/WindnsUtil.cpp
)
endif()

target_include_directories(dnssd-cpp PUBLIC include)

target_compile_definitions(dnssd-cpp PRIVATE 
    $<$<CONFIG:Debug>:DNSSD_DEBUG>
)

if (WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:libcmt")

    if (USE_WINDNS)
        target_link_libraries(dnssd-cpp PRIVATE ws2_32 dnsapi iphlpapi)
        target_compile_definitions(dnssd-cpp PUBLIC USE_WINDNS UNICODE _UNICODE)
    else()
        find_package(BonjourSDK REQUIRED)
        target_link_libraries(dnssd-cpp PUBLIC Bonjour::dnssd)
    endif()
elseif(USE_AVAHI)
    find_package(Avahi REQUIRED)
    target_link_libraries(dnssd-cpp PUBLIC Avahi::Avahi)
    target_compile_definitions(dnssd-cpp PUBLIC USE_AVAHI)
endif ()

if (NOT DNSSD_NO_EXAMPLES)
    add_executable(dnssd-advertiser examples/dnssd-advertiser.cpp)
    target_link_libraries(dnssd-advertiser dnssd-cpp)

    add_executable(dnssd-browser examples/dnssd-browser.cpp)
    target_link_libraries(dnssd-browser dnssd-cpp)
endif ()
