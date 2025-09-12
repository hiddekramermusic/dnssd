cmake_minimum_required(VERSION 3.15)

project(dnssd-cpp VERSION 0.0.1)

option(DNSSD_NO_EXAMPLES "Disable examples" OFF)

if (WIN32)
    if (NOT BONJOUR_SDK_ROOT)
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
    include/dnssd/bonjour/Bonjour.h
    include/dnssd/bonjour/BonjourAdvertiser.h
    include/dnssd/bonjour/BonjourBrowser.h
    include/dnssd/bonjour/ScopedDnsServiceRef.h
    include/dnssd/bonjour/Service.h
    include/dnssd/bonjour/SharedConnection.h
    include/dnssd/common/AdvertiserBase.h
    include/dnssd/common/BrowserBase.h
    include/dnssd/common/TxtRecord.h
    include/dnssd/common/Util.h

    src/ServiceDescription.cpp
    src/bonjour/Bonjour.cpp
    src/bonjour/BonjourAdvertiser.cpp
    src/bonjour/BonjourBrowser.cpp
    src/bonjour/BonjourTxtRecord.cpp
    src/bonjour/ScopedDnsServiceRef.cpp
    src/bonjour/Service.cpp
    src/bonjour/SharedConnection.cpp
    src/common/Result.cpp
    src/common/Result.cpp
    src/common/Log.cpp
)

target_include_directories(dnssd-cpp PUBLIC include)

if (WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:libcmt")

    find_package(BonjourSDK REQUIRED)
    target_link_libraries(dnssd-cpp PUBLIC Bonjour::dnssd)
endif ()

if (NOT DNSSD_NO_EXAMPLES)
    add_executable(dnssd-advertiser examples/dnssd-advertiser.cpp)
    target_link_libraries(dnssd-advertiser dnssd-cpp)

    add_executable(dnssd-browser examples/dnssd-browser.cpp)
    target_link_libraries(dnssd-browser dnssd-cpp)
endif ()
