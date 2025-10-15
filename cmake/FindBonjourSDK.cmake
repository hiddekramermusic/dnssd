function(find_bonjour_sdk)
    if (NOT WIN32)
        message(FATAL_ERROR "Bonjour SDK integration only supports Windows")
    endif ()

    if (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(BONJOUR_ARCH "x64")
        set(BONJOUR_ARCH_ALT "64")
    else ()
        set(BONJOUR_ARCH "Win32")
        set(BONJOUR_ARCH_ALT "86")
    endif ()

    set(BONJOUR_SEARCH_PATHS "${BONJOUR_SDK_ROOT}")
    if (DEFINED ENV{BONJOUR_SDK_ROOT} AND NOT "$ENV{BONJOUR_SDK_ROOT}" STREQUAL "")
        list(APPEND BONJOUR_SEARCH_PATHS $ENV{BONJOUR_SDK_ROOT})
    endif ()

    # vcpkg integration
    if (DEFINED CMAKE_PREFIX_PATH AND NOT CMAKE_PREFIX_PATH STREQUAL "")
        list(APPEND BONJOUR_SEARCH_PATHS ${CMAKE_PREFIX_PATH})
    endif ()

    # Standard installation locations
    list(APPEND BONJOUR_SEARCH_PATHS
        "C:/Program Files/Bonjour"
        "C:/Program Files/Bonjour SDK"
        "C:/Program Files (x86)/Bonjour"
        "C:/Program Files (x86)/Bonjour SDK"
    )

    find_path(BONJOUR_INCLUDE_DIR
        NAMES dns_sd.h
        PATHS ${BONJOUR_SEARCH_PATHS}
        PATH_SUFFIXES Include include
        DOC "Bonjour SDK include directory"
    )

    find_library(BONJOUR_LIBRARY
        NAMES dnssd libdnssd
        PATHS ${BONJOUR_SEARCH_PATHS}
        PATH_SUFFIXES
        "Lib/${BONJOUR_ARCH}"
        "lib/${BONJOUR_ARCH}"
        "Lib/${BONJOUR_ARCH_ALT}"
        DOC "Bonjour SDK library"
    )

    # Version detection
    if (BONJOUR_INCLUDE_DIR)
        file(READ "${BONJOUR_INCLUDE_DIR}/dns_sd.h" BONJOUR_HEADER_CONTENT)
        string(REGEX MATCH "#define[ \t]+_DNS_SD_H[ \t]+([0-9]+)"
            BONJOUR_VERSION_MATCH "${BONJOUR_HEADER_CONTENT}")

        if (CMAKE_MATCH_1)
            set(BONJOUR_RAW_VERSION "${CMAKE_MATCH_1}")
            math(EXPR BONJOUR_MAJOR_VERSION "${BONJOUR_RAW_VERSION} / 10000")
            math(EXPR BONJOUR_MINOR_VERSION "(${BONJOUR_RAW_VERSION} % 10000) / 100")
            math(EXPR BONJOUR_PATCH_VERSION "${BONJOUR_RAW_VERSION} % 100")
            set(BONJOUR_VERSION "${BONJOUR_MAJOR_VERSION}.${BONJOUR_MINOR_VERSION}.${BONJOUR_PATCH_VERSION}")
        endif ()
    endif ()

    if (BONJOUR_INCLUDE_DIR AND BONJOUR_LIBRARY)
        if (NOT TARGET Bonjour::dnssd)
            add_library(Bonjour::dnssd UNKNOWN IMPORTED)
            set_target_properties(Bonjour::dnssd PROPERTIES
                IMPORTED_LOCATION "${BONJOUR_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${BONJOUR_INCLUDE_DIR}"
                INTERFACE_COMPILE_DEFINITIONS "BONJOUR_SDK_AVAILABLE=1"
            )

            target_link_libraries(Bonjour::dnssd INTERFACE ws2_32)
        endif ()

        set(BONJOUR_FOUND TRUE PARENT_SCOPE)
        set(BONJOUR_INCLUDE_DIR "${BONJOUR_INCLUDE_DIR}" PARENT_SCOPE)
        set(BONJOUR_LIBRARY "${BONJOUR_LIBRARY}" PARENT_SCOPE)
        set(BONJOUR_VERSION "${BONJOUR_VERSION}" PARENT_SCOPE)
    else ()
        set(BONJOUR_FOUND FALSE PARENT_SCOPE)
    endif ()
endfunction()

find_bonjour_sdk()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BonjourSDK
    REQUIRED_VARS BONJOUR_LIBRARY BONJOUR_INCLUDE_DIR
    VERSION_VAR BONJOUR_VERSION
    FAIL_MESSAGE "Bonjour SDK not found. Install SDK or set BONJOUR_SDK_ROOT"
)
