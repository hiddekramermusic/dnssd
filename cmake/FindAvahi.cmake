# Find Avahi
#
# Find the Avahi client and common libraries.
#
# This module defines:
# AVAHI_INCLUDE_DIRS - where to find avahi-client/client.h, etc.
# AVAHI_LIBRARIES - libraries to link against to use Avahi.
# AVAHI_FOUND - true if Avahi has been found.

find_path(AVAHI_COMMON_INCLUDE_DIR avahi-common/address.h)
find_path(AVAHI_CLIENT_INCLUDE_DIR avahi-client/client.h)

find_library(AVAHI_COMMON_LIBRARY NAMES avahi-common)
find_library(AVAHI_CLIENT_LIBRARY NAMES avahi-client)

set(AVAHI_INCLUDE_DIRS ${AVAHI_COMMON_INCLUDE_DIR} ${AVAHI_CLIENT_INCLUDE_DIR})
set(AVAHI_LIBRARIES ${AVAHI_COMMON_LIBRARY} ${AVAHI_CLIENT_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Avahi DEFAULT_MSG AVAHI_COMMON_LIBRARY AVAHI_CLIENT_LIBRARY AVAHI_COMMON_INCLUDE_DIR AVAHI_CLIENT_INCLUDE_DIR)

mark_as_advanced(AVAHI_COMMON_INCLUDE_DIR AVAHI_CLIENT_INCLUDE_DIR AVAHI_COMMON_LIBRARY AVAHI_CLIENT_LIBRARY)

if(AVAHI_FOUND AND NOT TARGET Avahi::Avahi)
    add_library(Avahi::Avahi INTERFACE IMPORTED)
    set_target_properties(Avahi::Avahi PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${AVAHI_INCLUDE_DIRS}"
        INTERFACE_LINK_LIBRARIES "${AVAHI_LIBRARIES}"
    )
endif()
