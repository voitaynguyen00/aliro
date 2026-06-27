# FindPCSC.cmake — Locate the PC/SC API (PCSC-lite on Linux/macOS, WinSCard on Windows).
#
# Imported targets:
#   PCSC::PCSC   — link target with headers and library
#
# Result variables:
#   PCSC_FOUND
#   PCSC_INCLUDE_DIR
#   PCSC_LIBRARY

include(FindPackageHandleStandardArgs)

if(WIN32)
    find_path(PCSC_INCLUDE_DIR NAMES winscard.h)
    find_library(PCSC_LIBRARY NAMES winscard)
elseif(APPLE)
    find_library(PCSC_LIBRARY NAMES PCSC)
    # macOS ships PCSC as a framework; its headers are inside the bundle.
    if(PCSC_LIBRARY)
        set(PCSC_INCLUDE_DIR "${PCSC_LIBRARY}/Headers"
            CACHE PATH "PCSC include directory")
    endif()
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(PC_PCSC QUIET libpcsclite)
    endif()
    find_path(PCSC_INCLUDE_DIR
        NAMES PCSC/winscard.h
        HINTS ${PC_PCSC_INCLUDE_DIRS}
        PATHS /usr/include /usr/local/include)
    find_library(PCSC_LIBRARY
        NAMES pcsclite
        HINTS ${PC_PCSC_LIBRARY_DIRS})
endif()

find_package_handle_standard_args(PCSC REQUIRED_VARS PCSC_LIBRARY PCSC_INCLUDE_DIR)

if(PCSC_FOUND AND NOT TARGET PCSC::PCSC)
    if(APPLE)
        # Use -F (framework search path) so that cross-includes like
        # <PCSC/pcsclite.h> inside winscard.h resolve correctly.
        get_filename_component(_pcsc_fw_dir "${PCSC_LIBRARY}" DIRECTORY)
        add_library(PCSC::PCSC INTERFACE IMPORTED)
        set_target_properties(PCSC::PCSC PROPERTIES
            INTERFACE_COMPILE_OPTIONS  "-F${_pcsc_fw_dir}"
            INTERFACE_LINK_LIBRARIES   "-framework PCSC")
    else()
        add_library(PCSC::PCSC UNKNOWN IMPORTED)
        set_target_properties(PCSC::PCSC PROPERTIES
            IMPORTED_LOCATION             "${PCSC_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${PCSC_INCLUDE_DIR}")
    endif()
endif()

mark_as_advanced(PCSC_INCLUDE_DIR PCSC_LIBRARY)
