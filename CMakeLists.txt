cmake_minimum_required(VERSION 3.23)

# =============================================================================
# Core project definition
# =============================================================================
project(LLVMUtils
    VERSION
        1.0
    DESCRIPTION
        "Library of generic utility functions & extensions to default LLVM"
    LANGUAGES
        C CXX
)

# Load GNU install directory namings (e.g. /usr/local/bin, /usr/local/lib, etc.)
include(GNUInstallDirs)

message(STATUS "LLVMUtils build configuration:
\tTarget project: ${PROJECT_NAME}
\tRoot directory:  ${LLVMUtils_SOURCE_DIR}")

# =============================================================================
# LLVM & LLVM SETTINGS/CONFIG
# =============================================================================
# Configure default LLVM location
set(LLVM_ROOT $ENV{LLVM_DIR} CACHE PATH "Root of LLVM installation")
if(NOT EXISTS ${LLVM_ROOT}/include/llvm)
    message(FATAL_ERROR "LLVM_ROOT (${LLVM_ROOT}) is invalid!")
endif()
list(APPEND CMAKE_PREFIX_PATH "${LLVM_ROOT}/lib/cmake/llvm/")

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    find_package(LLVM CONFIG)
    message("LLVM STATUS:
    FOUND         ${LLVM_FOUND}
    Version       ${LLVM_PACKAGE_VERSION}
    Definitions   ${LLVM_DEFINITIONS}
    Includes      ${LLVM_INCLUDE_DIRS}
    Libraries     ${LLVM_LIBRARY_DIRS}
    Targets       ${LLVM_TARGETS_TO_BUILD}"
    )
else()
    find_package(LLVM CONFIG QUIET)
endif()

if(NOT LLVM_FOUND OR NOT "${LLVM_VERSION_MAJOR}" VERSION_EQUAL 15)
    message(FATAL_ERROR "Invalid LLVM: expected 15; found ${LLVM_VERSION}")
endif()

# Set the LLVM header and library paths
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

# =============================================================================
# Define the actual runtime library target and include its subdirectory
# =============================================================================
add_library(LLVMUtils SHARED)

target_include_directories(LLVMUtils PUBLIC include)

# Define the sources for the utilities library
target_sources(LLVMUtils
    PRIVATE "${LLVMUtils_SOURCE_DIR}/src/LLVMUtils.cpp"
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS "${LLVMUtils_SOURCE_DIR}/include"
        FILES "${LLVMUtils_SOURCE_DIR}/include/LLVMUtils.hpp"
)

set_target_properties(LLVMUtils
    PROPERTIES
        C_STANDARD 11
        CXX_STANDARD 20
        C_EXTENSIONS ON
        CXX_EXTENSIONS ON
        C_STANDARD_REQUIRED ON
        CXX_STANDARD_REQUIRED ON
)

target_compile_definitions(LLVMUtils PUBLIC "_BSD_SOURCE" "_DEFAULT_SOURCE")

# Get and install into default installation dirs. Don't export headers, only compiled libs
install(
    TARGETS LLVMUtils
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
