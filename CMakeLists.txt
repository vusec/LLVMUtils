cmake_minimum_required(VERSION 3.16.3)
project(InstrumentPass CXX)

# =============================================================================
# Global CMake core & compiler settings
# =============================================================================
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")
set(CMAKE_VERBOSE_MAKEFILE on CACHE STRING "Verbose Makefiles")
set(CMAKE_BUILD_TYPE Debug CACHE STRING "Debug Build Type" FORCE)

# =============================================================================
# LLVM & LLVM SETTINGS/CONFIG
# =============================================================================
find_package(LLVM 13 REQUIRED CONFIG)
if (NOT "13" VERSION_EQUAL "${LLVM_VERSION_MAJOR}")
  message(FATAL_ERROR "Found LLVM ${LLVM_VERSION_MAJOR}; need LLVM version 13!")
endif()

if(NOT LLVM_ENABLE_RTTI)
  add_compile_options("-fno-rtti")
endif()

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

message(STATUS
"LLVM STATUS:
    Version     ${LLVM_PACKAGE_VERSION}
    Definitions ${LLVM_DEFINITIONS}
    Location    ${LLVM_DIR}
    Includes    ${LLVM_INCLUDE_DIRS}
    Libraries   ${LLVM_LIBRARY_DIRS}
    Targets     ${LLVM_TARGETS_TO_BUILD}
    CMake Dir   ${LLVM_CMAKE_DIR}")

# =============================================================================
# LLVM Utilities library definition
# =============================================================================
add_library(LLVMUtils SHARED)

# Set build directories
set_target_properties(LLVMUtils PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
message(STATUS
"BUILD DIRECTORY CONFIGURATION:
    Root dir: ${SOURCE_DIR}
    Binary dir: ${BINARY_DIR}
    Archive output dir: ${ARCHIVE_OUTPUT_DIRECTORY}
    Library output dir: ${LIBRARY_OUTPUT_DIRECTORY}
    Runtime output dir: ${RUNTIME_OUTPUT_DIRECTORY}")

# Configure C++ standard version for target
set_target_properties(LLVMUtils PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES)

# Specify target-specific compile options
target_compile_options(LLVMUtils
    PRIVATE "-g"
    PRIVATE "-O2"
    PRIVATE "-Wall"
    PRIVATE "-Wextra"
    PRIVATE "-Wno-reorder"
    PRIVATE "-Wno-unused-parameter"
    PRIVATE "-Wno-overloaded-virtual"
    PRIVATE "-Wno-ignored-qualifiers"
    PRIVATE "-fdiagnostics-color=always")

# Specify target-specific linker options
target_link_options(LLVMUtils
    PRIVATE "-fuse-ld=lld")

# Specify include file tree (publicly available)
target_include_directories(LLVMUtils
    PUBLIC "include")

# Include all of the libraries needed for the utilities library
add_subdirectory(include)
add_subdirectory(src)
