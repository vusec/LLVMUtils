cmake_minimum_required(VERSION 3.16.3)
project(LLVMUtils CXX)

# =============================================================================
# Global CMake core & compiler settings
# =============================================================================
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")
set(CMAKE_VERBOSE_MAKEFILE on CACHE STRING "Verbose Makefiles")
set(CMAKE_BUILD_TYPE Debug CACHE STRING "Debug Build Type" FORCE)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(LOG_LEVEL "LOG_LEVEL_ERROR" CACHE STRING "Set the logging level")

# Global Compiler flags
add_compile_options("-Wall")
add_compile_options("-fdiagnostics-color=always")

# Set global linker options
add_link_options("-fuse-ld=lld")

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

# =============================================================================
# LLVM Utilities library definition
# =============================================================================
add_library(LLVMUtils SHARED)

# Configure C++ standard version for target
set_target_properties(LLVMUtils PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES)

# Specify target-specific compile options
target_compile_options(LLVMUtils
    PRIVATE "-g"
    PRIVATE "-O3"
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

# Install LLVMUtils
install(TARGETS LLVMUtils
    LIBRARY PUBLIC_HEADER
)
