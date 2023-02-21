cmake_minimum_required(VERSION 3.16.3)
project(LLVMUtils)

set(CMAKE_COLOR_DIAGNOSTICS ON)
set_property(GLOBAL PROPERTY CMAKE_COLOR_DIAGNOSTICS ON)

# =============================================================================
# Global CMake core & compiler settings
# =============================================================================
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")
set(CMAKE_VERBOSE_MAKEFILE on CACHE STRING "Verbose Makefiles")
set(LOG_LVL LVL_INFO CACHE STRING "Logging level for VeriPatch")
set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type debug" FORCE)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_options("-Wall")
add_compile_options("-fdiagnostics-color=always")
add_link_options("-fuse-ld=lld")

# =============================================================================
# LLVM & LLVM SETTINGS/CONFIG
# =============================================================================
find_package(LLVM 13 REQUIRED CONFIG)

if(NOT "13" VERSION_EQUAL "${LLVM_VERSION_MAJOR}")
    message(FATAL_ERROR "Found LLVM ${LLVM_VERSION_MAJOR}; need LLVM version 13!")
endif()

if(NOT LLVM_ENABLE_RTTI)
    add_compile_options("-fno-rtti")
endif()

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

llvm_map_components_to_libnames(llvm_libs all)

# =============================================================================
# LLVM Utilities library definition
# =============================================================================
add_library(LLVMUtils SHARED)

set_target_properties(LLVMUtils
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS ON
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS ON
)

target_compile_options(LLVMUtils
    PRIVATE
        "-g"
        "-O2"
        "-Wall"
        "-Wextra"
        "-Wno-reorder"
        "-Wno-unused-parameter"
        "-Wno-overloaded-virtual"
        "-Wno-ignored-qualifiers"
        "-fdiagnostics-color=always"
)

target_link_options(LLVMUtils PRIVATE "-fuse-ld=lld")
target_include_directories(LLVMUtils PUBLIC "include")

target_link_libraries(LLVMUtils ${llvm_libs})

add_subdirectory(include)
add_subdirectory(src)

# Get and install into default installation dirs. Don't export headers, only compiled libs
include(GNUInstallDirs)
install(
    TARGETS
        LLVMUtils
    RUNTIME
        DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
