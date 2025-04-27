cmake_minimum_required(VERSION 3.20)
set(CORNERSTONE_PROJECT_VERSION 0.1.0)

project(cornerstone
  VERSION ${CORNERSTONE_PROJECT_VERSION}
  DESCRIPTION "Cornerstone Engine"
  LANGUAGES C CXX
)

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
set(WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  set(CORNERSTONE_TOPLEVEL_PROJECT TRUE)
else()
  set(CORNERSTONE_TOPLEVEL_PROJECT FALSE)
endif()

option(CORNERSTONE_BUILD_SHARED "Builds shared cornerstone library" ON)
option(CORNERSTONE_BUILD_EXAMPLES "Builds cornerstone examples" OFF)
option(CORNERSTONE_BUILD_TESTS "Builds cornerstone tests" OFF)
option(CORNERSTONE_ENABLE_ALL_ARCHS "Enables all supported llvm architectures" ON)

option(CORNERSTONE_ENABLE_ARCH_X86 "Enables x86 support" OFF)
option(CORNERSTONE_ENABLE_ARCH_ARM "Enables arm support" OFF)
option(CORNERSTONE_ENABLE_ARCH_AARCH64 "Enables aarch64 support" OFF)
option(CORNERSTONE_ENABLE_ARCH_RISCV "Enables x86 support" OFF)

# find_package(LLVM 15...<20 CONFIG REQUIRED) # this doesn't work!
set(CORNERSTONE_LLVM_VERSIONS 19.1 19 18.1 18 17.1 17 16.1 16 15.1 15)

set(_found_llvm FALSE)
foreach(_ver IN LISTS CORNERSTONE_LLVM_VERSIONS)
  find_package(LLVM ${_ver} QUIET CONFIG)
  if(LLVM_FOUND)
    message(STATUS "Found LLVM ${_ver} (=> ${LLVM_VERSION_STRING})")
    set(_found_llvm TRUE)
    break()
  endif()
endforeach()

if(NOT _found_llvm)
  message(FATAL_ERROR
    "Could not find a compatible LLVM installation.\n"
    "Cornerstone requires LLVM 15.x, 16.x, 17.x, 18.x, or 19.x."
  )
endif()

if(LLVM_VERSION_MAJOR LESS 15 OR LLVM_VERSION_MAJOR GREATER 19)
  message(FATAL_ERROR
    "Found LLVM ${LLVM_VERSION_STRING}, but only LLVM 15–19 are supported."
  )
endif()

set(CORNERSTONE_LLVM_COMMON
  MC
  MCDisassembler
  MCJIT
  Object
  Support
)

set(CORNERSTONE_LLVM_ARCHS)
if(CORNERSTONE_ENABLE_ALL_ARCHS)
  set(CORNERSTONE_LLVM_ARCHS
    AllTargetsAsmParsers
    AllTargetsDescs
    AllTargetsDisassemblers
    AllTargetsInfos
  )
else()
  set(CORNERSTONE_LLVM_ARCHS
    X86
    ARM
    AArch64
    RISCV
  )
endif()

set(CORNERSTONE_HEADER_FILES 
  include/cornerstone/cornerstone.h
  include/cornerstone/cornerstone.hpp
)

set(CORNERSTONE_LIB_FORM)
if(CORNERSTONE_BUILD_SHARED)
  set(CORNERSTONE_LIB_FORM SHARED)
endif()

add_library(cornerstone ${CORNERSTONE_LIB_FORM}
  src/cornerstone.cpp
)

if(CORNERSTONE_ENABLE_ALL_ARCHS)
  target_compile_definitions(cornerstone PRIVATE
    CORNERSTONE_ENABLE_ALL_ARCHS
  )
else()
  foreach(_arch IN LISTS CORNERSTONE_LLVM_ARCHS)
    if(CORNERSTONE_ENABLE_ARCH_${_arch})
      target_compile_definitions(cornerstone PRIVATE
        CORNERSTONE_ENABLE_ARCH_${_arch}
      )
    endif()
  endforeach()
endif()

llvm_map_components_to_libnames(
  LLVM_LIBS
  ${CORNERSTONE_LLVM_ARCHS}
  ${CORNERSTONE_LLVM_COMMON}
)

target_include_directories(cornerstone PRIVATE
  ${LLVM_INCLUDE_DIRS}
)

target_compile_definitions(cornerstone PRIVATE
  ${LLVM_DEFINITIONS}
)

target_link_libraries(cornerstone PRIVATE ${LLVM_LIBS})
target_compile_features(cornerstone PUBLIC cxx_std_20)

target_include_directories(cornerstone PUBLIC 
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include>
)

set_target_properties(cornerstone PROPERTIES
  VERSION ${CORNERSTONE_PROJECT_VERSION}
  PUBLIC_HEADER "${CORNERSTONE_HEADER_FILES}"
)

add_library(cornerstone::cornerstone ALIAS cornerstone)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/cornerstoneConfigVersion.cmake
  VERSION ${CORNERSTONE_PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(
  TARGETS cornerstone
  EXPORT cornerstoneConfig
  ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
  LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/cornerstone
)

export(
  TARGETS cornerstone
  NAMESPACE cornerstone::
  FILE "${CMAKE_CURRENT_BINARY_DIR}/cornerstoneConfig.cmake"
)

install(
  EXPORT cornerstoneConfig
  DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cmake/cornerstone"
  NAMESPACE cornerstone::
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cornerstoneConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_PREFIX}/share/cmake/cornerstone
)

if(CORNERSTONE_BUILD_EXAMPLES)
  add_executable(cornerstone_cli examples/cornerstone_cli.cpp)
  target_link_libraries(cornerstone_cli PRIVATE cornerstone::cornerstone)

  add_executable(c_api examples/c_api.c)
  target_link_libraries(c_api PRIVATE cornerstone::cornerstone)

  add_executable(example examples/example.cpp)
  target_link_libraries(example PRIVATE cornerstone::cornerstone)

  add_executable(test_error examples/test_error.cpp)
  target_link_libraries(test_error PRIVATE cornerstone::cornerstone)
endif()

if (CORNERSTONE_BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
    OVERRIDE_FIND_PACKAGE
  )
  # For Windows: Prevent overriding the parent project's compiler/linker settings
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  find_package(googletest CONFIG REQUIRED)
  enable_testing()
  add_executable(test1 tests/test1.cpp)
  target_link_libraries(test1 PRIVATE cornerstone::cornerstone GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(test1)
endif()
