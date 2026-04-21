cmake_minimum_required(VERSION 3.20)
project(vmp VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(VMP_WITH_JIT "Enable JIT placeholder targets" ON)
option(VMP_WITH_VM2 "Enable VM2 placeholder targets" ON)

include(cmake/third_party.cmake)
vmp_require_nlohmann_json()

set(VMP_PLATFORM "linux" CACHE STRING "Target platform: linux|windows|macos|android|ios")
set_property(CACHE VMP_PLATFORM PROPERTY STRINGS linux windows macos android ios)
set(VMP_ARCH "x64" CACHE STRING "Target architecture: x86|x64|arm|arm64")
set_property(CACHE VMP_ARCH PROPERTY STRINGS x86 x64 arm arm64)


set(VMP_VALID_PLATFORMS linux windows macos android ios)
list(FIND VMP_VALID_PLATFORMS "${VMP_PLATFORM}" VMP_PLATFORM_INDEX)
if(VMP_PLATFORM_INDEX EQUAL -1)
  message(FATAL_ERROR "Invalid VMP_PLATFORM='${VMP_PLATFORM}'")
endif()

set(VMP_VALID_ARCHES x86 x64 arm arm64)
list(FIND VMP_VALID_ARCHES "${VMP_ARCH}" VMP_ARCH_INDEX)
if(VMP_ARCH_INDEX EQUAL -1)
  message(FATAL_ERROR "Invalid VMP_ARCH='${VMP_ARCH}'")
endif()

message(STATUS "Configuring VMP skeleton")
message(STATUS "  VMP_PLATFORM=${VMP_PLATFORM}")
message(STATUS "  VMP_ARCH=${VMP_ARCH}")
message(STATUS "  VMP_WITH_JIT=${VMP_WITH_JIT}")
message(STATUS "  VMP_WITH_VM2=${VMP_WITH_VM2}")

include(GNUInstallDirs)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
enable_testing()

add_library(vmp_build_options INTERFACE)
target_compile_features(vmp_build_options INTERFACE cxx_std_17)
target_compile_definitions(vmp_build_options INTERFACE
  VMP_WITH_JIT=$<BOOL:${VMP_WITH_JIT}>
  VMP_WITH_VM2=$<BOOL:${VMP_WITH_VM2}>
  VMP_PLATFORM_STR="${VMP_PLATFORM}"
  VMP_ARCH_STR="${VMP_ARCH}"
)
if(MSVC)
  target_compile_options(vmp_build_options INTERFACE /Oy-)
else()
  target_compile_options(vmp_build_options INTERFACE -fno-omit-frame-pointer)
endif()

function(vmp_add_placeholder_library target)
  cmake_parse_arguments(ARG "" "HEADER;SOURCE" "INCLUDES" ${ARGN})
  add_library(${target} STATIC ${ARG_SOURCE})
  target_link_libraries(${target} PUBLIC vmp_build_options)
  target_include_directories(${target} PUBLIC ${ARG_INCLUDES})
endfunction()

function(vmp_add_placeholder_tool target source)
  add_executable(${target} ${source})
  target_link_libraries(${target} PRIVATE vmp_build_options)
  set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools)
endfunction()

add_subdirectory(policy)
add_subdirectory(analyzer)
add_subdirectory(planner)
add_subdirectory(backends)
add_subdirectory(runtime)
add_subdirectory(loader)
add_subdirectory(arch)
add_subdirectory(bindings/cpp)
add_subdirectory(tools)
add_subdirectory(tests)
