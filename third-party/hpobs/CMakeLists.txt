cmake_minimum_required(VERSION 3.13)
project(hpobs CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_library(hpobs STATIC
  src/access_trace.cc
  src/elf.cc
  src/log.cc
  src/ptrace_target.cc
  src/symbols.cc
  src/watch.cc)
target_include_directories(hpobs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(hpobs PRIVATE -Wall -Wextra -Wno-unused-parameter)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(CAPSTONE capstone)
endif()
if(CAPSTONE_FOUND)
  target_include_directories(hpobs PRIVATE ${CAPSTONE_INCLUDE_DIRS})
  target_compile_definitions(hpobs PRIVATE HAVE_CAPSTONE=1)
  target_link_libraries(hpobs PUBLIC ${CAPSTONE_LDFLAGS})
  message(STATUS "capstone ${CAPSTONE_VERSION}: access tracing enabled")
else()
  message(STATUS "capstone not found: access tracing disabled")
endif()

option(HPOBS_BUILD_TOOLS "Build the hpobs-trace command" ON)
if(HPOBS_BUILD_TOOLS)
  add_executable(hpobs-trace tools/hpobs-trace.cc)
  target_link_libraries(hpobs-trace hpobs)
  target_compile_options(hpobs-trace PRIVATE -Wall -Wextra)
endif()
