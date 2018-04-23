cmake_minimum_required(VERSION 3.1.0)
project(libndt LANGUAGES CXX)

# Conan

include("${CMAKE_BINARY_DIR}/conanbuildinfo.cmake" OPTIONAL
        RESULT_VARIABLE CONAN_BUILDINFO_CMAKE)
if(NOT ("${CONAN_BUILDINFO_CMAKE}" STREQUAL "NOTFOUND"))
  conan_basic_setup()
  set(CMAKE_REQUIRED_INCLUDES ${CONAN_INCLUDE_DIRS})
endif()

# Checks

include(CheckIncludeFileCXX)
include(CheckFunctionExists)

check_function_exists(strtonum HAVE_STRTONUM)
if(${HAVE_STRTONUM})
  add_definitions(-DHAVE_STRTONUM)
endif()

check_include_file_cxx("nlohmann/json.hpp" HAVE_NLOHMANN_JSON
                       "${CMAKE_CXX11_STANDARD_COMPILE_OPTION}")
if(NOT (${HAVE_NLOHMANN_JSON}))
  message(FATAL_ERROR "nlohmann/json missing on your system")
endif()

check_include_file_cxx("argh.h" HAVE_ARGH_H
                       "${CMAKE_CXX11_STANDARD_COMPILE_OPTION}")
if(NOT (${HAVE_ARGH_H}))
  message(FATAL_ERROR "adishavit/argh missing on your system")
endif()

find_package(CURL)

# Compiler flags

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if("${UNIX}" OR "${MINGW}")
  set(LIBNDT_FLAGS "-Wall -Wextra -Werror")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBNDT_FLAGS} -Wmissing-prototypes")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LIBNDT_FLAGS}")
  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # for GCC, -Wmissing-prototypes only works for C/ObjC.
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wmissing-prototypes")
  endif()
endif()

if(${WIN32})
  add_definitions(-D_WIN32_WINNT=0x0600) # for NI_NUMERICSERV
endif()

# Library

add_library(
  ndt
  STATIC
  libndt.cpp
  libndt.hpp
  strtonum.c.h
)
target_include_directories(
  ndt
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CONAN_INCLUDE_DIRS}
)
install(
  FILES
  libndt.hpp
  DESTINATION
  include/measurement_kit/libndt
)
install(
  TARGETS
  ndt
  DESTINATION
  lib
)
if("${WIN32}" OR "${MINGW}")
  target_link_libraries(ndt ws2_32)
  if ("${MINGW}")
    target_link_libraries(ndt -static-libgcc -static-libstdc++)
  endif()
endif()

# Testing

set(BUILD_TESTING ON CACHE BOOL "Whether to build tests")
enable_testing()

if(${BUILD_TESTING}) # is a standard name in CMake-land
  if(${CURL_FOUND})
    add_executable(client client.cpp)
    target_include_directories(
      ndt
      PUBLIC
      ${CURL_INCLUDE_DIRS}
    )
    target_link_libraries(client ndt ${CURL_LIBRARIES} ${CONAN_LIBS})
    add_test(
      NAME simple_download_test
      COMMAND client --verbose --download
    )
    add_test(
      NAME simple_upload_test
      COMMAND client --verbose --json --upload
    )
  else()
    message(WARNING "cURL not found: cannot build example client")
  endif()
endif()
