cmake_minimum_required(VERSION 3.1.0)
project(libndt LANGUAGES CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckLibraryExists)

check_function_exists(strtonum HAVE_STRTONUM)
if(${HAVE_STRTONUM})
  add_definitions(-DHAVE_STRTONUM)
endif()

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

add_library(
  ndt
  STATIC
  json.hpp
  libndt.cpp
  libndt.hpp
  strtonum.c.h
)
target_include_directories(
  ndt
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
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

set(LIBNDT_BUILD_EXAMPLES ON CACHE BOOL "Whether to build examples")
if(LIBNDT_BUILD_EXAMPLES)
  add_executable(
    client
    client.cpp
    argh.h
  )
  target_link_libraries(client ndt)
endif()

enable_testing()
if("${LIBNDT_ENABLE_CI_TESTING_}" AND "${UNIX}")
  # TODO(bassosimone): make this smoke test work on Windows.
  add_test(
    NAME simple_smoke_test
    COMMAND bash ${CMAKE_SOURCE_DIR}/.ci/test/smoke.sh "${CMAKE_BINARY_DIR}"
  )
endif()
