cmake_minimum_required(VERSION 3.1.0)
project(libndt LANGUAGES CXX)

# Settings

set(LIBNDT_OPENSSL "${LIBNDT_OPENSSL}" CACHE PATH
    "Path where OpenSSL is installed")
if(NOT ("${LIBNDT_OPENSSL}" STREQUAL ""))
  list(APPEND CMAKE_REQUIRED_INCLUDES "${LIBNDT_OPENSSL}/include")
  list(APPEND CMAKE_LIBRARY_PATH "${LIBNDT_OPENSSL}/lib")
endif()

# Download header only dependencies

message(STATUS "Downloading adishavit/argh")
file(DOWNLOAD https://raw.githubusercontent.com/adishavit/argh/v1.2.1/argh.h
     "${CMAKE_CURRENT_BINARY_DIR}/argh.h" EXPECTED_HASH
     SHA256=ca14a63ea5be5b924019b4844218142936b6f4e3ef57dfe4c81ba35a7f07004e
     TLS_VERIFY ON SHOW_PROGRESS)

message(STATUS "Downloading nlohmann/json")
file(DOWNLOAD https://raw.githubusercontent.com/nlohmann/json/v3.1.2/single_include/nlohmann/json.hpp
     "${CMAKE_CURRENT_BINARY_DIR}/json.hpp" EXPECTED_HASH
     SHA256=fbdfec4b4cf63b3b565d09f87e6c3c183bdd45c5be1864d3fcb338f6f02c1733
     TLS_VERIFY ON SHOW_PROGRESS)

message(STATUS "Downloading catchorg/Catch2")
file(DOWNLOAD https://github.com/catchorg/Catch2/releases/download/v2.2.2/catch.hpp
     "${CMAKE_CURRENT_BINARY_DIR}/catch.hpp" EXPECTED_HASH
     SHA256=e0e0d85b65ffaab0006160e2238d9761212e93182716fcc85a87863042932919
     TLS_VERIFY ON SHOW_PROGRESS)

set(LIBNDT_ENABLE_CURL "TRUE" CACHE BOOL "Whether to enable cURL")
if("${MSVC}" AND "${LIBNDT_ENABLE_CURL}")
  set(_CURL_BASEURL "https://github.com/measurement-kit/prebuilt/releases/download")
  set(_CURL_CHANNEL "testing")
  set(_CURL_HASH "75f291c6da7c1d66ac932a5002ccc60a59442f725f291491dfda3e3c1027475b")
  set(_CURL_VERSION "7.59.0-1")
  set(_CURL_URL "${_CURL_BASEURL}/${_CURL_CHANNEL}/windows-curl-${_CURL_VERSION}.tar.gz")
  message(STATUS "Downloading precompiled cURL: ${_CURL_URL}")
  file(DOWNLOAD "${_CURL_URL}"
       "${CMAKE_CURRENT_BINARY_DIR}/curl-prebuilt.tar.gz"
       EXPECTED_HASH SHA256=${_CURL_HASH}
       TLS_VERIFY ON SHOW_PROGRESS)
  execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf "curl-prebuilt.tar.gz"
                  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
                  RESULT_VARIABLE TAR_FAILURE)
  if("${TAR_FAILURE}")
    message(FATAL_ERROR "Cannot unpack cURL: ${TAR_FAILURE}")
  endif()
  if("${CMAKE_SIZEOF_VOID_P}" EQUAL 8)
    set(_CURL_ARCH x64)
  elseif("${CMAKE_SIZEOF_VOID_P}" EQUAL 4)
    set(_CURL_ARCH x86)
  else()
    message(FATAL_ERROR "No prebuilt cURL for your system")
  endif()
  list(APPEND CMAKE_INCLUDE_PATH "${CMAKE_BINARY_DIR}/MK_DIST/windows/curl/${_CURL_VERSION}/${_CURL_ARCH}/include")
  list(APPEND CMAKE_LIBRARY_PATH "${CMAKE_BINARY_DIR}/MK_DIST/windows/curl/${_CURL_VERSION}/${_CURL_ARCH}/lib")
  message(STATUS "CMAKE_INCLUDE_PATH: ${CMAKE_INCLUDE_PATH}")
  message(STATUS "CMAKE_LIBRARY_PATH: ${CMAKE_LIBRARY_PATH}")
  add_definitions(-DCURL_STATICLIB)
  list(APPEND LIBNDT_LIBS Crypt32)
endif()

# Checks

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckSymbolExists)

check_function_exists(strtonum LIBNDT_HAVE_STRTONUM)
if(${LIBNDT_HAVE_STRTONUM})
  add_definitions(-DLIBNDT_HAVE_STRTONUM)
endif()

check_symbol_exists(SO_NOSIGPIPE sys/socket.h LIBNDT_HAVE_SO_NOSIGPIPE)
if(${LIBNDT_HAVE_SO_NOSIGPIPE})
  add_definitions(-DLIBNDT_HAVE_SO_NOSIGPIPE)
endif()
check_symbol_exists(MSG_NOSIGNAL sys/socket.h LIBNDT_HAVE_MSG_NOSIGNAL)
if(${LIBNDT_HAVE_MSG_NOSIGNAL})
  add_definitions(-DLIBNDT_HAVE_MSG_NOSIGNAL)
endif()

check_include_files(openssl/ssl.h LIBNDT_HAVE_OPENSSL_SSL_H)
find_library(CRYPTO_LIBRARY crypto)
find_library(SSL_LIBRARY ssl)
if (NOT ("${LIBNDT_HAVE_OPENSSL_SSL_H}" STREQUAL "") AND NOT
    ("${CRYPTO_LIBRARY}" STREQUAL "CRYPTO_LIBRARY-NOTFOUND") AND NOT
    ("${SSL_LIBRARY}" STREQUAL "SSL_LIBRARY-NOTFOUND"))
  message(STATUS "crypto library: ${CRYPTO_LIBRARY}")
  list(APPEND LIBNDT_LIBS "${CRYPTO_LIBRARY}")
  message(STATUS "ssl library: ${SSL_LIBRARY}")
  list(APPEND LIBNDT_LIBS "${SSL_LIBRARY}")
  add_definitions(-DLIBNDT_HAVE_OPENSSL)
else()
  message(WARNING "OpenSSL not found; will disable TLS support")
endif()

if(${LIBNDT_ENABLE_CURL})
  find_package(CURL)
  if(${CURL_FOUND})
    add_definitions(-DLIBNDT_HAVE_CURL)
  endif()
endif()

# Compiler flags

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if("${UNIX}" OR "${MINGW}")
  set(LIBNDT_FLAGS "-Wall -Wextra -Werror")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBNDT_FLAGS} -Wmissing-prototypes")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LIBNDT_FLAGS}")
  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # for GCC, -Wmissing-prototypes only works for C/ObjC.
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wmissing-prototypes")
  endif()
elseif("${MSVC}")
  # TODO(bassosimone): extend this also to linker warnings.
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /WX")
endif()

if(${WIN32})
  add_definitions(-D_WIN32_WINNT=0x0600) # for NI_NUMERICSERV and WSAPoll
endif()

# Library and binary
# ------------------

set(LIBNDT_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    ${CURL_INCLUDE_DIRS} ${CMAKE_REQUIRED_INCLUDES})

add_executable(libndt-client libndt-client.cpp)
target_include_directories(libndt-client PUBLIC ${LIBNDT_INCLUDES})
list (APPEND LIBNDT_LIBS ${CURL_LIBRARIES})
install(FILES libndt.hpp DESTINATION include)
install(TARGETS libndt-client DESTINATION bin)
if("${WIN32}" OR "${MINGW}")
  list(APPEND LIBNDT_LIBS "ws2_32")
  if ("${MINGW}")
      list(APPEND LIBNDT_LIBS -static-libgcc -static-libstdc++)
  endif()
endif()
list(APPEND LIBNDT_LIBS Threads::Threads)
target_link_libraries(libndt-client "${LIBNDT_LIBS}")

# Testing
# -------
#
# We have two different settings for testing so that we can control
# whether to build and run tests also when we're a subrepository.

set(LIBNDT_ENABLE_TESTS "TRUE" CACHE BOOL "Whether to enable tests")
set(BUILD_TESTING "ON" CACHE BOOL "Whether to build tests")

if(${BUILD_TESTING} AND ${LIBNDT_ENABLE_TESTS})
  enable_testing()
  if(${CURL_FOUND})
    add_executable(tests-curl curlx_test.cpp)
    target_link_libraries(tests-curl "${LIBNDT_LIBS}")
    target_include_directories(tests-curl PUBLIC ${LIBNDT_INCLUDES})
    add_test(NAME curl_unit_tests COMMAND tests-curl)
  endif()
  add_executable(tests-libndt libndt_test.cpp strtonum_test.cpp)
  target_link_libraries(tests-libndt "${LIBNDT_LIBS}")
  target_include_directories(tests-libndt PUBLIC ${LIBNDT_INCLUDES})
  add_test(NAME other_unit_tests COMMAND tests-libndt)
  if(${CURL_FOUND}) # Some tests require cURL for mlab-ns
    add_test(NAME simple_test COMMAND libndt-client --verbose
             --download --upload)
    add_test(NAME json_test COMMAND libndt-client --verbose --json
             --download --upload)
    add_test(NAME websocket_test COMMAND libndt-client --verbose --websocket
             --download --upload)
    if(${UNIX})  # On UNIX We auto-discover the CA bundle path
      add_test(NAME tls_test COMMAND libndt-client --verbose --download
               --upload --tls --json)
      # This is how NDT should run
      add_test(NAME modern_test COMMAND libndt-client --verbose --download
               --upload --tls --json --websocket)
    endif()
  endif()
endif()
