cmake_minimum_required(VERSION 3.1.0)
project(libndt LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")
include(MkUtils)

# Settings

set(LIBNDT_OPENSSL "${LIBNDT_OPENSSL}" CACHE PATH
    "Path where OpenSSL is installed")
if(NOT ("${LIBNDT_OPENSSL}" STREQUAL ""))
  list(APPEND CMAKE_REQUIRED_INCLUDES "${LIBNDT_OPENSSL}/include")
  list(APPEND CMAKE_LIBRARY_PATH "${LIBNDT_OPENSSL}/lib")
endif()

# Download header only dependencies

MkDownloadAdishavitArgh()
MkDownloadNlohmannJson()
MkDownloadCatchorgCatch2()

set(LIBNDT_ENABLE_CURL "TRUE" CACHE BOOL "Whether to enable cURL")
if("${MSVC}" AND "${LIBNDT_ENABLE_CURL}")
  set(_CURL_BASEURL "https://github.com/measurement-kit/prebuilt/releases/download")
  set(_CURL_CHANNEL "testing")
  set(_CURL_HASH "c4321f05ac238d42f2487536c4fdd8e55af68a3f364008271fe3b6741c6b855f")
  set(_CURL_VERSION "7.61.0-1")
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

MkSetCompilerFlags()

# Library and binary
# ------------------

set(LIBNDT_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    ${CURL_INCLUDE_DIRS} ${CMAKE_REQUIRED_INCLUDES})

add_executable(libndt-client libndt-client.cpp)
target_include_directories(libndt-client PUBLIC ${LIBNDT_INCLUDES})
list (APPEND LIBNDT_LIBS ${CURL_LIBRARIES})
install(FILES libndt.hpp DESTINATION include/measurement_kit)
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

set(BUILD_TESTING "ON" CACHE BOOL "Whether to build tests")
if(${BUILD_TESTING})
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
