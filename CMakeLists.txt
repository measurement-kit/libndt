cmake_minimum_required(VERSION 3.1.0)
project(libndt LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")
include(MkUtils)

# Settings

set(LIBNDT_OPENSSL "${LIBNDT_OPENSSL}" CACHE PATH
    "Path where OpenSSL is installed")
if(NOT ("${LIBNDT_OPENSSL}" STREQUAL ""))
  list(APPEND CMAKE_REQUIRED_INCLUDES "${LIBNDT_OPENSSL}/include")
  list(APPEND CMAKE_LIBRARY_PATH "${LIBNDT_OPENSSL}/lib")
endif()

# Download dependencies
# ---------------------

MkDownloadAdishavitArgh()
MkDownloadNlohmannJson()
MkDownloadCatchorgCatch2()

set(LIBNDT_ENABLE_CURL "TRUE" CACHE BOOL "Whether to enable cURL")
if("${MSVC}" AND "${LIBNDT_ENABLE_CURL}")
  MkDownloadMeasurementKitPrebuiltWindowsCurl()
  list(APPEND CMAKE_INCLUDE_PATH "${MK_WINDOWS_CURL_INCLUDE_PATH}")
  list(APPEND CMAKE_LIBRARY_PATH "${MK_WINDOWS_CURL_LIBRARY_PATH}")
  add_definitions(${MK_WINDOWS_CURL_DEFINITIONS})
  list(APPEND LIBNDT_LIBS ${MK_WINDOWS_CURL_EXTRA_LINK_LIBS})
endif()

# Checks
# ------

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
install(FILES libndt.hpp DESTINATION include/measurement-kit/libndt)
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
