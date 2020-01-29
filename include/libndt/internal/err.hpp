// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_LIBNDT_INTERNAL_ERR_HPP
#define MEASUREMENT_KIT_LIBNDT_INTERNAL_ERR_HPP

// libndt/internal/err.hpp - definition of error

namespace measurement_kit {
namespace libndt {
namespace internal {

enum class Err {
  none,
  //
  // Error codes that map directly to errno values. Here we use the naming used
  // by the C++ library <https://en.cppreference.com/w/cpp/error/errc>.
  //
  broken_pipe,
  connection_aborted,
  connection_refused,
  connection_reset,
  function_not_supported,
  host_unreachable,
  interrupted,
  invalid_argument,
  io_error,
  message_size,
  network_down,
  network_reset,
  network_unreachable,
  operation_in_progress,
  operation_would_block,
  timed_out,
  value_too_large,
  //
  // Getaddrinfo() error codes. See <http://man.openbsd.org/gai_strerror>.
  //
  ai_generic,
  ai_again,
  ai_fail,
  ai_noname,
  //
  // SSL error codes. See <http://man.openbsd.org/SSL_get_error>.
  //
  ssl_generic,
  ssl_want_read,
  ssl_want_write,
  ssl_syscall,
  //
  // Libndt misc error codes.
  //
  eof,       // We got an unexpected EOF
  socks5h,   // SOCKSv5 protocol error
  ws_proto,  // WebSocket protocol error
};

}  // namespace internal
}  // namespace libndt
}  // namespace measurement_kit
#endif  // MEASUREMENT_KIT_LIBNDT_INTERNAL_ERR_HPP
