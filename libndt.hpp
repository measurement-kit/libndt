// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_LIBNDT_LIBNDT_HPP
#define MEASUREMENT_KIT_LIBNDT_LIBNDT_HPP

/// \file libndt.hpp
///
/// \brief Public header of measurement-kit/libndt. The basic usage is a simple
/// as creating a `libndt::Client c` instance and then calling `c.run()`. More
/// advanced usage may require you to create a subclass of `libndt::Client` and
/// override specific virtual methods to customize the behaviour.
///
/// \remark As a general rule, what is not documented using Doxygen comments
/// inside of this file is considered either internal or experimental. We
/// recommend you to only use documented interfaces.
///
/// \see https://github.com/ndt-project/ndt/wiki/NDTProtocol.
///
/// Usage example:
///
/// ```
/// measurement_kit::libndt::Client client;
/// client.run();
/// ```

#ifndef _WIN32
#include <sys/select.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <stddef.h>
#include <stdint.h>  // IWYU pragma: export

#include <map>
#include <memory>
#include <string>
#include <vector>

struct addrinfo;
struct sockaddr;
struct timeval;

/// Contains measurement-kit code.
namespace measurement_kit {

/// Contains measurement-kit/libndt code.
namespace libndt {

/// Contains version constants. You can use the constants defined in this
/// namespace at compile time to check whether the version of libndt you
/// are compiling against matches your expectations.
namespace version {

/// Major API version number of measurement-kit/libndt.
constexpr uint64_t api_major = 0;

/// Minor API version number of measurement-kit/libndt.
constexpr uint64_t api_minor = 23;

/// Patch API version number of measurement-kit/libndt.
constexpr uint64_t api_patch = 0;

} // namespace version

/// Contains nettests identifiers. You can run multiple nettests as part of
/// a single NDT transaction with a NDT server. To specify what nettests you
/// want to run, modify Settings::test_suite accordingly, by using the
/// constants contained inside of this namespace.
namespace nettest {

constexpr uint8_t middlebox = 1U << 0;

/// The upload net test.
constexpr uint8_t upload = 1U << 1;

/// The download net test.
constexpr uint8_t download = 1U << 2;

constexpr uint8_t simple_firewall = 1U << 3;

constexpr uint8_t status = 1U << 4;

constexpr uint8_t meta = 1U << 5;

constexpr uint8_t upload_ext = 1U << 6;

/// The multi-stream download net test.
constexpr uint8_t download_ext = 1U << 7;

} // namespace nettest

/// Constants used to control verbosity. You can pass these constants to
/// Settings::verbosity to control the verbosity level.
namespace verbosity {

/// Do not emit any log message.
constexpr uint64_t quiet = 0;

/// Emit only warning messages.
constexpr uint64_t warning = 1;

/// Emit warning and informational messages.
constexpr uint64_t info = 2;

/// Emit all log messages.
constexpr uint64_t debug = 3;

} // namespace verbosity

constexpr const char *ndt_version_compat = "v3.7.0";

/// Type containing the size of something.
using Size = uint64_t;

/// Type containing the signed size of something.
using Ssize = int64_t;

/// Type wide enough to contain a socket.
using Socket = int64_t;

/// Type wide enough to contain `socklen_t`.
using SockLen = int;

/// Contains flags definiting what protocol to use. Historically NDT used a
/// binary, cleartext protocol for communicating with the server. Historically
/// messages were raw strings framed using the binary framing.
namespace protocol {

/// When this flag is set we use JSON messages. This specifically means that
/// we send and receive JSON messages (as opposed to raw strings).
constexpr uint64_t json = (1 << 0);

/// When this flag is set we use TLS. This specifically means that we will
/// use TLS channels for the control and the measurement connections.
constexpr uint64_t tls = (1 << 1);

/// When this flag is set we use WebSockets. This specifically means that
/// we use the WebSockets framing (as opposed to the original binary framing).
constexpr uint64_t websockets = (1 << 2);

} // namespace protocol

/// NDT client settings. If you do not customize the settings when creating
/// a Client, the defaults listed below will be used instead.
class Settings {
 public:
  /// URL to be used to query the mlab-ns service. If you specify an explicit
  /// hostname, mlab-ns won't be used.
  std::string mlabns_url = "https://mlab-ns.appspot.com/ndt";

  /// cURL timeout used when querying mlab-ns. If you specify an explicit
  /// hostname, mlab-ns won't be used.
  long curl_timeout = 3 /* seconds */;

  /// Host name of the NDT server to use. If this is left blank (the default),
  /// we will use mlab-ns to discover a nearby server.
  std::string hostname;

  /// Port of the NDT server to use.
  std::string port = "3001";

  /// The tests you want to run with the NDT server.
  uint8_t test_suite = nettest::download;

  /// Verbosity of the client. By default no message is emitted. Set to other
  /// values to get more messages (useful when debugging).
  uint64_t verbosity = verbosity::quiet;

  /// Metadata to include in the server side logs. By default we just identify
  /// the NDT version and the application.
  std::map<std::string, std::string> metadata{
      {"client.version", ndt_version_compat},
      {"client.application", "measurement-kit/libndt"},
  };

  /// Type of NDT protocol that you want to use. Depending on the requested
  /// protocol, you may need to change also the port. By default, NDT listens
  /// on port 3001 for in-clear communications and port 3010 for TLS ones.
  uint64_t proto = 0;

  /// Maximum time for which a nettest (i.e. download) is allowed to run. After
  /// this time has elapsed, the code will stop downloading (or uploading). It
  /// is meant as a safeguard to prevent the test for running for much more time
  /// than anticipated, due to buffering and/or changing network conditions.
  double max_runtime = 14 /* seconds */;

  /// SOCKSv5h port to use for tunnelling traffic using, e.g., Tor. If non
  /// empty, all DNS and TCP traffic should be tunnelled over such port.
  std::string socks5h_port;

  /// Path to OpenSSL-compatible CA bundle. If not provided, attempts to use
  /// the protocol::tls option will fail because there is no place from which
  /// to load the certificate authorities, so we cannot validate certs.
  std::string ca_bundle_path;
};

/// NDT client. In the typical usage, you just need to construct a Client,
/// optionally providing settings, and to call the run() method. More advanced
/// usage may require you to override methods in a subclass to customize the
/// default behavior. E.g., you may want to customize `recv` and `send`
/// to record when data is received and sent to the other endpoint.
class Client {
 public:
  // Implementation note: this is the classic implementation of the pimpl
  // pattern where we use a unique pointer, constructor and destructor are
  // defined in the ndt.cpp file so the code compiles, and copy/move
  // constructors and operators are not defined, thus resulting deleted.
  //
  // See <https://herbsutter.com/gotw/_100/>.

  /// Constructs a Client with default settings.
  Client() noexcept;

  /// Constructs a Client with the specified @p settings.
  explicit Client(Settings settings) noexcept;

  /// Destroys a Client.
  virtual ~Client() noexcept;

  /// Runs a NDT test using the configured (or default) settings.
  bool run() noexcept;

  /// Called when a warning message is emitted. The default behavior is to write
  /// the warning onto the `std::clog` standard stream.
  virtual void on_warning(const std::string &s) noexcept;

  /// Called when an informational message is emitted. The default behavior is
  /// to write the warning onto the `std::clog` standard stream.
  virtual void on_info(const std::string &s) noexcept;

  /// Called when a debug message is emitted. The default behavior is
  /// to write the warning onto the `std::clog` standard stream.
  virtual void on_debug(const std::string &s) noexcept;

  /// Called to inform you about the measured speed. The default behavior is
  /// to write the provided information as an info message. @param tid is either
  /// nettest_download or nettest_upload. @param nflows is the number of flows
  /// that we're using. @param measured_bytes is the number of bytes received
  /// or sent since the previous measurement. @param measurement_interval is the
  /// number of seconds elapsed since the previous measurement. @param elapsed
  /// is the number of seconds elapsed since the beginning of the nettest.
  /// @param max_runtime is the maximum runtime of this nettest, as copied from
  /// the Settings. @remark By dividing @p elapsed by @p max_runtime, you can
  /// get the percentage of completion of the current nettest. @remark We
  /// provide you with @p tid, so you know whether the nettest is downloading
  /// bytes from the server or uploading bytes to the server.
  virtual void on_performance(uint8_t tid, uint8_t nflows,
                              uint64_t measured_bytes,
                              double measurement_interval, double elapsed,
                              double max_runtime) noexcept;

  /// Called to provide you with NDT results. The default behavior is
  /// to write the provided information as an info message. @param scope is
  /// either "web100", when we're passing you Web 100 variables, "tcp_info" when
  /// we're passing you TCP info variables, or "summary" when we're passing you
  /// summary variables. @param name is the name of the variable. @param value
  /// is the variable value (variables are typically int, float, or string).
  virtual void on_result(std::string scope, std::string name,
                         std::string value) noexcept;

  /// Called when the server is busy. The default behavior is to write a
  /// warning message. @param msg is the reason why the server is busy, encoded
  /// according to the NDT protocol.
  virtual void on_server_busy(std::string msg) noexcept;

  /*
               _        __             _    _ _                _
   ___ _ _  __| |  ___ / _|  _ __ _  _| |__| (_)__   __ _ _ __(_)
  / -_) ' \/ _` | / _ \  _| | '_ \ || | '_ \ | / _| / _` | '_ \ |
  \___|_||_\__,_| \___/_|   | .__/\_,_|_.__/_|_\__| \__,_| .__/_|
                            |_|                          |_|
  */
  // If you're just interested to use measurement-kit/libndt, you can stop
  // reading right here. All the remainder of this file is not documented on
  // purpose and contains functionality that you'll typically don't care about
  // unless you're looking into heavily customizing this library.
  //
  // High-level API

  virtual bool query_mlabns() noexcept;
  virtual bool connect() noexcept;
  virtual bool send_login() noexcept;
  virtual bool recv_kickoff() noexcept;
  virtual bool wait_in_queue() noexcept;
  virtual bool recv_version() noexcept;
  virtual bool recv_tests_ids() noexcept;
  virtual bool run_tests() noexcept;
  virtual bool recv_results_and_logout() noexcept;
  virtual bool wait_close() noexcept;

  // Mid-level API

  virtual bool run_download() noexcept;
  virtual bool run_meta() noexcept;
  virtual bool run_upload() noexcept;

  // Low-level API

  virtual bool connect_tcp_maybe_socks5(const std::string &hostname,
                                        const std::string &port,
                                        Socket *sock) noexcept;

  virtual bool connect_tcp(const std::string &hostname, const std::string &port,
                           Socket *sock) noexcept;

  bool msg_write_login(const std::string &version) noexcept;

  virtual bool msg_write(uint8_t code, std::string &&msg) noexcept;

  virtual bool msg_write_legacy(uint8_t code, std::string &&msg) noexcept;

  virtual bool msg_expect_test_prepare(  //
      std::string *pport, uint8_t *pnflows) noexcept;

  virtual bool msg_expect_empty(uint8_t code) noexcept;

  virtual bool msg_expect(uint8_t code, std::string *msg) noexcept;

  virtual bool msg_read(uint8_t *code, std::string *msg) noexcept;

  virtual bool msg_read_legacy(uint8_t *code, std::string *msg) noexcept;

  // Utilities for low-level

  virtual Ssize recvn(Socket fd, void *base, Size count) noexcept;

  virtual Ssize sendn(Socket fd, const void *base, Size count) noexcept;

  virtual bool resolve(const std::string &hostname,
                       std::vector<std::string> *addrs) noexcept;

  // Utilities (SSL)

  virtual int maybessl_connect(const std::string &hostname, Socket fd,
                               const sockaddr *sa, SockLen n) noexcept;

  // Dependencies (cURL)

  virtual bool query_mlabns_curl(const std::string &url, long timeout,
                                 std::string *body) noexcept;

  // Dependencies (libc)

  virtual int get_last_error() noexcept;
  virtual void set_last_error(int err) noexcept;

  virtual int getaddrinfo(const char *domain, const char *port,
                          const addrinfo *hints, addrinfo **res) noexcept;
  virtual int getnameinfo(const sockaddr *sa, SockLen salen, char *host,
                          SockLen hostlen, char *serv, SockLen servlen,
                          int flags) noexcept;
  virtual void freeaddrinfo(addrinfo *aip) noexcept;

  virtual Socket socket(int domain, int type, int protocol) noexcept;
  virtual int connect(Socket fd, const sockaddr *sa, SockLen n) noexcept;
  virtual Ssize recv(Socket fd, void *base, Size count) noexcept;
  virtual Ssize send(Socket fd, const void *base, Size count) noexcept;
  virtual int shutdown(Socket fd, int how) noexcept;
  virtual int closesocket(Socket fd) noexcept;

  virtual int select(int numfd, fd_set *readset, fd_set *writeset,
                     fd_set *exceptset, timeval *timeout) noexcept;

  virtual long long strtonum(const char *s, long long minval, long long maxval,
                             const char **err) noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl;
};

constexpr uint8_t msg_comm_failure = 0;
constexpr uint8_t msg_srv_queue = 1;
constexpr uint8_t msg_login = 2;
constexpr uint8_t msg_test_prepare = 3;
constexpr uint8_t msg_test_start = 4;
constexpr uint8_t msg_test_msg = 5;
constexpr uint8_t msg_test_finalize = 6;
constexpr uint8_t msg_error = 7;
constexpr uint8_t msg_results = 8;
constexpr uint8_t msg_logout = 9;
constexpr uint8_t msg_waiting = 10;
constexpr uint8_t msg_extended_login = 11;

}  // namespace libndt
}  // namespace measurement_kit
#endif
