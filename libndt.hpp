// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef LIBNDT_HPP
#define LIBNDT_HPP

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
/// #include <libndt.hpp>
/// measurement_kit::libndt::Client client;
/// client.run();
/// ```

#ifndef _WIN32
#include <sys/select.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifndef _WIN32
#include <netdb.h>
#endif
#include <stddef.h>
#include <stdint.h>  // IWYU pragma: export

#include <map>
#include <memory>
#include <string>
#include <vector>

/// Contains measurement-kit/libndt code.
namespace libndt {

/// Type containing a version number.
using Version = unsigned int;

/// Major API version number of measurement-kit/libndt.
constexpr Version version_major = Version{0};

/// Minor API version number of measurement-kit/libndt.
constexpr Version version_minor = Version{24};

/// Patch API version number of measurement-kit/libndt.
constexpr Version version_patch = Version{0};

/// Flags that indicate what subtests to run.
using NettestFlags = unsigned char;

constexpr NettestFlags nettest_flag_middlebox = NettestFlags{1U << 0};

/// Run the upload subtest.
constexpr NettestFlags nettest_flag_upload = NettestFlags{1U << 1};

/// Run the download subtest.
constexpr NettestFlags nettest_flag_download = NettestFlags{1U << 2};

constexpr NettestFlags nettest_flag_simple_firewall = NettestFlags{1U << 3};

constexpr NettestFlags nettest_flag_status = NettestFlags{1U << 4};

constexpr NettestFlags nettest_flag_meta = NettestFlags{1U << 5};

constexpr NettestFlags nettest_flag_upload_ext = NettestFlags{1U << 6};

/// Run the multi-stream download subtest.
constexpr NettestFlags nettest_flag_download_ext = NettestFlags{1U << 7};

/// Library's logging verbosity.
using Verbosity = unsigned int;

/// Do not emit any log message.
constexpr Verbosity verbosity_quiet = Verbosity{0};

/// Emit only warning messages.
constexpr Verbosity verbosity_warning = Verbosity{1};

/// Emit warning and informational messages.
constexpr Verbosity verbosity_info = Verbosity{2};

/// Emit all log messages.
constexpr Verbosity verbosity_debug = Verbosity{3};

constexpr const char *ndt_version_compat = "v3.7.0";

using Size = uint64_t;

using Ssize = int64_t;

using Socket = int64_t;

using SockLen = int;

/// Flags to select what protocol should be used.
using ProtocolFlags = unsigned int;

/// When this flag is set we use JSON messages. This specifically means that
/// we send and receive JSON messages (as opposed to raw strings).
constexpr ProtocolFlags protocol_flag_json = ProtocolFlags{1 << 0};

/// When this flag is set we use TLS. This specifically means that we will
/// use TLS channels for the control and the measurement connections.
constexpr ProtocolFlags protocol_flag_tls = ProtocolFlags{1 << 1};

/// When this flag is set we use WebSockets. This specifically means that
/// we use the WebSockets framing (as opposed to the original binary framing).
constexpr ProtocolFlags protocol_flag_websockets = ProtocolFlags{1 << 2};

enum class Err;  // Forward declaration (see bottom of this file)

/// Timeout expressed in seconds.
using Timeout = unsigned int;

/// NDT client settings. If you do not customize the settings when creating
/// a Client, the defaults listed below will be used instead.
class Settings {
 public:
  /// URL to be used to query the mlab-ns service. If you specify an explicit
  /// hostname, mlab-ns won't be used.
  std::string mlabns_url = "https://mlab-ns.appspot.com/ndt";

  /// Timeout used for I/O operations. \bug in v0.23.0 this timeout is only
  /// used for cURL operations, but this will be fixed in v0.24.0.
  Timeout timeout = Timeout{3} /* seconds */;

  /// Host name of the NDT server to use. If this is left blank (the default),
  /// we will use mlab-ns to discover a nearby server.
  std::string hostname;

  /// Port of the NDT server to use.
  std::string port = "3001";

  /// The tests you want to run with the NDT server.
  NettestFlags nettest_flags = nettest_flag_download;

  /// Verbosity of the client. By default no message is emitted. Set to other
  /// values to get more messages (useful when debugging).
  Verbosity verbosity = verbosity_quiet;

  /// Metadata to include in the server side logs. By default we just identify
  /// the NDT version and the application.
  std::map<std::string, std::string> metadata{
      {"client.version", ndt_version_compat},
      {"client.application", "measurement-kit/libndt"},
  };

  /// Type of NDT protocol that you want to use. Depending on the requested
  /// protocol, you may need to change also the port. By default, NDT listens
  /// on port 3001 for in-clear communications and port 3010 for TLS ones.
  ProtocolFlags protocol_flags = ProtocolFlags{0};

  /// Maximum time for which a nettest (i.e. download) is allowed to run. After
  /// this time has elapsed, the code will stop downloading (or uploading). It
  /// is meant as a safeguard to prevent the test for running for much more time
  /// than anticipated, due to buffering and/or changing network conditions.
  Timeout max_runtime = Timeout{14} /* seconds */;

  /// SOCKSv5h port to use for tunnelling traffic using, e.g., Tor. If non
  /// empty, all DNS and TCP traffic should be tunnelled over such port.
  std::string socks5h_port;
};

using MsgType = unsigned char;

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

  // Implementation note: currently SWIG does not propagate `noexcept` even
  // though that is implemented in master [1], hence we have removed this
  // qualifiers from the functions that SWIG needs to wrap.
  //
  // .. [1] https://github.com/swig/swig/issues/526

  /// Called when a warning message is emitted. The default behavior is to write
  /// the warning onto the `std::clog` standard stream.
  virtual void on_warning(const std::string &s);

  /// Called when an informational message is emitted. The default behavior is
  /// to write the warning onto the `std::clog` standard stream.
  virtual void on_info(const std::string &s);

  /// Called when a debug message is emitted. The default behavior is
  /// to write the warning onto the `std::clog` standard stream.
  virtual void on_debug(const std::string &s);

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
  virtual void on_performance(NettestFlags tid, uint8_t nflows,
                              double measured_bytes,
                              double measurement_interval, double elapsed,
                              double max_runtime);

  /// Called to provide you with NDT results. The default behavior is
  /// to write the provided information as an info message. @param scope is
  /// either "web100", when we're passing you Web 100 variables, "tcp_info" when
  /// we're passing you TCP info variables, or "summary" when we're passing you
  /// summary variables. @param name is the name of the variable. @param value
  /// is the variable value (variables are typically int, float, or string).
  virtual void on_result(std::string scope, std::string name,
                         std::string value);

  /// Called when the server is busy. The default behavior is to write a
  /// warning message. @param msg is the reason why the server is busy, encoded
  /// according to the NDT protocol.
  virtual void on_server_busy(std::string msg);

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
#ifdef SWIG
 private:
#endif

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

  bool msg_write_login(const std::string &version) noexcept;

  virtual bool msg_write(MsgType code, std::string &&msg) noexcept;

  virtual bool msg_write_legacy(MsgType code, std::string &&msg) noexcept;

  virtual bool msg_expect_test_prepare(  //
      std::string *pport, uint8_t *pnflows) noexcept;

  virtual bool msg_expect_empty(MsgType code) noexcept;

  virtual bool msg_expect(MsgType code, std::string *msg) noexcept;

  virtual bool msg_read(MsgType *code, std::string *msg) noexcept;

  virtual bool msg_read_legacy(MsgType *code, std::string *msg) noexcept;

  // Networking layer

  virtual Err netx_maybesocks5h_dial(const std::string &hostname,
                                     const std::string &port,
                                     Socket *sock) noexcept;

  static Err netx_map_errno(int ec) noexcept;

  Err netx_map_eai(int ec) noexcept;

  virtual Err netx_dial(const std::string &hostname, const std::string &port,
                        Socket *sock) noexcept;

  virtual Err netx_recv(Socket fd, void *base, Size count,
                        Size *actual) noexcept;

  virtual Err netx_recvn(Socket fd, void *base, Size count) noexcept;

  virtual Err netx_send(Socket fd, const void *base, Size count,
                        Size *actual) noexcept;

  virtual Err netx_sendn(Socket fd, const void *base, Size count) noexcept;

  virtual Err netx_resolve(const std::string &hostname,
                           std::vector<std::string> *addrs) noexcept;

  virtual Err netx_setnonblocking(Socket fd, bool enable) noexcept;

  virtual Err netx_select(int numfd, fd_set *readset, fd_set *writeset,
                          fd_set *exceptset, timeval *timeout) noexcept;

  // Dependencies (cURL)

  Verbosity get_verbosity() const noexcept;

  virtual bool query_mlabns_curl(const std::string &url, long timeout,
                                 std::string *body) noexcept;

  // Dependencies (libc)

  virtual int get_last_system_error() noexcept;
  virtual void set_last_system_error(int err) noexcept;

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

#ifdef _WIN32
  virtual int ioctlsocket(Socket s, long cmd, u_long *argp) noexcept;
#else
  virtual int fcntl2(Socket s, int cmd) noexcept;
  virtual int fcntl3i(Socket s, int cmd, int arg) noexcept;
#endif

  virtual int getsockopt(int socket, int level, int name, void *value,
                         SockLen *len) noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl;
};

enum class Err {
  none,
  broken_pipe,
  connection_aborted,
  connection_refused,
  connection_reset,
  host_unreachable,
  interrupted,
  invalid_argument,
  io_error,
  network_down,
  network_reset,
  network_unreachable,
  operation_in_progress,
  operation_would_block,
  timed_out,
  eof,
  ai_generic,
  ai_again,
  ai_fail,
  ai_noname,
  socks5h,
};

constexpr MsgType msg_comm_failure = MsgType{0};
constexpr MsgType msg_srv_queue = MsgType{1};
constexpr MsgType msg_login = MsgType{2};
constexpr MsgType msg_test_prepare = MsgType{3};
constexpr MsgType msg_test_start = MsgType{4};
constexpr MsgType msg_test_msg = MsgType{5};
constexpr MsgType msg_test_finalize = MsgType{6};
constexpr MsgType msg_error = MsgType{7};
constexpr MsgType msg_results = MsgType{8};
constexpr MsgType msg_logout = MsgType{9};
constexpr MsgType msg_waiting = MsgType{10};
constexpr MsgType msg_extended_login = MsgType{11};

}  // namespace libndt
#endif
