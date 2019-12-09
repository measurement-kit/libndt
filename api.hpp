// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_LIBNDT_API_HPP
#define MEASUREMENT_KIT_LIBNDT_API_HPP

// TODO(bassosimone): run through cppcheck and attempt to minimize warnings.

/// \file libndt.hpp
///
/// \brief Public header of measurement-kit/libndt. The basic usage is a simple
/// as creating a `libndt::Client c` instance and then calling `c.run()`. More
/// advanced usage may require you to create a subclass of `libndt::Client` and
/// override specific virtual methods to customize the behaviour.
///
/// This implementation provides the C2S and S2C NDT subtests. We implement
/// NDT over TLS and NDT over websocket. For more information on the NDT
/// protocol, \see https://github.com/ndt-project/ndt/wiki/NDTProtocol.
///
/// The NDT protocol described above is version 5 (aka ndt5). The code in this
/// library also implements the ndt7 specification, which is described at
/// \see https://github.com/m-lab/ndt-server/blob/master/spec/ndt7-protocol.md.
///
/// Throughout this file, we'll use NDT to indicate ndt5 and ndt7 explicitly
/// to indicate version 7 of the protocol. Please, use ndt7 in newer code and
/// stick to ndt5 only if backwards compatibility is necessary.
///
/// \remark As a general rule, what is not documented using Doxygen comments
/// inside of this file is considered either internal or experimental. We
/// recommend you to only use documented interfaces.
///
/// Usage example follows. We assume that you have downloaded the single include
/// headers of nlohmann/json >= 3.0.0 and of libndt.
///
/// ```
/// #include "json.hpp"
/// #include "libndt.hpp"
/// measurement_kit::libndt::Client client;
/// client.run();
/// ```
///
/// \warning Not including nlohmann/json before including libndt will cause
/// the build to fail, because libndt uses nlohmann/json symbols.

// Check dependencies
// ``````````````````
#ifndef NLOHMANN_JSON_VERSION_MAJOR
#error "Libndt depends on nlohmann/json. Include nlohmann/json before including libndt."
#endif  // !NLOHMANN_JSON_VERSION_MAJOR
#if NLOHMANN_JSON_VERSION_MAJOR < 3
#error "Libndt requires nlohmann/json >= 3"
#endif

// TODO(bassosimone): these headers should be in impl.hpp and here we
// need to include the bare minimum required by the API

#ifndef _WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <assert.h>
#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <curl/curl.h>

namespace measurement_kit {
namespace libndt {

// Versioning
// ``````````

/// Type containing a version number.
using Version = unsigned int;

/// Major API version number of measurement-kit/libndt.
constexpr Version version_major = Version{0};

/// Minor API version number of measurement-kit/libndt.
constexpr Version version_minor = Version{27};

/// Patch API version number of measurement-kit/libndt.
constexpr Version version_patch = Version{0};

// Flags for selecting subtests
// ````````````````````````````

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

// Verbosity levels
// ````````````````

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

// Flags for selecting what NDT protocol features to use
// `````````````````````````````````````````````````````

/// Flags to select what protocol should be used.
using ProtocolFlags = unsigned int;

/// When this flag is set we use JSON messages. This specifically means that
/// we send and receive JSON messages (as opposed to raw strings).
constexpr ProtocolFlags protocol_flag_json = ProtocolFlags{1 << 0};

/// When this flag is set we use TLS. This specifically means that we will
/// use TLS channels for the control and the measurement connections.
constexpr ProtocolFlags protocol_flag_tls = ProtocolFlags{1 << 1};

/// When this flag is set we use WebSocket. This specifically means that
/// we use the WebSocket framing to encapsulate NDT messages.
constexpr ProtocolFlags protocol_flag_websocket = ProtocolFlags{1 << 2};

/// When this flag is set, we use ndt7 rather than ndt5. This specifically
/// means that a totally different protocol is used. You can read more on ndt7
/// at https://github.com/m-lab/ndt-server/blob/master/spec/ndt7-protocol.md
constexpr ProtocolFlags protocol_flag_ndt7 = ProtocolFlags{1 << 3};

// Policy for auto-selecting a NDT server
// ``````````````````````````````````````

/// Flags modifying the behavior of mlab-ns. Mlab-ns is the web service used
/// to automatically discover NDT's (and other experiments') servers.
using MlabnsPolicy = unsigned short;

/// Request just the closest NDT server.
constexpr MlabnsPolicy mlabns_policy_closest = MlabnsPolicy{0};

/// Request for a random NDT server.
constexpr MlabnsPolicy mlabns_policy_random = MlabnsPolicy{1};

/// Return a list of nearby NDT servers. When more than one server is returned
/// all the available servers will be tried in case some of them are down.
constexpr MlabnsPolicy mlabns_policy_geo_options = MlabnsPolicy{2};

// NDT message types
// `````````````````
// See <https://github.com/ndt-project/ndt/wiki/NDTProtocol#message-types>.

using MsgType = unsigned char;
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

// Settings
// ````````

/// Timeout expressed in seconds.
using Timeout = unsigned int;

constexpr const char *ndt_version_compat = "v3.7.0";

/// NDT client settings. If you do not customize the settings when creating
/// a Client, the defaults listed below will be used instead.
class Settings {
 public:
  /// Base URL to be used to query the mlab-ns service. If you specify an
  /// explicit hostname, mlab-ns won't be used. Note that the URL specified
  /// here MUST NOT end with a final slash.
  std::string mlabns_base_url = "https://locate.measurementlab.net";

  /// Flags that modify the behavior of mlabn-ns. By default we use the
  /// geo_options policy that is the most robust to random server failures.
  MlabnsPolicy mlabns_policy = mlabns_policy_geo_options;

  /// Timeout used for I/O operations.
  Timeout timeout = Timeout{7} /* seconds */;

  /// Host name of the NDT server to use. If this is left blank (the default),
  /// we will use mlab-ns to discover a nearby server.
  std::string hostname;

  /// Port of the NDT server to use. If this is not specified, we will use
  /// the most correct port depending on the configuration.
  std::string port;

  /// The tests you want to run with the NDT server. By default we run
  /// a download test, because that is probably the typical usage.
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

  /// Type of NDT protocol that you want to use. Selecting the protocol may
  /// cause libndt to use different default settings for the port or for
  /// mlab-ns. Clear text NDT uses port 3001, NDT-over-TLS uses 3010. There
  /// will most likely be servers listening on port 443 in the future, but
  /// they will only support the TLS+WebSocket protocol.
  ProtocolFlags protocol_flags = ProtocolFlags{0};

  /// Maximum time for which a nettest (i.e. download) is allowed to run. After
  /// this time has elapsed, the code will stop downloading (or uploading). It
  /// is meant as a safeguard to prevent the test for running for much more time
  /// than anticipated, due to buffering and/or changing network conditions.
  Timeout max_runtime = Timeout{14} /* seconds */;

  /// SOCKSv5h port to use for tunnelling traffic using, e.g., Tor. If non
  /// empty, all DNS and TCP traffic should be tunnelled over such port.
  std::string socks5h_port;

  /// CA bundle path to be used to verify TLS connections. If you do not
  /// set this variable and you're on Unix, we'll attempt to use some reasonable
  /// default value. Otherwise, the test will fail (unless you set the
  /// tls_verify_peer setting to false, indicating that you do not care about
  /// verifying the peer -- insecure, not recommended).
  std::string ca_bundle_path;

  /// Whether to use the CA bundle and OpenSSL's builtin hostname validation to
  /// make sure we are talking to the correct host. Enabled by default, but it
  /// may be useful sometimes to disable it for testing purposes. You should
  /// not disable this option in general, since doing that is insecure.
  bool tls_verify_peer = true;
};

// Error codes
// ```````````

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

// Client
// ``````

// Sys contains system dependent routines
class Sys;

/// NDT client. In the typical usage, you just need to construct a Client,
/// optionally providing settings, and to call the run() method. More advanced
/// usage may require you to override methods in a subclass to customize the
/// default behavior. For instance, you may probably want to override the
/// on_result() method that is called when processing NDT results to either
/// show such results to a user or store them on the disk.
class Client {
 public:
  /// Constructs a Client with default settings.
  Client() noexcept;

  /// Deleted copy constructor.
  Client(const Client &) noexcept = delete;

  /// Deleted copy assignment.
  Client &operator=(const Client &) noexcept = delete;

  /// Deleted move constructor.
  Client(Client &&) noexcept = delete;

  /// Deleted move assignment.
  Client &operator=(Client &&) noexcept = delete;

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
  /// the warning onto the `std::clog` standard stream. \warning This method
  /// could be called from a different thread context.
  virtual void on_warning(const std::string &s) const;

  /// Called when an informational message is emitted. The default behavior is
  /// to write the message onto the `std::clog` standard stream. \warning This method
  /// could be called from a different thread context.
  virtual void on_info(const std::string &s) const;

  /// Called when a debug message is emitted. The default behavior is
  /// to write the message onto the `std::clog` standard stream. \warning This method
  /// could be called from a different thread context.
  virtual void on_debug(const std::string &s) const;

  /// Called to inform you about the measured speed. The default behavior is
  /// to write the provided information as an info message. @param tid is either
  /// nettest_flag_download or nettest_flag_upload. @param nflows is the number
  /// of used flows. @param measured_bytes is the number of bytes received
  /// or sent since the beginning of the measurement. @param elapsed
  /// is the number of seconds elapsed since the beginning of the nettest.
  /// @param max_runtime is the maximum runtime of this nettest, as copied from
  /// the Settings. @remark By dividing @p elapsed by @p max_runtime, you can
  /// get the percentage of completion of the current nettest. @remark We
  /// provide you with @p tid, so you know whether the nettest is downloading
  /// bytes from the server or uploading bytes to the server. \warning This
  /// method could be called from another thread context.
  virtual void on_performance(NettestFlags tid, uint8_t nflows,
                              double measured_bytes, double elapsed,
                              double max_runtime);

  /// Called to provide you with NDT results. The default behavior is
  /// to write the provided information as an info message. @param scope is
  /// "web100", when we're passing you Web 100 variables, "tcp_info" when
  /// we're passing you TCP info variables, "summary" when we're passing you
  /// summary variables, or "ndt7" when we're passing you results returned
  /// by a ndt7 server. @param name is the name of the variable; if @p scope
  /// is "ndt7", then @p name should be "download". @param value is the
  /// variable value; variables are typically int, float, or string when
  /// running ndt5 tests, instead they are serialized JSON returned by the
  /// server when running a ndt7 test. \warning This method could be called
  /// from another thread context.
  virtual void on_result(std::string scope, std::string name,
                         std::string value);

  /// Called when the server is busy. The default behavior is to write a
  /// warning message. @param msg is the reason why the server is busy, encoded
  /// according to the NDT protocol. @remark when Settings::hostname is empty,
  /// we will autodiscover one or more servers, depending on the configured
  /// policy; in the event in which we autodiscover more than one server, we
  /// will attempt to use each of them, hence, this method may be called more
  /// than once if some of these servers happen to be busy. \warning This
  /// method could be called from another thread context.
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
  // SWIG should not see anything below this point otherwise it will attempt
  // to create wrappers for that. TODO(bassosimone): it should be evaluated in
  // the future whether it makes sense enforcing `protected` here. This is
  // certainly feasible but would require some refactoring.
#ifdef SWIG
 private:
#endif

  // High-level API
  virtual void summary() noexcept;
  virtual bool query_mlabns(std::vector<std::string> *) noexcept;
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

  // ndt7 protocol API
  // `````````````````
  //
  // This API allows you to perform ndt7 tests. The plan is to increasingly
  // use ndt7 code and eventually deprecate and remove NDT.
  //
  // Note that we cannot have ndt7 without OpenSSL.

  // ndt7_download performs a ndt7 download. Returns true if the download
  // succeeds and false in case of failure.
  bool ndt7_download() noexcept;

  // ndt7_upload is like ndt7_download but performs an upload.
  bool ndt7_upload() noexcept;

  // ndt7_connect connects to @p url_path.
  bool ndt7_connect(std::string url_path) noexcept;

  // NDT protocol API
  // ````````````````
  //
  // This API allows to send and receive NDT messages. At the bottom of the
  // abstraction layer lie functions to send and receive NDT's binary protocol
  // which here is called "legacy". It's called like this because it's still
  // the original protocol, AFAIK, even though several additions were layered
  // on top of it over the years (i.e. websocket, JSON, and TLS).

  bool msg_write_login(const std::string &version) noexcept;

  virtual bool msg_write(MsgType code, std::string &&msg) noexcept;

  virtual bool msg_write_legacy(MsgType code, std::string &&msg) noexcept;

  virtual bool msg_expect_test_prepare(  //
      std::string *pport, uint8_t *pnflows) noexcept;

  virtual bool msg_expect_empty(MsgType code) noexcept;

  virtual bool msg_expect(MsgType code, std::string *msg) noexcept;

  virtual bool msg_read(MsgType *code, std::string *msg) noexcept;

  virtual bool msg_read_legacy(MsgType *code, std::string *msg) noexcept;

  // WebSocket
  // `````````
  //
  // This section contain a WebSocket implementation.

  // Send @p line over @p fd.
  virtual Err ws_sendln(Socket fd, std::string line) noexcept;

  // Receive shorter-than @p maxlen @p *line over @p fd.
  virtual Err ws_recvln(Socket fd, std::string *line, size_t maxlen) noexcept;

  // Perform websocket handshake. @param fd is the socket to use. @param
  // ws_flags specifies what headers to send and to expect (for more information
  // see the ws_f_xxx constants defined below). @param ws_protocol specifies
  // what protocol to specify as Sec-WebSocket-Protocol in the upgrade request.
  // @param port is used to construct the Host header. @param url_path is the
  // URL path to use for performing the websocket upgrade.
  virtual Err ws_handshake(Socket fd, std::string port, uint64_t ws_flags,
                           std::string ws_protocol,
                           std::string url_path) noexcept;

  // Prepare and return a WebSocket frame containing @p first_byte and
  // the content of @p base and @p count as payload. If @p base is nullptr
  // then we'll just not include a body in the prepared frame.
  virtual std::string ws_prepare_frame(uint8_t first_byte, uint8_t *base,
                                       Size count) const noexcept;

  // Send @p count bytes from @p base over @p sock as a frame whose first byte
  // @p first_byte should contain the opcode and possibly the FIN flag.
  virtual Err ws_send_frame(Socket sock, uint8_t first_byte, uint8_t *base,
                            Size count) const noexcept;

  // Receive a frame from @p sock. Puts the opcode in @p *opcode. Puts whether
  // there is a FIN flag in @p *fin. The buffer starts at @p base and it
  // contains @p total bytes. Puts in @p *count the actual number of bytes
  // in the message. @return The error that occurred or Err::none.
  Err ws_recv_any_frame(Socket sock, uint8_t *opcode, bool *fin, uint8_t *base,
                        Size total, Size *count) const noexcept;

  // Receive a frame. Automatically and transparently responds to PING, ignores
  // PONG, and handles CLOSE frames. Arguments like ws_recv_any_frame().
  Err ws_recv_frame(Socket sock, uint8_t *opcode, bool *fin, uint8_t *base,
                    Size total, Size *count) const noexcept;

  // Receive a message consisting of one or more frames. Transparently handles
  // PING and PONG frames. Handles CLOSE frames. @param sock is the socket to
  // use. @param opcode is where the opcode is returned. @param base is the
  // beginning of the buffer. @param total is the size of the buffer. @param
  // count contains the actual message size. @return An error on failure or
  // Err::none in case of success.
  Err ws_recvmsg(Socket sock, uint8_t *opcode, uint8_t *base, Size total,
                 Size *count) const noexcept;

  // Networking layer
  // ````````````````
  //
  // This section contains network functionality used by NDT. The functionality
  // to connect to a remote host is layered to comply with the websocket spec
  // as follows:
  //
  // - netx_maybews_dial() calls netx_maybessl_dial() and, if that succeeds, it
  //   then attempts to negotiate a websocket channel (if enabled);
  //
  // - netx_maybessl_dial() calls netx_maybesocks5h_dial() and, if that
  //   suceeds, it then attempts to establish a TLS connection (if enabled);
  //
  // - netx_maybesocks5h_dial() possibly creates the connection through a
  //   SOCKSv5h proxy (if the proxy is enabled).
  //
  // By default with TLS we use a CA and we perform SNI validation. That can be
  // disabled for debug reasons. Doing that breaks compliancy with the websocket
  // spec. See <https://tools.ietf.org/html/rfc6455#section-4.1>.

  // Connect to @p hostname and @p port possibly using WebSocket,
  // SSL, and SOCKSv5. This depends on the Settings. See the documentation
  // of ws_handshake() for more info on @p ws_flags, @p ws_protocol, and
  // @p url_path.
  virtual Err netx_maybews_dial(const std::string &hostname,
                                const std::string &port, uint64_t ws_flags,
                                std::string ws_protocol, std::string url_path,
                                Socket *sock) noexcept;

  // Connect to @p hostname and @p port possibly using SSL and SOCKSv5. This
  // depends on the Settings you configured.
  virtual Err netx_maybessl_dial(const std::string &hostname,
                                 const std::string &port,
                                 Socket *sock) noexcept;

  // Connect to @p hostname and @port possibly using SOCKSv5. This depends
  // on the Settings you configured.
  virtual Err netx_maybesocks5h_dial(const std::string &hostname,
                                     const std::string &port,
                                     Socket *sock) noexcept;

  // Map errno code into a Err value.
  static Err netx_map_errno(int ec) noexcept;

  // Map getaddrinfo return value into a Err value.
  Err netx_map_eai(int ec) noexcept;

  // Connect to @p hostname and @p port.
  virtual Err netx_dial(const std::string &hostname, const std::string &port,
                        Socket *sock) noexcept;

  // Receive from the network.
  virtual Err netx_recv(Socket fd, void *base, Size count,
                        Size *actual) const noexcept;

  // Receive from the network without blocking.
  virtual Err netx_recv_nonblocking(Socket fd, void *base, Size count,
                                    Size *actual) const noexcept;

  // Receive exactly N bytes from the network.
  virtual Err netx_recvn(Socket fd, void *base, Size count) const noexcept;

  // Send data to the network.
  virtual Err netx_send(Socket fd, const void *base, Size count,
                        Size *actual) const noexcept;

  // Send to the network without blocking.
  virtual Err netx_send_nonblocking(Socket fd, const void *base, Size count,
                                    Size *actual) const noexcept;

  // Send exactly N bytes to the network.
  virtual Err netx_sendn(
    Socket fd, const void *base, Size count) const noexcept;

  // Resolve hostname into a list of IP addresses.
  virtual Err netx_resolve(const std::string &hostname,
                           std::vector<std::string> *addrs) noexcept;

  // Set socket non blocking.
  virtual Err netx_setnonblocking(Socket fd, bool enable) noexcept;

  // Pauses until the socket becomes readable.
  virtual Err netx_wait_readable(Socket, Timeout timeout) const noexcept;

  // Pauses until the socket becomes writeable.
  virtual Err netx_wait_writeable(Socket, Timeout timeout) const noexcept;

  // Main function for dealing with I/O patterned after poll(2).
  virtual Err netx_poll(
    std::vector<pollfd> *fds, int timeout_msec) const noexcept;

  // Shutdown both ends of a socket.
  virtual Err netx_shutdown_both(Socket fd) noexcept;

  // Close a socket.
  virtual Err netx_closesocket(Socket fd) noexcept;

  // Dependencies (cURL)
  // ```````````````````
  //
  // This section contains functionality used by cURL.
  class CurlDeleter {
   public:
    void operator()(CURL *handle) noexcept;
  };
  using UniqueCurl = std::unique_ptr<CURL, CurlDeleter>;

  bool curlx_get_maybe_socks5(const std::string &proxy_port,
                              const std::string &url, long timeout,
                              std::string *body) noexcept;

  bool curlx_get(UniqueCurl &, const std::string &url, long timeout,
                 std::string *body) noexcept;

  virtual CURLcode curlx_setopt_url(
                UniqueCurl &, const std::string &url) noexcept;

  virtual CURLcode curlx_setopt_proxy(UniqueCurl &,
                const std::string &url) noexcept;

  virtual CURLcode curlx_setopt_writefunction(UniqueCurl &, size_t (*callback)(
      char *ptr, size_t size, size_t nmemb, void *userdata)) noexcept;

  virtual CURLcode curlx_setopt_writedata(UniqueCurl &, void *pointer) noexcept;

  virtual CURLcode curlx_setopt_timeout(UniqueCurl &, long timeout) noexcept;

  virtual CURLcode curlx_setopt_failonerror(UniqueCurl &) noexcept;

  virtual CURLcode curlx_perform(UniqueCurl &) noexcept;

  virtual UniqueCurl curlx_easy_init() noexcept;

  virtual CURLcode curlx_getinfo_response_code(
    UniqueCurl &handle, long *response_code) noexcept;

  virtual bool query_mlabns_curl(const std::string &url, long timeout,
                                 std::string *body) noexcept;

  // Other helpers

  Verbosity get_verbosity() const noexcept;

  // Reference to overridable system dependencies
  std::unique_ptr<Sys> sys{new Sys{}};

 private:
  class Winsock {
   public:
    Winsock() noexcept;
    Winsock(const Winsock &) = delete;
    Winsock &operator=(const Winsock &) = delete;
    Winsock(Winsock &&) = delete;
    Winsock &operator=(Winsock &&) = delete;
    ~Winsock() noexcept;
  };

  Socket sock_ = (Socket)-1;
  std::vector<NettestFlags> granted_suite_;
  Settings settings_;

  nlohmann::json web100_;
  double download_speed_;
  double upload_speed_;
  double retransmission_rate_;

  std::map<Socket, SSL *> fd_to_ssl_;
#ifdef _WIN32
  Winsock winsock_;
#endif
};

}  // namespace libndt
}  // namespace measurement_kit
#endif
