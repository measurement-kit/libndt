// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt.hpp"

#ifndef _WIN32
#include <arpa/inet.h>   // IWYU pragma: keep
#include <sys/select.h>  // IWYU pragma: keep
#include <sys/socket.h>

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <assert.h>
#include <string.h>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <utility>
#include <vector>

#include "curlx.hpp"
#include "json.hpp"
#include "strtonum.h"

namespace measurement_kit {
namespace libndt {

// Private constants

constexpr auto max_loops = 256;

constexpr char msg_kickoff[] = "123456 654321";
constexpr size_t msg_kickoff_size = sizeof(msg_kickoff) - 1;

// Private utils

#define EMIT_WARNING(statements)                          \
  do {                                                    \
    if (impl->settings.verbosity >= verbosity::warning) { \
      std::stringstream ss;                               \
      ss << statements;                                   \
      on_warning(ss.str());                               \
    }                                                     \
  } while (0)

#define EMIT_INFO(statements)                          \
  do {                                                 \
    if (impl->settings.verbosity >= verbosity::info) { \
      std::stringstream ss;                            \
      ss << statements;                                \
      on_info(ss.str());                               \
    }                                                  \
  } while (0)

#define EMIT_DEBUG(statements)                          \
  do {                                                  \
    if (impl->settings.verbosity >= verbosity::debug) { \
      std::stringstream ss;                             \
      ss << statements;                                 \
      on_debug(ss.str());                               \
    }                                                   \
  } while (0)

#ifdef _WIN32
#define OS_ERROR_IS_EINTR() (false)
#define OS_SHUT_RDWR SD_BOTH
#define AS_OS_SOCKET(s) ((SOCKET)s)
#else
#define OS_ERROR_IS_EINTR() (errno == EINTR)
#define OS_SHUT_RDWR SHUT_RDWR
#define AS_OS_SOCKET(s) ((int)s)
#endif

class Client::Impl {
 public:
  Socket sock = -1;
  std::vector<uint64_t> granted_suite;
  Settings settings;
};

static void random_printable_fill(char *buffer, size_t length) noexcept {
  static const std::string ascii =
      " !\"#$%&\'()*+,-./"          // before numbers
      "0123456789"                  // numbers
      ":;<=>?@"                     // after numbers
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  // uppercase
      "[\\]^_`"                     // between upper and lower
      "abcdefghijklmnopqrstuvwxyz"  // lowercase
      "{|}~"                        // final
      ;
  std::random_device rd;
  std::mt19937 g(rd());
  for (size_t i = 0; i < length; ++i) {
    buffer[i] = ascii[g() % ascii.size()];
  }
}

static double compute_speed(uint64_t data, double elapsed) noexcept {
  return (elapsed > 0.0) ? ((data * 8.0) / 1000.0 / elapsed) : 0.0;
}

static std::string represent(std::string message) noexcept {
  bool printable = true;
  for (auto &c : message) {
    if (c < ' ' || c > '~') {
      printable = false;
      break;
    }
  }
  if (printable) {
    return message;
  }
  std::stringstream ss;
  ss << "binary([";
  for (auto &c : message) {
    if (c <= ' ' || c > '~') {
      ss << "<0x" << std::fixed << std::setw(2) << std::setfill('0') << std::hex
         << (unsigned)(uint8_t)c << ">";
    } else {
      ss << (char)c;
    }
  }
  ss << "])";
  return ss.str();
}

static std::string trim(std::string s) noexcept {
  auto pos = s.find_first_not_of(" \t");
  if (pos != std::string::npos) {
    s = s.substr(pos);
  }
  pos = s.find_last_not_of(" \t");
  if (pos != std::string::npos) {
    s = s.substr(0, pos + 1);
  }
  return s;
}

static bool emit_result(Client *client, std::string scope,
                        std::string message) noexcept {
  std::stringstream ss{message};
  std::string line;
  while ((std::getline(ss, line, '\n'))) {
    std::vector<std::string> keyval;
    std::string token;
    std::stringstream ss{line};
    while ((std::getline(ss, token, ':'))) {
      keyval.push_back(token);
    }
    if (keyval.size() != 2) {
      return false;
    }
    client->on_result(scope, trim(std::move(keyval[0])),
                      trim(std::move(keyval[1])));
  }
  return true;
}

class SocketVector {
 public:
  SocketVector(Client *c) noexcept;
  ~SocketVector() noexcept;
  Client *owner = nullptr;
  std::vector<Socket> sockets;
};

SocketVector::SocketVector(Client *c) noexcept : owner{c} {}

SocketVector::~SocketVector() noexcept {
  if (owner != nullptr) {
    for (auto &fd : sockets) {
      owner->closesocket(fd);
    }
  }
}

// Constructor and destructor

Client::Client() noexcept { impl.reset(new Client::Impl); }

Client::Client(Settings settings) noexcept : Client::Client() {
  std::swap(impl->settings, settings);
}

Client::~Client() noexcept {
  if (impl->sock != -1) {
    this->closesocket(impl->sock);
  }
}

// Top-level API

bool Client::run() noexcept {
  if (!query_mlabns()) {
    return false;
  }
  if (!connect()) {
    return false;
  }
  EMIT_INFO("connected to remote host");
  if (!send_login()) {
    return false;
  }
  EMIT_INFO("sent login message");
  if (!recv_kickoff()) {
    return false;
  }
  EMIT_INFO("received kickoff message");
  if (!wait_in_queue()) {
    return false;
  }
  EMIT_INFO("authorized to run test");
  if (!recv_version()) {
    return false;
  }
  EMIT_INFO("received server version");
  if (!recv_tests_ids()) {
    return false;
  }
  EMIT_INFO("received tests ids");
  if (!run_tests()) {
    return false;
  }
  EMIT_INFO("finished running tests; now reading summary data:");
  if (!recv_results_and_logout()) {
    return false;
  }
  EMIT_INFO("received logout message");
  if (!wait_close()) {
    return false;
  }
  EMIT_INFO("connection closed");
  return true;
}

void Client::on_warning(const std::string &msg) noexcept {
  std::clog << "[!] " << msg << std::endl;
}

void Client::on_info(const std::string &msg) noexcept {
  std::clog << msg << std::endl;
}

void Client::on_debug(const std::string &msg) noexcept {
  std::clog << "[D] " << msg << std::endl;
}

void Client::on_performance(uint8_t tid, uint8_t nflows,
                            uint64_t measured_bytes, double measured_interval,
                            double elapsed_time, double max_runtime) noexcept {
  auto speed = compute_speed(measured_bytes, measured_interval);
  EMIT_INFO("  [" << std::fixed << std::setprecision(0) << std::setw(2)
                  << std::right << (elapsed_time * 100.0 / max_runtime) << "%]"
                  << " elapsed: " << std::fixed << std::setprecision(3)
                  << std::setw(6) << elapsed_time << " s;"
                  << " test_id: " << (int)tid << " num_flows: " << (int)nflows
                  << " speed: " << std::setprecision(0) << std::setw(8)
                  << std::right << speed << " kbit/s");
}

void Client::on_result(std::string scope, std::string name,
                       std::string value) noexcept {
  EMIT_INFO("  - [" << scope << "] " << name << ": " << value);
}

void Client::on_server_busy(std::string msg) noexcept {
  EMIT_WARNING("server is busy: " << msg);
}

// High-level API

bool Client::query_mlabns() noexcept {
  if (!impl->settings.hostname.empty()) {
    EMIT_DEBUG("no need to query mlab-ns; we have hostname");
    return true;
  }
  std::string body;
  if (!query_mlabns_curl(  //
          impl->settings.mlabns_url, impl->settings.curl_timeout, &body)) {
    return false;
  }
  nlohmann::json json;
  try {
    json = nlohmann::json::parse(body);
  } catch (const nlohmann::json::exception &exc) {
    EMIT_WARNING("cannot parse JSON: " << exc.what());
    return false;
  }
  try {
    impl->settings.hostname = json.at("fqdn");
  } catch (const nlohmann::json::exception &exc) {
    EMIT_WARNING("cannot access FQDN field: " << exc.what());
    return false;
  }
  EMIT_INFO("discovered host: " << impl->settings.hostname);
  return true;
}

bool Client::connect() noexcept {
  return netx_maybesocks5h_connect(impl->settings.hostname, impl->settings.port,
                                   &impl->sock) == Err::none;
}

bool Client::send_login() noexcept {
  return msg_write_login(ndt_version_compat);
}

bool Client::recv_kickoff() noexcept {
  char buf[msg_kickoff_size];
  auto err = netx_recvn(impl->sock, buf, sizeof(buf));
  if (err != Err::none) {
    // TODO(bassosimone): pretty print `err` not the last system error, because,
    // when we'll use also SSL, the latter will probably be inaccurate.
    EMIT_WARNING(
        "recv_kickoff: netx_recvn() failed: " << get_last_system_error());
    return false;
  }
  if (memcmp(buf, msg_kickoff, sizeof(buf)) != 0) {
    EMIT_WARNING("recv_kickoff: invalid kickoff message");
    return false;
  }
  return true;
}

bool Client::wait_in_queue() noexcept {
  std::string message;
  if (!msg_expect(msg_srv_queue, &message)) {
    return false;
  }
  // There is consensus among NDT developers that modern NDT should not
  // wait in queue rather it should fail immediately.
  if (message != "0") {
    on_server_busy(std::move(message));
    return false;
  }
  return true;
}

bool Client::recv_version() noexcept {
  std::string message;
  if (!msg_expect(msg_login, &message)) {
    return false;
  }
  // TODO(bassosimone): validate version number?
  EMIT_DEBUG("server version: " << message);
  return true;
}

bool Client::recv_tests_ids() noexcept {
  std::string message;
  if (!msg_expect(msg_login, &message)) {
    return false;
  }
  std::istringstream ss{message};
  std::string cur;
  while ((std::getline(ss, cur, ' '))) {
    const char *errstr = nullptr;
    uint8_t tid = (uint8_t)this->strtonum(cur.data(), 1, 256, &errstr);
    if (errstr != nullptr) {
      EMIT_WARNING("recv_tests_ids: found invalid test-id: "
                   << cur.data() << " (error: " << errstr << ")");
      return false;
    }
    impl->granted_suite.push_back(tid);
  }
  return true;
}

bool Client::run_tests() noexcept {
  for (auto &tid : impl->granted_suite) {
    switch (tid) {
      case nettest::upload:
        EMIT_INFO("running upload test");
        if (!run_upload()) {
          return false;
        }
        break;
      case nettest::meta:
        EMIT_DEBUG("running meta test");  // don't annoy the user with this
        if (!run_meta()) {
          return false;
        }
        break;
      case nettest::download:
      case nettest::download_ext:
        EMIT_INFO("running download test");
        if (!run_download()) {
          return false;
        }
        break;
      default:
        EMIT_WARNING("run_tests(): unexpected test id");
        return false;
    }
  }
  return true;
}

bool Client::recv_results_and_logout() noexcept {
  for (auto i = 0; i < max_loops; ++i) {  // don't loop forever
    std::string message;
    uint8_t code = 0;
    if (!msg_read(&code, &message)) {
      return false;
    }
    if (code != msg_results && code != msg_logout) {
      EMIT_WARNING("recv_results_and_logout: unexpected message type");
      return false;
    }
    if (code == msg_logout) {
      return true;
    }
    if (!emit_result(this, "summary", std::move(message))) {
      return false;
    }
  }
  EMIT_WARNING("recv_results_and_logout: too many msg_results messages");
  return false;  // Too many loops
}

bool Client::wait_close() noexcept {
  fd_set readset;
  FD_ZERO(&readset);
  // In wait_close() regress test we call wait_close() with sock
  // equal to -1, which causes a segfault. For testability do not
  // reject the value but rather just ignore the socket.
  if (impl->sock >= 0) {
    FD_SET(AS_OS_SOCKET(impl->sock), &readset);
  }
  timeval tv{};
  tv.tv_sec = 1;
  // Note: cast to `int` safe because on Unix sockets are `int`s and on
  // Windows instead the first argment to select() is ignored.
  auto rv = this->select((int)impl->sock + 1, &readset, nullptr, nullptr, &tv);
  if (rv < 0 && !OS_ERROR_IS_EINTR()) {
    EMIT_WARNING("wait_close(): select() failed: " << get_last_system_error());
    return false;
  }
  if (rv <= 0) {
    EMIT_DEBUG("wait_close(): timeout or EINTR waiting for EOF on connection");
    (void)this->shutdown(impl->sock, OS_SHUT_RDWR);
    return true;  // be tolerant
  }
  {
    char data;
    Size n = 0;
    auto err = netx_recv(impl->sock, &data, sizeof(data), &n);
    if (err == Err::none) {
      EMIT_WARNING("wait_close(): unexpected data recv'd when waiting for EOF");
      return false;
    }
    if (err != Err::eof) {
      EMIT_WARNING("wait_close(): unexpected error when waiting for EOF");
      return false;
    }
  }
  return true;
}

// Mid-level API

bool Client::run_download() noexcept {
  SocketVector dload_socks{this};
  std::string port;
  uint8_t nflows = 1;
  if (!msg_expect_test_prepare(&port, &nflows)) {
    return false;
  }

  for (uint8_t i = 0; i < nflows; ++i) {
    Socket sock = -1;
    Err err = netx_maybesocks5h_connect(impl->settings.hostname, port, &sock);
    if (err != Err::none) {
      break;
    }
    dload_socks.sockets.push_back(sock);
  }
  if (dload_socks.sockets.size() != nflows) {
    EMIT_WARNING("run_download: not all connect succeeded");
    return false;
  }

  if (!msg_expect_empty(msg_test_start)) {
    return false;
  }

  double client_side_speed = 0.0;
  {
    uint64_t recent_data = 0;
    uint64_t total_data = 0;
    auto begin = std::chrono::steady_clock::now();
    auto prev = begin;
    char buf[64000];
    for (auto done = false; !done;) {
      Socket maxsock = -1;
      fd_set set;
      FD_ZERO(&set);
      for (auto &fd : dload_socks.sockets) {
        assert(fd >= 0);
        FD_SET(AS_OS_SOCKET(fd), &set);
        maxsock = (std::max)(maxsock, fd);
      }
      timeval tv{};
      tv.tv_usec = 250000;
      // Cast to `int` safe as explained above.
      auto rv = this->select((int)maxsock + 1, &set, nullptr, nullptr, &tv);
      if (rv < 0 && !OS_ERROR_IS_EINTR()) {
        EMIT_WARNING(
            "run_download: select() failed: " << get_last_system_error());
        return false;
      }
      if (rv > 0) {
        for (auto &fd : dload_socks.sockets) {
          if (FD_ISSET(fd, &set)) {
            Size n = 0;
            auto err = netx_recv(fd, buf, sizeof(buf), &n);
            if (err != Err::none) {
              EMIT_WARNING("run_download: next_recv() failed: "
                           << get_last_system_error());
              done = true;
              break;
            }
            recent_data += (uint64_t)n;
            total_data += (uint64_t)n;
          }
        }
      }
      auto now = std::chrono::steady_clock::now();
      std::chrono::duration<double> measurement_interval = now - prev;
      std::chrono::duration<double> elapsed = now - begin;
      if (measurement_interval.count() > 0.25) {
        on_performance(nettest::download, nflows, recent_data,
                       measurement_interval.count(), elapsed.count(),
                       impl->settings.max_runtime);
        recent_data = 0;
        prev = now;
      }
      if (elapsed.count() > impl->settings.max_runtime) {
        EMIT_WARNING("run_download(): running for too much time");
        done = true;
      }
    }
    for (auto &fd : dload_socks.sockets) {
      (void)this->shutdown(fd, OS_SHUT_RDWR);
    }
    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = now - begin;
    client_side_speed = compute_speed(total_data, elapsed.count());
  }

  {
    // TODO(bassosimone): emit this information.
    uint8_t code = 0;
    std::string message;
    if (!msg_read_legacy(&code, &message)) {  // legacy on purpose!
      return false;
    }
    if (code != msg_test_msg) {
      EMIT_WARNING("run_download: unexpected message type");
      return false;
    }
    EMIT_DEBUG("run_download: server computed speed: " << message);
  }

  if (!msg_write(msg_test_msg, std::to_string(client_side_speed))) {
    return false;
  }

  EMIT_INFO("reading summary web100 variables");
  for (auto i = 0; i < max_loops; ++i) {  // don't loop forever
    std::string message;
    uint8_t code = 0;
    if (!msg_read(&code, &message)) {
      return false;
    }
    if (code != msg_test_msg && code != msg_test_finalize) {
      EMIT_WARNING("run_download: unexpected message type");
      return false;
    }
    if (code == msg_test_finalize) {
      return true;
    }
    if (!emit_result(this, "web100", std::move(message))) {
      return false;
    }
  }

  EMIT_WARNING("run_download: too many msg_test_msg messages");
  return false;  // Too many loops
}

bool Client::run_meta() noexcept {
  if (!msg_expect_empty(msg_test_prepare)) {
    return false;
  }
  if (!msg_expect_empty(msg_test_start)) {
    return false;
  }

  for (auto &kv : impl->settings.metadata) {
    std::stringstream ss;
    ss << kv.first << ":" << kv.second;
    if (!msg_write(msg_test_msg, ss.str())) {
      return false;
    }
  }
  if (!msg_write(msg_test_msg, "")) {
    return false;
  }

  if (!msg_expect_empty(msg_test_finalize)) {
    return false;
  }

  return true;
}

bool Client::run_upload() noexcept {
  SocketVector upload_socks{this};
  char buf[8192];
  {
    auto begin = std::chrono::steady_clock::now();
    random_printable_fill(buf, sizeof(buf));
    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = now - begin;
    EMIT_DEBUG("run_upload(): time to fill random buffer: " << elapsed.count());
  }

  std::string port;
  uint8_t nflows = 1;
  if (!msg_expect_test_prepare(&port, &nflows)) {
    return false;
  }
  // TODO(bassosimone): implement C2S_EXT
  if (nflows != 1) {
    EMIT_WARNING("run_upload(): unexpected number of flows");
    return false;
  }

  {
    Socket sock = -1;
    Err err = netx_maybesocks5h_connect(impl->settings.hostname, port, &sock);
    if (err != Err::none) {
      return false;
    }
    upload_socks.sockets.push_back(sock);
  }

  if (!msg_expect_empty(msg_test_start)) {
    return false;
  }

  double client_side_speed = 0.0;
  {
    uint64_t recent_data = 0;
    uint64_t total_data = 0;
    auto begin = std::chrono::steady_clock::now();
    auto prev = begin;
    for (auto done = false; !done;) {
      Socket maxsock = -1;
      fd_set set;
      FD_ZERO(&set);
      for (auto &fd : upload_socks.sockets) {
        assert(fd >= 0);
        FD_SET(AS_OS_SOCKET(fd), &set);
        maxsock = (std::max)(maxsock, fd);
      }
      timeval tv{};
      tv.tv_usec = 250000;
      // Cast to `int` safe as explained above.
      auto rv = this->select((int)maxsock + 1, nullptr, &set, nullptr, &tv);
      if (rv < 0 && !OS_ERROR_IS_EINTR()) {
        EMIT_WARNING(
            "run_upload: select() failed: " << get_last_system_error());
        return false;
      }
      if (rv > 0) {
        for (auto &fd : upload_socks.sockets) {
          if (FD_ISSET(fd, &set)) {
            Size n = 0;
            auto err = netx_send(fd, buf, sizeof(buf), &n);
            if (err != Err::none) {
              if (err != Err::broken_pipe) {
                EMIT_WARNING("run_upload: netx_send() failed: "
                             << get_last_system_error());
              }
              done = true;
              break;
            }
            recent_data += (uint64_t)n;
            total_data += (uint64_t)n;
          }
        }
      }
      auto now = std::chrono::steady_clock::now();
      std::chrono::duration<double> measurement_interval = now - prev;
      std::chrono::duration<double> elapsed = now - begin;
      if (measurement_interval.count() > 0.25) {
        on_performance(nettest::upload, nflows, recent_data,
                       measurement_interval.count(), elapsed.count(),
                       impl->settings.max_runtime);
        recent_data = 0;
        prev = now;
      }
      if (elapsed.count() > impl->settings.max_runtime) {
        EMIT_WARNING("run_upload(): running for too much time");
        done = true;
      }
    }
    for (auto &fd : upload_socks.sockets) {
      (void)this->shutdown(fd, OS_SHUT_RDWR);
    }
    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = now - begin;
    client_side_speed = compute_speed(total_data, elapsed.count());
    EMIT_DEBUG("run_upload: client computed speed: " << client_side_speed);
  }

  {
    std::string message;
    if (!msg_expect(msg_test_msg, &message)) {
      return false;
    }
    // TODO(bassosimone): emit this information
    EMIT_DEBUG("run_upload: server computed speed: " << message);
  }

  if (!msg_expect_empty(msg_test_finalize)) {
    return false;
  }

  return true;
}

// Low-level API

bool Client::msg_write_login(const std::string &version) noexcept {
  static_assert(sizeof(impl->settings.test_suite) == 1, "test_suite too large");
  uint8_t code = 0;
  impl->settings.test_suite |= nettest::status | nettest::meta;
  if ((impl->settings.test_suite & nettest::middlebox)) {
    EMIT_WARNING("msg_write_login(): nettest::middlebox: not implemented");
    impl->settings.test_suite &= ~nettest::middlebox;
  }
  if ((impl->settings.test_suite & nettest::simple_firewall)) {
    EMIT_WARNING(
        "msg_write_login(): nettest::simple_firewall: not implemented");
    impl->settings.test_suite &= ~nettest::simple_firewall;
  }
  if ((impl->settings.test_suite & nettest::upload_ext)) {
    EMIT_WARNING("msg_write_login(): nettest::upload_ext: not implemented");
    impl->settings.test_suite &= ~nettest::upload_ext;
  }
  std::string serio;
  if ((impl->settings.proto & protocol::json) == 0) {
    serio = std::string{(char *)&impl->settings.test_suite,
                        sizeof(impl->settings.test_suite)};
    code = msg_login;
  } else {
    code = msg_extended_login;
    nlohmann::json msg{
        {"msg", version},
        {"tests", std::to_string((unsigned)impl->settings.test_suite)},
    };
    try {
      serio = msg.dump();
    } catch (nlohmann::json::exception &) {
      EMIT_WARNING("msg_write_login: cannot serialize JSON");
      return false;
    }
  }
  assert(code != 0);
  if ((impl->settings.proto & protocol::websockets) != 0) {
    EMIT_WARNING("msg_write_login: websockets not supported");
    return false;
  }
  if (!msg_write_legacy(code, std::move(serio))) {
    return false;
  }
  return true;
}

// TODO(bassosimone): when we will implement WebSockets here, it may
// be useful to have an interface for reading/writing data and to use
// a different implementation depending on the actual protocol.
bool Client::msg_write(uint8_t code, std::string &&msg) noexcept {
  EMIT_DEBUG("msg_write: message to send: " << represent(msg));
  if ((impl->settings.proto & protocol::json) != 0) {
    nlohmann::json json;
    json["msg"] = msg;
    try {
      msg = json.dump();
    } catch (const nlohmann::json::exception &) {
      EMIT_WARNING("msg_write: cannot serialize JSON");
      return false;
    }
  }
  if ((impl->settings.proto & protocol::websockets) != 0) {
    EMIT_WARNING("msg_write: websockets not supported");
    return false;
  }
  if (!msg_write_legacy(code, std::move(msg))) {
    return false;
  }
  return true;
}

bool Client::msg_write_legacy(uint8_t code, std::string &&msg) noexcept {
  {
    EMIT_DEBUG("msg_write_legacy: raw message: " << represent(msg));
    EMIT_DEBUG("msg_write_legacy: message length: " << msg.size());
    char header[3];
    header[0] = code;
    if (msg.size() > UINT16_MAX) {
      EMIT_WARNING("msg_write: message too long");
      return false;
    }
    uint16_t len = (uint16_t)msg.size();
    len = htons(len);
    memcpy(&header[1], &len, sizeof(len));
    EMIT_DEBUG("msg_write_legacy: header[0] (type): " << (int)header[0]);
    EMIT_DEBUG("msg_write_legacy: header[1] (len-high): " << (int)header[1]);
    EMIT_DEBUG("msg_write_legacy: header[2] (len-low): " << (int)header[2]);
    {
      auto err = netx_sendn(impl->sock, header, sizeof(header));
      if (err != Err::none) {
        EMIT_WARNING(
            "msg_write_legacy: sendn() failed: " << get_last_system_error());
        return false;
      }
    }
    EMIT_DEBUG("msg_write_legacy: sent message header");
  }
  if (msg.size() <= 0) {
    EMIT_DEBUG("msg_write_legacy: zero length message");
    return true;
  }
  {
    auto err = netx_sendn(impl->sock, msg.data(), msg.size());
    if (err != Err::none) {
      EMIT_WARNING(
          "msg_write_legacy: sendn() failed: " << get_last_system_error());
      return false;
    }
  }
  EMIT_DEBUG("msg_write_legacy: sent message body");
  return true;
}

bool Client::msg_expect_test_prepare(std::string *pport,
                                     uint8_t *pnflows) noexcept {
  // Both download and upload tests send the same options vector containing
  // the port (non-extended case) and other parameters (otherwise). Currently
  // we only honour the port and the number of flows parameters.

  std::vector<std::string> options;
  {
    std::string message;
    if (!msg_expect(msg_test_prepare, &message)) {
      return false;
    }
    std::istringstream ss{message};
    std::string cur;
    while ((std::getline(ss, cur, ' '))) {
      options.push_back(cur);
    }
  }
  if (options.size() < 1) {
    EMIT_WARNING("msg_expect_test_prepare: not enough options in vector");
    return false;
  }

  std::string port;
  {
    const char *error = nullptr;
    (void)this->strtonum(options[0].data(), 1, UINT16_MAX, &error);
    if (error != nullptr) {
      EMIT_WARNING("msg_expect_test_prepare: cannot parse port");
      return false;
    }
    port = options[0];
  }

  // Here we are being liberal; in theory we should only accept the
  // extra parameters when the test is extended.
  //
  // Also, we do not parse fields that we don't use.

  uint8_t nflows = 1;
  if (options.size() >= 6) {
    const char *error = nullptr;
    nflows = (uint8_t)this->strtonum(options[5].c_str(), 1, 16, &error);
    if (error != nullptr) {
      EMIT_WARNING("msg_expect_test_prepare: cannot parse num-flows");
      return false;
    }
  }

  *pport = port;
  *pnflows = nflows;
  return true;
}

bool Client::msg_expect_empty(uint8_t expected_code) noexcept {
  std::string s;
  if (!msg_expect(expected_code, &s)) {
    return false;
  }
  if (s != "") {
    EMIT_WARNING("msg_expect_empty: non-empty body");
    return false;
  }
  return true;
}

bool Client::msg_expect(uint8_t expected_code, std::string *s) noexcept {
  assert(s != nullptr);
  uint8_t code = 0;
  if (!msg_read(&code, s)) {
    return false;
  }
  if (code != expected_code) {
    EMIT_WARNING("msg_expect: unexpected message type");
    return false;
  }
  return true;
}

bool Client::msg_read(uint8_t *code, std::string *msg) noexcept {
  assert(code != nullptr && msg != nullptr);
  std::string s;
  if ((impl->settings.proto & protocol::websockets) != 0) {
    EMIT_WARNING("msg_read: websockets not supported");
    return false;
  }
  if (!msg_read_legacy(code, &s)) {
    return false;
  }
  if ((impl->settings.proto & protocol::json) == 0) {
    std::swap(s, *msg);
  } else {
    nlohmann::json json;
    try {
      json = nlohmann::json::parse(s);
    } catch (const nlohmann::json::exception &) {
      EMIT_WARNING("msg_read: cannot parse JSON");
      return false;
    }
    try {
      *msg = json.at("msg");
    } catch (const nlohmann::json::exception &) {
      EMIT_WARNING("msg_read: cannot find 'msg' field");
      return false;
    }
  }
  EMIT_DEBUG("msg_read: message: " << represent(*msg));
  return true;
}

bool Client::msg_read_legacy(uint8_t *code, std::string *msg) noexcept {
  assert(code != nullptr && msg != nullptr);
  uint16_t len = 0;
  {
    char header[3];
    {
      auto err = netx_recvn(impl->sock, header, sizeof(header));
      if (err != Err::none) {
        EMIT_WARNING(
            "msg_read_legacy: recvn() failed: " << get_last_system_error());
        return false;
      }
    }
    EMIT_DEBUG("msg_read_legacy: header[0] (type): " << (int)header[0]);
    EMIT_DEBUG("msg_read_legacy: header[1] (len-high): " << (int)header[1]);
    EMIT_DEBUG("msg_read_legacy: header[2] (len-low): " << (int)header[2]);
    *code = header[0];
    memcpy(&len, &header[1], sizeof(len));
    len = ntohs(len);
    EMIT_DEBUG("msg_read_legacy: message length: " << len);
  }
  if (len <= 0) {
    EMIT_DEBUG("msg_read_legacy: zero length message");
    *msg = "";
    return true;
  }
  // Allocating a unique pointer and then copying into a string seems better
  // than resizing() `msg` (because that appends zero characters to the end
  // of it). Returning something more buffer-like than a string might be better
  // for efficiency but NDT messages are generally small, and the performance
  // critical path is certainly not the one with control messages.
  std::unique_ptr<char[]> buf{new char[len]};
  {
    auto err = netx_recvn(impl->sock, buf.get(), len);
    if (err != Err::none) {
      EMIT_WARNING(
          "msg_read_legacy: recvn() failed: " << get_last_system_error());
      return false;
    }
  }
  *msg = std::string{buf.get(), len};
  EMIT_DEBUG("msg_read_legacy: raw message: " << represent(*msg));
  return true;
}

// Networking layer

Err Client::netx_maybesocks5h_connect(const std::string &hostname,
                                      const std::string &port,
                                      Socket *sock) noexcept {
  if (impl->settings.socks5h_port.empty()) {
    return netx_connect(hostname, port, sock);
  }
  {
    auto err = netx_connect("127.0.0.1", impl->settings.socks5h_port, sock);
    if (err != Err::none) {
      return err;
    }
  }
  EMIT_INFO("socks5h: connected to proxy");
  {
    char auth_request[] = {
        5,  // version
        1,  // number of methods
        0   // "no auth" method
    };
    auto err = netx_sendn(*sock, auth_request, sizeof(auth_request));
    if (err != Err::none) {
      EMIT_WARNING("socks5h: cannot send auth_request");
      this->closesocket(*sock);
      *sock = -1;
      return err;
    }
    EMIT_DEBUG("socks5h: sent this auth request: "
               << represent(std::string{auth_request, sizeof(auth_request)}));
  }
  {
    char auth_response[2] = {
        0,  // version
        0   // method
    };
    auto err = netx_recvn(*sock, auth_response, sizeof(auth_response));
    if (err != Err::none) {
      EMIT_WARNING("socks5h: cannot recv auth_response");
      this->closesocket(*sock);
      *sock = -1;
      return err;
    }
    constexpr uint8_t version = 5;
    if (auth_response[0] != version) {
      EMIT_WARNING("socks5h: received unexpected version number");
      this->closesocket(*sock);
      *sock = -1;
      return Err::socks5h;
    }
    constexpr uint8_t auth_method = 0;
    if (auth_response[1] != auth_method) {
      EMIT_WARNING("socks5h: received unexpected auth_method");
      this->closesocket(*sock);
      *sock = -1;
      return Err::socks5h;
    }
    EMIT_DEBUG("socks5h: authenticated with proxy; response: "
               << represent(std::string{auth_response, sizeof(auth_response)}));
  }
  {
    std::string connect_request;
    {
      std::stringstream ss;
      ss << (uint8_t)5;  // version
      ss << (uint8_t)1;  // CMD_CONNECT
      ss << (uint8_t)0;  // reserved
      ss << (uint8_t)3;  // ATYPE_DOMAINNAME
      if (hostname.size() > UINT8_MAX) {
        EMIT_WARNING("socks5h: hostname is too long");
        this->closesocket(*sock);
        *sock = -1;
        return Err::invalid_argument;
      }
      ss << (uint8_t)hostname.size();
      ss << hostname;
      uint16_t portno{};
      {
        const char *errstr = nullptr;
        portno = (uint16_t)this->strtonum(port.c_str(), 0, UINT16_MAX, &errstr);
        if (errstr != nullptr) {
          EMIT_WARNING("socks5h: invalid port number: " << errstr);
          this->closesocket(*sock);
          *sock = -1;
          return Err::invalid_argument;
        }
      }
      portno = htons(portno);
      ss << (uint8_t)((char *)&portno)[0] << (uint8_t)((char *)&portno)[1];
      connect_request = ss.str();
      EMIT_DEBUG("socks5h: connect_request: " << represent(connect_request));
    }
    auto err = netx_sendn(  //
        *sock, connect_request.data(), connect_request.size());
    if (err != Err::none) {
      EMIT_WARNING("socks5h: cannot send connect_request");
      this->closesocket(*sock);
      *sock = -1;
      return err;
    }
    EMIT_DEBUG("socks5h: sent connect request");
  }
  {
    char connect_response_hdr[] = {
        0,  // version
        0,  // error
        0,  // reserved
        0   // type
    };
    auto err = netx_recvn(  //
        *sock, connect_response_hdr, sizeof(connect_response_hdr));
    if (err != Err::none) {
      EMIT_WARNING("socks5h: cannot recv connect_response_hdr");
      this->closesocket(*sock);
      *sock = -1;
      return err;
    }
    EMIT_DEBUG("socks5h: connect_response_hdr: " << represent(std::string{
                   connect_response_hdr, sizeof(connect_response_hdr)}));
    constexpr uint8_t version = 5;
    if (connect_response_hdr[0] != version) {
      EMIT_WARNING("socks5h: invalid message version");
      this->closesocket(*sock);
      *sock = -1;
      return Err::socks5h;
    }
    if (connect_response_hdr[1] != 0) {
      // TODO(bassosimone): map the socks5 error to a system error
      EMIT_WARNING("socks5h: connect() failed: "
                   << (unsigned)(uint8_t)connect_response_hdr[1]);
      this->closesocket(*sock);
      *sock = -1;
      return Err::io_error;
    }
    if (connect_response_hdr[2] != 0) {
      EMIT_WARNING("socks5h: invalid reserved field");
      this->closesocket(*sock);
      *sock = -1;
      return Err::socks5h;
    }
    // receive IP or domain
    switch (connect_response_hdr[3]) {
      case 1:  // ipv4
      {
        constexpr Size expected = 4;  // ipv4
        char buf[expected];
        auto err = netx_recvn(*sock, buf, sizeof(buf));
        if (err != Err::none) {
          EMIT_WARNING("socks5h: cannot recv ipv4 address");
          this->closesocket(*sock);
          *sock = -1;
          return err;
        }
        // TODO(bassosimone): log the ipv4 address. However tor returns a zero
        // ipv4 and so there is little added value in logging.
        break;
      }
      case 3:  // domain
      {
        uint8_t len = 0;
        auto err = netx_recvn(*sock, &len, sizeof(len));
        if (err != Err::none) {
          EMIT_WARNING("socks5h: cannot recv domain length");
          this->closesocket(*sock);
          *sock = -1;
          return err;
        }
        char domain[UINT8_MAX + 1];  // space for final '\0'
        err = netx_recvn(*sock, domain, len);
        if (err != Err::none) {
          EMIT_WARNING("socks5h: cannot recv domain");
          this->closesocket(*sock);
          *sock = -1;
          return err;
        }
        domain[len] = 0;
        EMIT_DEBUG("socks5h: domain: " << domain);
        break;
      }
      case 4:  // ipv6
      {
        constexpr Size expected = 16;  // ipv6
        char buf[expected];
        auto err = netx_recvn(*sock, buf, sizeof(buf));
        if (err != Err::none) {
          EMIT_WARNING("socks5h: cannot recv ipv6 address");
          this->closesocket(*sock);
          *sock = -1;
          return err;
        }
        // TODO(bassosimone): log the ipv6 address. However tor returns a zero
        // ipv6 and so there is little added value in logging.
        break;
      }
      default:
        EMIT_WARNING("socks5h: invalid address type");
        this->closesocket(*sock);
        *sock = -1;
        return Err::socks5h;
    }
    // receive the port
    {
      uint16_t port = 0;
      auto err = netx_recvn(*sock, &port, sizeof(port));
      if (err != Err::none) {
        EMIT_WARNING("socks5h: cannot recv port");
        this->closesocket(*sock);
        *sock = -1;
        return err;
      }
      port = ntohs(port);
      EMIT_DEBUG("socks5h: port number: " << port);
    }
  }
  EMIT_INFO("socks5h: the proxy has successfully connected");
  return Err::none;
}

#ifdef _WIN32
#define E(name) WSAE##name
#else
#define E(name) E##name
#endif

/*static*/ Err Client::netx_map_errno(int ec) noexcept {
  // clang-format off
  switch (ec) {
    case 0: {
      assert(false);  // we don't expect `errno` to be zero
      return Err::io_error;
    }
#ifndef _WIN32
    case E(PIPE): return Err::broken_pipe;
#endif
    case E(CONNABORTED): return Err::connection_aborted;
    case E(CONNREFUSED): return Err::connection_refused;
    case E(CONNRESET): return Err::connection_reset;
    case E(HOSTUNREACH): return Err::host_unreachable;
    case E(INTR): return Err::interrupted;
    case E(INVAL): return Err::invalid_argument;
#ifndef _WIN32
    case E(IO): return Err::io_error;
#endif
    case E(NETDOWN): return Err::network_down;
    case E(NETRESET): return Err::network_reset;
    case E(NETUNREACH): return Err::network_unreachable;
    case E(INPROGRESS): return Err::operation_in_progress;
    case E(WOULDBLOCK): return Err::operation_would_block;
#if !defined _WIN32 && EAGAIN != EWOULDBLOCK
    case E(AGAIN): return Err::operation_would_block;
#endif
    case E(TIMEDOUT): return Err::timed_out;
  }
  // clang-format on
  return Err::io_error;
}

#undef E  // Tidy up

Err Client::netx_map_eai(int ec) noexcept {
  // clang-format off
  switch (ec) {
    case EAI_AGAIN: return Err::ai_again;
    case EAI_FAIL: return Err::ai_fail;
    case EAI_NONAME: return Err::ai_noname;
#ifdef EAI_SYSTEM
    case EAI_SYSTEM: {
      return netx_map_errno(get_last_system_error());
    }
#endif
  }
  // clang-format on
  return Err::ai_generic;
}

Err Client::netx_connect(const std::string &hostname, const std::string &port,
                         Socket *sock) noexcept {
  assert(sock != nullptr);
  if (*sock != -1) {
    EMIT_WARNING("socket already connected");
    return Err::invalid_argument;
  }
  // Implementation note: we could perform getaddrinfo() in one pass but having
  // a virtual API that resolves a hostname to a vector of IP addresses makes
  // life easier when you want to override hostname resolution, because you have
  // to reimplement a simpler method, compared to reimplementing getaddrinfo().
  std::vector<std::string> addresses;
  Err err;
  if ((err = netx_resolve(hostname, &addresses)) != Err::none) {
    return err;
  }
  for (auto &addr : addresses) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo *rp = nullptr;
    int rv = this->getaddrinfo(addr.data(), port.data(), &hints, &rp);
    if (rv != 0) {
      EMIT_WARNING("unexpected getaddrinfo() failure");
      return netx_map_eai(rv);
    }
    assert(rp);
    for (auto aip = rp; (aip); aip = aip->ai_next) {
      set_last_system_error(0);
      *sock = this->socket(aip->ai_family, aip->ai_socktype, 0);
      if (*sock == -1) {
        EMIT_WARNING("socket() failed: " << get_last_system_error());
        continue;
      }
      // The following two lines ensure that casting `size_t` to
      // SockLen is safe because SockLen is `int` and the value of
      // the ai_addrlen field is always small enough.
      static_assert(sizeof(SockLen) == sizeof(int), "Wrong SockLen size");
      assert(aip->ai_addrlen <= INT_MAX);
      if (this->connect(*sock, aip->ai_addr, (SockLen)aip->ai_addrlen) == 0) {
        EMIT_DEBUG("connect(): okay");
        break;
      }
      EMIT_WARNING("connect() failed: " << get_last_system_error());
      this->closesocket(*sock);
      *sock = -1;
    }
    this->freeaddrinfo(rp);
    if (*sock != -1) {
      break;  // we have a connection!
    }
  }
  // TODO(bassosimone): it's possible to write a better algorithm here
  return *sock != -1 ? Err::none : Err::io_error;
}

Err Client::netx_recv(Socket fd, void *base, Size count,
                      Size *actual) noexcept {
  if (count <= 0) {
    EMIT_WARNING(
        "netx_recv: explicitly disallowing zero read; use select() "
        "to check the state of a socket");
    return Err::invalid_argument;
  }
  set_last_system_error(0);
  auto rv = this->recv(fd, base, count);
  if (rv < 0) {
    assert(rv == -1);
    *actual = 0;
    return netx_map_errno(get_last_system_error());
  }
  if (rv == 0) {
    assert(count > 0);  // guaranteed by the above check
    *actual = 0;
    return Err::eof;
  }
  *actual = (Size)rv;
  return Err::none;
}

Err Client::netx_recvn(Socket fd, void *base, Size count) noexcept {
  Size off = 0;
  while (off < count) {
    Size n = 0;
    Err err = netx_recv(fd, ((char *)base) + off, count - off, &n);
    if (err != Err::none) {
      return err;
    }
    off += n;
  }
  return Err::none;
}

Err Client::netx_send(Socket fd, const void *base, Size count,
                      Size *actual) noexcept {
  if (count <= 0) {
    EMIT_WARNING(
        "netx_send: explicitly disallowing zero send; use select() "
        "to check the state of a socket");
    return Err::invalid_argument;
  }
  set_last_system_error(0);
  auto rv = this->send(fd, base, count);
  if (rv < 0) {
    assert(rv == -1);
    *actual = 0;
    return netx_map_errno(get_last_system_error());
  }
  // Send() should not return zero unless count is zero. So consider a zero
  // return value as an I/O error rather than EOF.
  if (rv == 0) {
    assert(count > 0);  // guaranteed by the above check
    *actual = 0;
    return Err::io_error;
  }
  *actual = (Size)rv;
  return Err::none;
}

Err Client::netx_sendn(Socket fd, const void *base, Size count) noexcept {
  Size off = 0;
  while (off < count) {
    Size n = 0;
    Err err = netx_send(fd, ((char *)base) + off, count - off, &n);
    if (err != Err::none) {
      return err;
    }
    off += n;
  }
  return Err::none;
}

Err Client::netx_resolve(const std::string &hostname,
                         std::vector<std::string> *addrs) noexcept {
  assert(addrs != nullptr);
  EMIT_DEBUG("netx_resolve: " << hostname);
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
  addrinfo *rp = nullptr;
  constexpr const char *portno = "80";  // any port would do
  int rv = this->getaddrinfo(hostname.data(), portno, &hints, &rp);
  if (rv != 0) {
    hints.ai_flags &= ~AI_NUMERICHOST;
    rv = this->getaddrinfo(hostname.data(), portno, &hints, &rp);
    if (rv != 0) {
      EMIT_WARNING("getaddrinfo() failed: " << gai_strerror(rv));
      return netx_map_eai(rv);
    }
    // FALLTHROUGH
  }
  assert(rp);
  EMIT_DEBUG("getaddrinfo(): okay");
  Err result = Err::none;
  for (auto aip = rp; (aip); aip = aip->ai_next) {
    char address[NI_MAXHOST], port[NI_MAXSERV];
    // The following two lines ensure that casting `size_t` to
    // SockLen is safe because SockLen is `int` and the value of
    // the ai_addrlen field is always small enough.
    static_assert(sizeof(SockLen) == sizeof(int), "Wrong SockLen size");
    assert(sizeof(address) <= INT_MAX && sizeof(port) <= INT_MAX);
    if (this->getnameinfo(aip->ai_addr, (SockLen)aip->ai_addrlen, address,
                          (SockLen)sizeof(address), port, (SockLen)sizeof(port),
                          NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
      EMIT_WARNING("unexpected getnameinfo() failure");
      result = Err::ai_generic;
      break;
    }
    addrs->push_back(address);  // we only care about address
    EMIT_DEBUG("- " << address);
  }
  this->freeaddrinfo(rp);
  return result;
}

// Dependencies (curl)

uint64_t Client::get_verbosity() const noexcept {
  return impl->settings.verbosity;
}

bool Client::query_mlabns_curl(const std::string &url, long timeout,
                               std::string *body) noexcept {
#ifdef HAVE_CURL
  Curl curl{this};
  if (!curl.method_get_maybe_socks5(  //
          impl->settings.socks5h_port, url, timeout, body)) {
    return false;
  }
  return true;
#else
  (void)url, (void)timeout, (void)body;
  EMIT_WARNING("cURL not compiled in; don't know how to get server");
  return false;
#endif
}

// Dependencies (libc)

#ifdef _WIN32
#define AS_OS_SOCKLEN(n) ((int)n)
#define AS_OS_BUFFER(b) ((char *)b)
#define AS_OS_BUFFER_LEN(n) ((int)n)
#define OS_SSIZE_MAX INT_MAX
#define OS_EINVAL WSAEINVAL
#else
#define AS_OS_SOCKLEN(n) ((socklen_t)n)
#define AS_OS_BUFFER(b) ((char *)b)
#define AS_OS_BUFFER_LEN(n) ((size_t)n)
#define OS_SSIZE_MAX SSIZE_MAX
#define OS_EINVAL EINVAL
#endif

int Client::get_last_system_error() noexcept {
#ifdef _WIN32
  return GetLastError();
#else
  return errno;
#endif
}

void Client::set_last_system_error(int err) noexcept {
#ifdef _WIN32
  SetLastError(err);
#else
  errno = err;
#endif
}

int Client::getaddrinfo(const char *domain, const char *port,
                        const addrinfo *hints, addrinfo **res) noexcept {
  return ::getaddrinfo(domain, port, hints, res);
}

int Client::getnameinfo(const sockaddr *sa, SockLen salen, char *host,
                        SockLen hostlen, char *serv, SockLen servlen,
                        int flags) noexcept {
  return ::getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

void Client::freeaddrinfo(addrinfo *aip) noexcept { ::freeaddrinfo(aip); }

Socket Client::socket(int domain, int type, int protocol) noexcept {
  return (Socket)::socket(domain, type, protocol);
}

int Client::connect(Socket fd, const sockaddr *sa, SockLen len) noexcept {
  return ::connect(AS_OS_SOCKET(fd), sa, AS_OS_SOCKLEN(len));
}

Ssize Client::recv(Socket fd, void *base, Size count) noexcept {
  if (count > OS_SSIZE_MAX) {
    set_last_system_error(OS_EINVAL);
    return -1;
  }
  return (Ssize)::recv(AS_OS_SOCKET(fd), AS_OS_BUFFER(base),
                       AS_OS_BUFFER_LEN(count), 0);
}

Ssize Client::send(Socket fd, const void *base, Size count) noexcept {
  if (count > OS_SSIZE_MAX) {
    set_last_system_error(OS_EINVAL);
    return -1;
  }
  return (Ssize)::send(AS_OS_SOCKET(fd), AS_OS_BUFFER(base),
                       AS_OS_BUFFER_LEN(count), 0);
}

int Client::shutdown(Socket fd, int how) noexcept {
  return ::shutdown(AS_OS_SOCKET(fd), how);
}

int Client::closesocket(Socket fd) noexcept {
#ifdef _WIN32
  return ::closesocket(AS_OS_SOCKET(fd));
#else
  return ::close(AS_OS_SOCKET(fd));
#endif
}

int Client::select(int numfd, fd_set *readset, fd_set *writeset,
                   fd_set *exceptset, timeval *timeout) noexcept {
  return ::select(numfd, readset, writeset, exceptset, timeout);
}

long long Client::strtonum(const char *s, long long minval, long long maxval,
                           const char **errp) noexcept {
  return ::strtonum(s, minval, maxval, errp);
}

}  // namespace libndt
}  // namespace measurement_kit
