// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt.hpp"

#ifndef _WIN32
#include <arpa/inet.h>   // IWYU pragma: keep
#include <sys/select.h>  // IWYU pragma: keep
#include <sys/socket.h>
#endif

#include <assert.h>
#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#endif
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

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

namespace libndt {

// Private constants

constexpr auto max_loops = 256;

constexpr char msg_kickoff[] = "123456 654321";
constexpr size_t msg_kickoff_size = sizeof(msg_kickoff) - 1;

// Private utils

#define EMIT_WARNING(statements)                         \
  do {                                                   \
    if (impl->settings.verbosity >= verbosity_warning) { \
      std::stringstream ss;                              \
      ss << statements;                                  \
      on_warning(ss.str());                              \
    }                                                    \
  } while (0)

#define EMIT_INFO(statements)                         \
  do {                                                \
    if (impl->settings.verbosity >= verbosity_info) { \
      std::stringstream ss;                           \
      ss << statements;                               \
      on_info(ss.str());                              \
    }                                                 \
  } while (0)

#define EMIT_DEBUG(statements)                         \
  do {                                                 \
    if (impl->settings.verbosity >= verbosity_debug) { \
      std::stringstream ss;                            \
      ss << statements;                                \
      on_debug(ss.str());                              \
    }                                                  \
  } while (0)

#ifdef _WIN32
#define OS_SHUT_RDWR SD_BOTH
#else
#define OS_SHUT_RDWR SHUT_RDWR
#endif

class Client::Impl {
 public:
  Socket sock = -1;
  std::vector<NettestFlags> granted_suite;
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

static double compute_speed(double data, double elapsed) noexcept {
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
      owner->sys_closesocket(fd);
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
    sys_closesocket(impl->sock);
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

void Client::on_warning(const std::string &msg) {
  std::clog << "[!] " << msg << std::endl;
}

void Client::on_info(const std::string &msg) { std::clog << msg << std::endl; }

void Client::on_debug(const std::string &msg) {
  std::clog << "[D] " << msg << std::endl;
}

void Client::on_performance(NettestFlags tid, uint8_t nflows,
                            double measured_bytes, double measured_interval,
                            double elapsed_time, double max_runtime) {
  auto speed = compute_speed(measured_bytes, measured_interval);
  EMIT_INFO("  [" << std::fixed << std::setprecision(0) << std::setw(2)
                  << std::right << (elapsed_time * 100.0 / max_runtime) << "%]"
                  << " elapsed: " << std::fixed << std::setprecision(3)
                  << std::setw(6) << elapsed_time << " s;"
                  << " test_id: " << (int)tid << " num_flows: " << (int)nflows
                  << " speed: " << std::setprecision(0) << std::setw(8)
                  << std::right << speed << " kbit/s");
}

void Client::on_result(std::string scope, std::string name, std::string value) {
  EMIT_INFO("  - [" << scope << "] " << name << ": " << value);
}

void Client::on_server_busy(std::string msg) {
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
          impl->settings.mlabns_url, impl->settings.timeout, &body)) {
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
  return netx_maybesocks5h_dial(impl->settings.hostname, impl->settings.port,
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
    EMIT_WARNING("recv_kickoff: netx_recvn() failed: " << sys_get_last_error());
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
    static_assert(sizeof(NettestFlags) == sizeof(uint8_t),
                  "Invalid NettestFlags size");
    auto tid = (uint8_t)sys_strtonum(cur.data(), 1, 256, &errstr);
    if (errstr != nullptr) {
      EMIT_WARNING("recv_tests_ids: found invalid test-id: "
                   << cur.data() << " (error: " << errstr << ")");
      return false;
    }
    impl->granted_suite.push_back(NettestFlags{tid});
  }
  return true;
}

bool Client::run_tests() noexcept {
  for (auto &tid : impl->granted_suite) {
    if (tid == nettest_flag_upload) {
      EMIT_INFO("running upload test");
      if (!run_upload()) {
        return false;
      }
    } else if (tid == nettest_flag_meta) {
      EMIT_DEBUG("running meta test");  // don't annoy the user with this
      if (!run_meta()) {
        return false;
      }
    } else if (tid == nettest_flag_download ||
               tid == nettest_flag_download_ext) {
      EMIT_INFO("running download test");
      if (!run_download()) {
        return false;
      }
    } else {
      EMIT_WARNING("run_tests(): unexpected test id");
      return false;
    }
  }
  return true;
}

bool Client::recv_results_and_logout() noexcept {
  for (auto i = 0; i < max_loops; ++i) {  // don't loop forever
    std::string message;
    MsgType code = MsgType{0};
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
  constexpr Timeout wait_for_close = 1;
  auto err = netx_wait_readable(impl->sock, wait_for_close);
  if (err != Err::none) {
    EMIT_WARNING(
        "wait_close(): netx_wait_readable() failed: " << sys_get_last_error());
    (void)sys_shutdown(impl->sock, OS_SHUT_RDWR);
    return (err == Err::timed_out);
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
    Err err = netx_maybesocks5h_dial(impl->settings.hostname, port, &sock);
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
      std::vector<pollfd> pfds;
      for (auto fd : dload_socks.sockets) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events |= POLLIN;
        pfds.push_back(pfd);
      }
      constexpr int timeout_msec = 250;
      auto err = netx_poll(&pfds, timeout_msec);
      if (err != Err::none && err != Err::timed_out) {
        EMIT_WARNING(
            "run_download: netx_poll() failed: " << sys_get_last_error());
        return false;
      }
      for (auto fd : pfds) {
        if ((fd.revents & POLLIN) == 0) {
          continue;
        }
        Size n = 0;
        auto err = netx_recv_nonblocking(fd.fd, buf, sizeof(buf), &n);
        if (err != Err::none) {
          EMIT_WARNING(
              "run_download: netx_recv() failed: " << sys_get_last_error());
          done = true;
          break;
        }
        recent_data += (uint64_t)n;
        total_data += (uint64_t)n;
      }
      auto now = std::chrono::steady_clock::now();
      std::chrono::duration<double> measurement_interval = now - prev;
      std::chrono::duration<double> elapsed = now - begin;
      if (measurement_interval.count() > 0.25) {
        on_performance(nettest_flag_download, nflows,
                       static_cast<double>(recent_data),
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
      (void)sys_shutdown(fd, OS_SHUT_RDWR);
    }
    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = now - begin;
    client_side_speed = compute_speed(  //
        static_cast<double>(total_data), elapsed.count());
  }

  {
    // TODO(bassosimone): emit this information.
    MsgType code = MsgType{0};
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
    MsgType code = MsgType{0};
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
    Err err = netx_maybesocks5h_dial(impl->settings.hostname, port, &sock);
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
      std::vector<pollfd> pfds;
      for (auto fd : upload_socks.sockets) {
        pollfd pfd;
        pfd.fd = fd;
        pfd.events |= POLLOUT;
        pfds.push_back(pfd);
      }
      constexpr int timeout_msec = 250;
      auto err = netx_poll(&pfds, timeout_msec);
      if (err != Err::none && err != Err::timed_out) {
        EMIT_WARNING(
            "run_upload: netx_poll() failed: " << sys_get_last_error());
        return false;
      }
      for (auto fd : pfds) {
        if ((fd.revents & POLLOUT) == 0) {
          continue;
        }
        Size n = 0;
        auto err = netx_send_nonblocking(fd.fd, buf, sizeof(buf), &n);
        if (err != Err::none) {
          if (err != Err::broken_pipe) {
            EMIT_WARNING(
                "run_upload: netx_send() failed: " << sys_get_last_error());
          }
          done = true;
          break;
        }
        recent_data += (uint64_t)n;
        total_data += (uint64_t)n;
      }
      auto now = std::chrono::steady_clock::now();
      std::chrono::duration<double> measurement_interval = now - prev;
      std::chrono::duration<double> elapsed = now - begin;
      if (measurement_interval.count() > 0.25) {
        on_performance(nettest_flag_upload, nflows,
                       static_cast<double>(recent_data),
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
      (void)sys_shutdown(fd, OS_SHUT_RDWR);
    }
    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = now - begin;
    client_side_speed = compute_speed(  //
        static_cast<double>(total_data), elapsed.count());
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
  static_assert(sizeof(impl->settings.nettest_flags) == 1,
                "nettest_flags too large");
  MsgType code = MsgType{0};
  impl->settings.nettest_flags |= nettest_flag_status | nettest_flag_meta;
  if ((impl->settings.nettest_flags & nettest_flag_middlebox) !=
      NettestFlags{0}) {
    EMIT_WARNING("msg_write_login(): nettest_flag_middlebox: not implemented");
    impl->settings.nettest_flags &= ~nettest_flag_middlebox;
  }
  if ((impl->settings.nettest_flags & nettest_flag_simple_firewall) !=
      NettestFlags{0}) {
    EMIT_WARNING(
        "msg_write_login(): nettest_flag_simple_firewall: not implemented");
    impl->settings.nettest_flags &= ~nettest_flag_simple_firewall;
  }
  if ((impl->settings.nettest_flags & nettest_flag_upload_ext) !=
      NettestFlags{0}) {
    EMIT_WARNING("msg_write_login(): nettest_flag_upload_ext: not implemented");
    impl->settings.nettest_flags &= ~nettest_flag_upload_ext;
  }
  std::string serio;
  if ((impl->settings.protocol_flags & protocol_flag_json) == 0) {
    serio = std::string{(char *)&impl->settings.nettest_flags,
                        sizeof(impl->settings.nettest_flags)};
    code = msg_login;
  } else {
    code = msg_extended_login;
    nlohmann::json msg{
        {"msg", version},
        {"tests", std::to_string((unsigned)impl->settings.nettest_flags)},
    };
    try {
      serio = msg.dump();
    } catch (nlohmann::json::exception &) {
      EMIT_WARNING("msg_write_login: cannot serialize JSON");
      return false;
    }
  }
  assert(code != MsgType{0});
  if ((impl->settings.protocol_flags & protocol_flag_websockets) != 0) {
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
bool Client::msg_write(MsgType code, std::string &&msg) noexcept {
  EMIT_DEBUG("msg_write: message to send: " << represent(msg));
  if ((impl->settings.protocol_flags & protocol_flag_json) != 0) {
    nlohmann::json json;
    json["msg"] = msg;
    try {
      msg = json.dump();
    } catch (const nlohmann::json::exception &) {
      EMIT_WARNING("msg_write: cannot serialize JSON");
      return false;
    }
  }
  if ((impl->settings.protocol_flags & protocol_flag_websockets) != 0) {
    EMIT_WARNING("msg_write: websockets not supported");
    return false;
  }
  if (!msg_write_legacy(code, std::move(msg))) {
    return false;
  }
  return true;
}

bool Client::msg_write_legacy(MsgType code, std::string &&msg) noexcept {
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
            "msg_write_legacy: sendn() failed: " << sys_get_last_error());
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
          "msg_write_legacy: sendn() failed: " << sys_get_last_error());
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
    (void)sys_strtonum(options[0].data(), 1, UINT16_MAX, &error);
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
    nflows = (uint8_t)sys_strtonum(options[5].c_str(), 1, 16, &error);
    if (error != nullptr) {
      EMIT_WARNING("msg_expect_test_prepare: cannot parse num-flows");
      return false;
    }
  }

  *pport = port;
  *pnflows = nflows;
  return true;
}

bool Client::msg_expect_empty(MsgType expected_code) noexcept {
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

bool Client::msg_expect(MsgType expected_code, std::string *s) noexcept {
  assert(s != nullptr);
  MsgType code = MsgType{0};
  if (!msg_read(&code, s)) {
    return false;
  }
  if (code != expected_code) {
    EMIT_WARNING("msg_expect: unexpected message type");
    return false;
  }
  return true;
}

bool Client::msg_read(MsgType *code, std::string *msg) noexcept {
  assert(code != nullptr && msg != nullptr);
  std::string s;
  if ((impl->settings.protocol_flags & protocol_flag_websockets) != 0) {
    EMIT_WARNING("msg_read: websockets not supported");
    return false;
  }
  if (!msg_read_legacy(code, &s)) {
    return false;
  }
  if ((impl->settings.protocol_flags & protocol_flag_json) == 0) {
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

bool Client::msg_read_legacy(MsgType *code, std::string *msg) noexcept {
  assert(code != nullptr && msg != nullptr);
  uint16_t len = 0;
  {
    char header[3];
    {
      auto err = netx_recvn(impl->sock, header, sizeof(header));
      if (err != Err::none) {
        EMIT_WARNING(
            "msg_read_legacy: recvn() failed: " << sys_get_last_error());
        return false;
      }
    }
    EMIT_DEBUG("msg_read_legacy: header[0] (type): " << (int)header[0]);
    EMIT_DEBUG("msg_read_legacy: header[1] (len-high): " << (int)header[1]);
    EMIT_DEBUG("msg_read_legacy: header[2] (len-low): " << (int)header[2]);
    static_assert(sizeof(MsgType) == sizeof(unsigned char),
                  "Unexpected MsgType size");
    *code = MsgType{(unsigned char)header[0]};
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
      EMIT_WARNING("msg_read_legacy: recvn() failed: " << sys_get_last_error());
      return false;
    }
  }
  *msg = std::string{buf.get(), len};
  EMIT_DEBUG("msg_read_legacy: raw message: " << represent(*msg));
  return true;
}

// Networking layer

Err Client::netx_maybesocks5h_dial(const std::string &hostname,
                                   const std::string &port,
                                   Socket *sock) noexcept {
  if (impl->settings.socks5h_port.empty()) {
    return netx_dial(hostname, port, sock);
  }
  {
    auto err = netx_dial("127.0.0.1", impl->settings.socks5h_port, sock);
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
      sys_closesocket(*sock);
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
      sys_closesocket(*sock);
      *sock = -1;
      return err;
    }
    constexpr uint8_t version = 5;
    if (auth_response[0] != version) {
      EMIT_WARNING("socks5h: received unexpected version number");
      sys_closesocket(*sock);
      *sock = -1;
      return Err::socks5h;
    }
    constexpr uint8_t auth_method = 0;
    if (auth_response[1] != auth_method) {
      EMIT_WARNING("socks5h: received unexpected auth_method");
      sys_closesocket(*sock);
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
        sys_closesocket(*sock);
        *sock = -1;
        return Err::invalid_argument;
      }
      ss << (uint8_t)hostname.size();
      ss << hostname;
      uint16_t portno{};
      {
        const char *errstr = nullptr;
        portno = (uint16_t)sys_strtonum(port.c_str(), 0, UINT16_MAX, &errstr);
        if (errstr != nullptr) {
          EMIT_WARNING("socks5h: invalid port number: " << errstr);
          sys_closesocket(*sock);
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
      sys_closesocket(*sock);
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
      sys_closesocket(*sock);
      *sock = -1;
      return err;
    }
    EMIT_DEBUG("socks5h: connect_response_hdr: " << represent(std::string{
                   connect_response_hdr, sizeof(connect_response_hdr)}));
    constexpr uint8_t version = 5;
    if (connect_response_hdr[0] != version) {
      EMIT_WARNING("socks5h: invalid message version");
      sys_closesocket(*sock);
      *sock = -1;
      return Err::socks5h;
    }
    if (connect_response_hdr[1] != 0) {
      // TODO(bassosimone): map the socks5 error to a system error
      EMIT_WARNING("socks5h: connect() failed: "
                   << (unsigned)(uint8_t)connect_response_hdr[1]);
      sys_closesocket(*sock);
      *sock = -1;
      return Err::io_error;
    }
    if (connect_response_hdr[2] != 0) {
      EMIT_WARNING("socks5h: invalid reserved field");
      sys_closesocket(*sock);
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
          sys_closesocket(*sock);
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
          sys_closesocket(*sock);
          *sock = -1;
          return err;
        }
        char domain[UINT8_MAX + 1];  // space for final '\0'
        err = netx_recvn(*sock, domain, len);
        if (err != Err::none) {
          EMIT_WARNING("socks5h: cannot recv domain");
          sys_closesocket(*sock);
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
          sys_closesocket(*sock);
          *sock = -1;
          return err;
        }
        // TODO(bassosimone): log the ipv6 address. However tor returns a zero
        // ipv6 and so there is little added value in logging.
        break;
      }
      default:
        EMIT_WARNING("socks5h: invalid address type");
        sys_closesocket(*sock);
        *sock = -1;
        return Err::socks5h;
    }
    // receive the port
    {
      uint16_t port = 0;
      auto err = netx_recvn(*sock, &port, sizeof(port));
      if (err != Err::none) {
        EMIT_WARNING("socks5h: cannot recv port");
        sys_closesocket(*sock);
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
      return netx_map_errno(sys_get_last_error());
    }
#endif
  }
  // clang-format on
  return Err::ai_generic;
}

#ifdef _WIN32
// Depending on the version of Winsock it's either EAGAIN or EINPROGRESS
#define CONNECT_IN_PROGRESS(e) \
  (e == Err::operation_would_block || e == Err::operation_in_progress)
#else
#define CONNECT_IN_PROGRESS(e) (e == Err::operation_in_progress)
#endif

Err Client::netx_dial(const std::string &hostname, const std::string &port,
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
    int rv = sys_getaddrinfo(addr.data(), port.data(), &hints, &rp);
    if (rv != 0) {
      EMIT_WARNING("unexpected getaddrinfo() failure");
      return netx_map_eai(rv);
    }
    assert(rp);
    for (auto aip = rp; (aip); aip = aip->ai_next) {
      sys_set_last_error(0);
      *sock = sys_socket(aip->ai_family, aip->ai_socktype, 0);
      if (!is_socket_valid(*sock)) {
        EMIT_WARNING("socket() failed: " << sys_get_last_error());
        continue;
      }
      if (netx_setnonblocking(*sock, true) != Err::none) {
        EMIT_WARNING("netx_setnonblocking() failed: " << sys_get_last_error());
        sys_closesocket(*sock);
        *sock = -1;
        continue;
      }
      // While on Unix ai_addrlen is socklen_t, it's size_t on Windows. Just
      // for the sake of correctness, add a check that ensures that the size has
      // a reasonable value before casting to socklen_t. My understanding is
      // that size_t is `ULONG_PTR` while socklen_t is most likely `int`.
#ifdef _WIN32
      if (aip->ai_addrlen > sizeof(sockaddr_in6)) {
        EMIT_WARNING("unexpected size of aip->ai_addrlen");
        sys_closesocket(*sock);
        *sock = -1;
        continue;
      }
#endif
      if (sys_connect(*sock, aip->ai_addr, (socklen_t)aip->ai_addrlen) == 0) {
        EMIT_DEBUG("connect(): okay");
        break;
      }
      auto err = netx_map_errno(sys_get_last_error());
      if (CONNECT_IN_PROGRESS(err)) {
        err = netx_wait_writeable(*sock, impl->settings.timeout);
        if (err == Err::none) {
          int soerr = 0;
          socklen_t soerrlen = sizeof(soerr);
          if (sys_getsockopt(*sock, SOL_SOCKET, SO_ERROR, (void *)&soerr,
                             &soerrlen) == 0) {
            assert(soerrlen == sizeof(soerr));
            if (soerr == 0) {
              EMIT_DEBUG("connect(): okay");
              break;
            }
            sys_set_last_error(soerr);
          }
        }
      }
      EMIT_WARNING("connect() failed: " << sys_get_last_error());
      sys_closesocket(*sock);
      *sock = -1;
    }
    sys_freeaddrinfo(rp);
    if (*sock != -1) {
      break;  // we have a connection!
    }
  }
  // TODO(bassosimone): it's possible to write a better algorithm here
  return *sock != -1 ? Err::none : Err::io_error;
}

#undef CONNECT_IN_PROGRESS  // Tidy

Err Client::netx_recv(Socket fd, void *base, Size count,
                      Size *actual) noexcept {
  auto err = netx_recv_nonblocking(fd, base, count, actual);
  if (err != Err::operation_would_block) {
    return err;
  }
  err = netx_wait_readable(fd, impl->settings.timeout);
  if (err != Err::none) {
    return err;
  }
  return netx_recv_nonblocking(fd, base, count, actual);
}

Err Client::netx_recv_nonblocking(Socket fd, void *base, Size count,
                                  Size *actual) noexcept {
  if (count <= 0) {
    EMIT_WARNING(
        "netx_recv: explicitly disallowing zero read; use netx_select() "
        "to check the state of a socket");
    return Err::invalid_argument;
  }
  sys_set_last_error(0);
  auto rv = sys_recv(fd, base, count);
  if (rv < 0) {
    assert(rv == -1);
    *actual = 0;
    return netx_map_errno(sys_get_last_error());
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
    if ((uintptr_t)base > UINTPTR_MAX - off) {
      return Err::value_too_large;
    }
    Err err = netx_recv(fd, ((char *)base) + off, count - off, &n);
    if (err != Err::none) {
      return err;
    }
    if (off > SizeMax - n) {
      return Err::value_too_large;
    }
    off += n;
  }
  return Err::none;
}

Err Client::netx_send(Socket fd, const void *base, Size count,
                      Size *actual) noexcept {
  auto err = netx_send_nonblocking(fd, base, count, actual);
  if (err != Err::operation_would_block) {
    return err;
  }
  err = netx_wait_writeable(fd, impl->settings.timeout);
  if (err != Err::none) {
    return err;
  }
  return netx_send_nonblocking(fd, base, count, actual);
}

Err Client::netx_send_nonblocking(Socket fd, const void *base, Size count,
                                  Size *actual) noexcept {
  if (count <= 0) {
    EMIT_WARNING(
        "netx_send: explicitly disallowing zero send; use netx_select() "
        "to check the state of a socket");
    return Err::invalid_argument;
  }
  sys_set_last_error(0);
  auto rv = sys_send(fd, base, count);
  if (rv < 0) {
    assert(rv == -1);
    *actual = 0;
    return netx_map_errno(sys_get_last_error());
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
    if ((uintptr_t)base > UINTPTR_MAX - off) {
      return Err::value_too_large;
    }
    Err err = netx_send(fd, ((char *)base) + off, count - off, &n);
    if (err != Err::none) {
      return err;
    }
    if (off > SizeMax - n) {
      return Err::value_too_large;
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
  int rv = sys_getaddrinfo(hostname.data(), portno, &hints, &rp);
  if (rv != 0) {
    hints.ai_flags &= ~AI_NUMERICHOST;
    rv = sys_getaddrinfo(hostname.data(), portno, &hints, &rp);
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
    // The following casts from `size_t` to `socklen_t` are safe for sure
    // because NI_MAXHOST and NI_MAXSERV are small values. To make sure this
    // assumption is correct, deploy the following static assertion. Here I am
    // using INT_MAX as upper bound since socklen_t SHOULD be `int`.
    static_assert(sizeof(address) <= INT_MAX && sizeof(port) <= INT_MAX,
                  "Wrong assumption about NI_MAXHOST or NI_MAXSERV");
    // Additionally on Windows there's a cast from size_t to socklen_t that
    // needs to be handled as we do above for getaddrinfo().
#ifdef _WIN32
    if (aip->ai_addrlen > sizeof(sockaddr_in6)) {
      EMIT_WARNING("unexpected size of aip->ai_addrlen");
      result = Err::value_too_large;
      break;
    }
#endif
    if (sys_getnameinfo(aip->ai_addr, (socklen_t)aip->ai_addrlen, address,
                        (socklen_t)sizeof(address), port,
                        (socklen_t)sizeof(port),
                        NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
      EMIT_WARNING("unexpected getnameinfo() failure");
      result = Err::ai_generic;
      break;
    }
    addrs->push_back(address);  // we only care about address
    EMIT_DEBUG("- " << address);
  }
  sys_freeaddrinfo(rp);
  return result;
}

Err Client::netx_setnonblocking(Socket fd, bool enable) noexcept {
#ifdef _WIN32
  u_long lv = (enable) ? 1UL : 0UL;
  if (sys_ioctlsocket(fd, FIONBIO, &lv) != 0) {
    return netx_map_errno(sys_get_last_error());
  }
#else
  auto flags = sys_fcntl(fd, F_GETFL);
  if (flags < 0) {
    assert(flags == -1);
    return netx_map_errno(sys_get_last_error());
  }
  if (enable) {
    flags |= O_NONBLOCK;
  } else {
    flags &= ~O_NONBLOCK;
  }
  if (sys_fcntl(fd, F_SETFL, flags) != 0) {
    return netx_map_errno(sys_get_last_error());
  }
#endif
  return Err::none;
}

static Err netx_wait(Client *client, Socket fd, Timeout timeout,
                     short expected_events) noexcept {
  pollfd pfd{};
  pfd.fd = fd;
  pfd.events |= expected_events;
  std::vector<pollfd> pfds;
  pfds.push_back(pfd);
  static_assert(sizeof(timeout) == sizeof(int), "Unexpected Timeout size");
  if (timeout > INT_MAX / 1000) {
    timeout = INT_MAX / 1000;
  }
  auto err = client->netx_poll(&pfds, timeout * 1000);
  assert((err == Err::none && (pfds[0].revents & expected_events) != 0) ||
         (err != Err::none && pfds[0].revents == 0));
  return err;
}

Err Client::netx_wait_readable(Socket fd, Timeout timeout) noexcept {
  return netx_wait(this, fd, timeout, POLLIN);
}

Err Client::netx_wait_writeable(Socket fd, Timeout timeout) noexcept {
  return netx_wait(this, fd, timeout, POLLOUT);
}

Err Client::netx_poll(std::vector<pollfd> *pfds, int timeout_msec) noexcept {
  if (pfds == nullptr) {
    EMIT_WARNING("netx_poll: passed a null vector of descriptors");
    return Err::invalid_argument;
  }
  // The second argument to poll(2) is nfds_t (an unsigned integer with size no
  // greater than sizeof(long) according to IEEE Std 1003.1) on Unix. It's
  // instead `unsigned long` on Windows. The compiler complains on Windows 64
  // about the conversion from `size_t` to the second argument. Since we
  // use a very small number of file descriptors, artificially limit the max
  // number of descriptors to unsigned short and let the compiler then
  // promote the unsigned short to the proper type.
  if (pfds->size() > USHRT_MAX) {
    EMIT_WARNING("netx_poll: passed too many file descriptors");
    return Err::value_too_large;
  }
  unsigned short numfds = (unsigned short)pfds->size();
  int rv = 0;
#ifndef _WIN32
again:
#endif
  rv = sys_poll(pfds->data(), numfds, timeout_msec);
#ifdef _WIN32
  if (rv == SOCKET_ERROR) {
    return netx_map_errno(sys_get_last_error());
  }
#else
  if (rv < 0) {
    assert(rv == -1);
    auto err = netx_map_errno(sys_get_last_error());
    if (err == Err::interrupted) {
      goto again;
    }
    return err;
  }
#endif
  if (rv == 0) {
    return Err::timed_out;
  }
  return Err::none;
}

// Dependencies (curl)

Verbosity Client::get_verbosity() const noexcept {
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
#define AS_OS_BUFFER(b) ((char *)b)
#define AS_OS_BUFFER_LEN(n) ((int)n)
#define OS_SSIZE_MAX INT_MAX
#define OS_EINVAL WSAEINVAL
#define AS_OS_OPTION_VALUE(x) ((char *)x)
#else
#define AS_OS_BUFFER(b) ((char *)b)
#define AS_OS_BUFFER_LEN(n) ((size_t)n)
#define OS_SSIZE_MAX SSIZE_MAX
#define OS_EINVAL EINVAL
#define AS_OS_OPTION_VALUE(x) ((void *)x)
#endif

int Client::sys_get_last_error() noexcept {
#ifdef _WIN32
  return GetLastError();
#else
  return errno;
#endif
}

void Client::sys_set_last_error(int err) noexcept {
#ifdef _WIN32
  SetLastError(err);
#else
  errno = err;
#endif
}

int Client::sys_getaddrinfo(const char *domain, const char *port,
                            const addrinfo *hints, addrinfo **res) noexcept {
  return ::getaddrinfo(domain, port, hints, res);
}

int Client::sys_getnameinfo(const sockaddr *sa, socklen_t salen, char *host,
                            socklen_t hostlen, char *serv, socklen_t servlen,
                            int flags) noexcept {
  return ::getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

void Client::sys_freeaddrinfo(addrinfo *aip) noexcept { ::freeaddrinfo(aip); }

Socket Client::sys_socket(int domain, int type, int protocol) noexcept {
  return (Socket)::socket(domain, type, protocol);
}

int Client::sys_connect(Socket fd, const sockaddr *sa, socklen_t len) noexcept {
  return ::connect(fd, sa, len);
}

Ssize Client::sys_recv(Socket fd, void *base, Size count) noexcept {
  if (count > OS_SSIZE_MAX) {
    sys_set_last_error(OS_EINVAL);
    return -1;
  }
  return (Ssize)::recv(fd, AS_OS_BUFFER(base), AS_OS_BUFFER_LEN(count), 0);
}

Ssize Client::sys_send(Socket fd, const void *base, Size count) noexcept {
  if (count > OS_SSIZE_MAX) {
    sys_set_last_error(OS_EINVAL);
    return -1;
  }
  return (Ssize)::send(fd, AS_OS_BUFFER(base), AS_OS_BUFFER_LEN(count), 0);
}

int Client::sys_shutdown(Socket fd, int shutdown_how) noexcept {
  return ::shutdown(fd, shutdown_how);
}

int Client::sys_closesocket(Socket fd) noexcept {
#ifdef _WIN32
  return ::closesocket(fd);
#else
  return ::close(fd);
#endif
}

#ifdef _WIN32
int Client::sys_poll(LPWSAPOLLFD fds, ULONG nfds, INT timeout) noexcept {
  return ::WSAPoll(fds, nfds, timeout);
}
#else
int Client::sys_poll(pollfd *fds, nfds_t nfds, int timeout) noexcept {
  return ::poll(fds, nfds, timeout);
}
#endif

long long Client::sys_strtonum(const char *s, long long minval,
                               long long maxval, const char **errp) noexcept {
  return ::strtonum(s, minval, maxval, errp);
}

#ifdef _WIN32
int Client::sys_ioctlsocket(Socket s, long cmd, u_long *argp) noexcept {
  return ::ioctlsocket(s, cmd, argp);
}
#else
int Client::sys_fcntl(Socket s, int cmd) noexcept { return ::fcntl(s, cmd); }
int Client::sys_fcntl(Socket s, int cmd, int arg) noexcept {
  return ::fcntl(s, cmd, arg);
}
#endif

int Client::sys_getsockopt(Socket socket, int level, int name, void *value,
                           socklen_t *len) noexcept {
  return ::getsockopt(socket, level, name, AS_OS_OPTION_VALUE(value), len);
}

}  // namespace libndt
