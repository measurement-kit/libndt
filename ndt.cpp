#include "ndt.hpp"

#ifdef _WIN32
// TODO(bassosimone): add here Win32 specific headers
#else
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#endif

#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "strtonum.h"

namespace measurement_kit {
namespace libndt {

// Private utils

#define EMIT_WARNING(statements)                   \
  do {                                             \
    if (settings.verbosity >= verbosity_warning) { \
      std::stringstream ss;                        \
      ss << statements;                            \
      on_warning(ss.str());                        \
    }                                              \
  } while (0)

#define EMIT_INFO(statements)                   \
  do {                                          \
    if (settings.verbosity >= verbosity_info) { \
      std::stringstream ss;                     \
      ss << statements;                         \
      on_info(ss.str());                        \
    }                                           \
  } while (0)

#define EMIT_DEBUG(statements)                   \
  do {                                           \
    if (settings.verbosity >= verbosity_debug) { \
      std::stringstream ss;                      \
      ss << statements;                          \
      on_debug(ss.str());                        \
    }                                            \
  } while (0)

class Ndt::Impl {
 public:
  Socket sock = -1;
  std::vector<uint64_t> granted_suite;
  std::vector<Socket> dload_socks;
  std::vector<Socket> upload_socks;
};

// Top-level API

bool Ndt::run() noexcept {
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
  EMIT_INFO("finished running tests");
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

void Ndt::on_warning(const std::string &msg) noexcept {
  std::clog << "[!] " << msg << std::endl;
}

void Ndt::on_info(const std::string &msg) noexcept {
  std::clog << "    " << msg << std::endl;
}

void Ndt::on_debug(const std::string &msg) noexcept {
  std::clog << "[D] " << msg << std::endl;
}

// High-level API

bool Ndt::connect() noexcept {
  assert(impl->sock == -1);
  return connect_tcp(settings.hostname, settings.port, &impl->sock);
}

bool Ndt::send_login() noexcept {
  assert(impl->sock != -1);
  return msg_write_login();
}

bool Ndt::recv_kickoff() noexcept {
  assert(impl->sock != -1);
  char buf[msg_kickoff_size];
  for (Size off = 0; off < msg_kickoff_size;) {
    Ssize n = this->recv(impl->sock, buf + off, sizeof(buf) - off);
    if (n <= 0) {
      EMIT_WARNING("recv_kickoff: recv() failed: " << get_last_error());
      return false;
    }
    off += (Size)n;
  }
  if (memcmp(buf, msg_kickoff, sizeof(buf)) != 0) {
    EMIT_WARNING("recv_kickoff: invalid kickoff message");
    return false;
  }
  return true;
}

bool Ndt::wait_in_queue() noexcept {
  assert(impl->sock != -1);
  std::string message;
  if (!msg_expect(msg_srv_queue, &message)) {
    return false;
  }
  // There is consensus among NDT developers that modern NDT should not
  // wait in queue rather it should fail immediately.
  if (message != "0") {
    EMIT_WARNING("wait_in_queue: server busy");
    return false;
  }
  return true;
}

bool Ndt::recv_version() noexcept {
  assert(impl->sock != -1);
  std::string message;
  if (!msg_expect(msg_login, &message)) {
    return false;
  }
  // TODO(bassosimone): validate version number?
  EMIT_INFO("server version: " << message);
  return true;
}

bool Ndt::recv_tests_ids() noexcept {
  assert(impl->sock != -1);
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
      EMIT_WARNING("recv_tests_ids: cannot stringify token: "
                   << cur.data() << " (error: " << errstr << ")");
      return false;
    }
    impl->granted_suite.push_back(tid);
  }
  return true;
}

bool Ndt::run_tests() noexcept {
  for (auto &tid : impl->granted_suite) {
    switch (tid) {
      case nettest_upload:
      case nettest_upload_ext:
        EMIT_INFO("running upload test");
        if (!run_upload()) {
          return false;
        }
        break;
      case nettest_meta:
        EMIT_INFO("running meta test");
        if (!run_meta()) {
          return false;
        }
        break;
      case nettest_download:
      case nettest_download_ext:
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

bool Ndt::recv_results_and_logout() noexcept {
  assert(impl->sock != -1);
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
        EMIT_WARNING("recv_results_and_logout: invalid number of tokens");
        return false;
      }
      EMIT_DEBUG("recv_results_and_logout: key: " << keyval[0]);
      EMIT_DEBUG("recv_results_and_logout: value: " << keyval[1]);
    }
  }
  EMIT_WARNING("recv_results_and_logout: too many msg_results messages");
  return false;  // Too many loops
}

bool Ndt::wait_close() noexcept {
  fd_set readset;
  FD_ZERO(&readset);
  FD_SET(impl->sock, &readset);
  timeval tv{};
  tv.tv_sec = 1;
  auto rv = this->select(impl->sock + 1, &readset, nullptr, nullptr, &tv);
  if (rv < 0) {
    EMIT_WARNING("wait_close(): select() failed: " << get_last_error());
    return false;
  }
  if (rv == 0) {
    EMIT_DEBUG("wait_close(): timeout waiting for server to close connection");
    (void)this->shutdown(impl->sock, SHUT_RDWR);
    return true;  // be tolerant
  }
  char data;
  auto n = this->recv(impl->sock, &data, sizeof(data));
  if (n != 0) {
    EMIT_WARNING("wait_close(): server did not close connection");
    return false;
  }
  return true;
}

// Mid-level API

bool Ndt::run_download() noexcept {
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
    EMIT_WARNING("run_download: too little options");
    return false;
  }

  // Here we are being liberal; in theory we should only accept the
  // extra parameters when the test is S2C_EXT.

  std::string port;
  {
    const char *error = nullptr;
    (void)this->strtonum(options[0].data(), 1, UINT16_MAX, &error);
    if (error != nullptr) {
      EMIT_WARNING("run_download: cannot parse port");
      return false;
    }
    port = options[0];
  }

  // We do not parse fields that we don't use.

  uint8_t nflows = 1;
  if (options.size() >= 6) {
    const char *error = nullptr;
    nflows = this->strtonum(options[5].c_str(), 1, 16, &error);
    if (error != nullptr) {
      EMIT_WARNING("run_download: cannot parse num-flows");
      return false;
    }
  }

  for (uint8_t i = 0; i < nflows; ++i) {
    Socket sock = -1;
    if (!connect_tcp(settings.hostname, port, &sock)) {
      break;
    }
    impl->dload_socks.push_back(sock);
  }
  if (impl->dload_socks.size() != nflows) {
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
      for (auto &fd : impl->dload_socks) {
        FD_SET(fd, &set);
        maxsock = (std::max)(maxsock, fd);
      }
      timeval tv{};
      tv.tv_usec = 250000;
      if (this->select(maxsock + 1, &set, nullptr, nullptr, &tv) <= 0) {
        EMIT_WARNING("run_download: select() failed: " << get_last_error());
        return false;
      }
      for (auto &fd : impl->dload_socks) {
        if (FD_ISSET(fd, &set)) {
          Ssize n = this->recv(fd, buf, sizeof(buf));
          if (n < 0) {
            EMIT_WARNING("run_download: recv() failed: " << get_last_error());
            done = true;
            break;
          }
          if (n == 0) {
            EMIT_DEBUG("run_download: recv(): EOF");
            done = true;
            break;
          }
          recent_data += (uint64_t)n;
          total_data += (uint64_t)n;
        }
      }
      auto now = std::chrono::steady_clock::now();
      std::chrono::duration<double> elapsed = now - prev;
      if (elapsed.count() > 0.25) {
        auto speed = (recent_data * 8.0) / 1000.0 / elapsed.count();
        recent_data = 0;
        prev = now;
        EMIT_INFO("num_flows: " << (int)nflows << " elapsed: " << std::fixed
                                << std::setprecision(3) << elapsed.count()
                                << " s; speed: " << std::setprecision(0)
                                << std::setw(8) << std::right << speed
                                << " kbit/s");
      }
    }
    for (auto &fd : impl->dload_socks) {
      (void)shutdown(fd, SHUT_RDWR);
    }
    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = now - begin;
    if (elapsed.count() > 0.0) {
      client_side_speed = (total_data * 8.0) / 1000.0 / elapsed.count();
    }
  }

  {
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
        EMIT_WARNING("run_download: invalid number of tokens");
        return false;
      }
      EMIT_DEBUG("run_download: key: " << keyval[0]);
      EMIT_DEBUG("run_download: value: " << keyval[1]);
    }
  }

  EMIT_WARNING("run_download: too many msg_test_msg messages");
  return false;  // Too many loops
}

bool Ndt::run_meta() noexcept {
  if (!msg_expect_empty(msg_test_prepare)) {
    return false;
  }
  if (!msg_expect_empty(msg_test_start)) {
    return false;
  }

  for (auto &kv : settings.metadata) {
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

bool Ndt::run_upload() noexcept { return false; }

// Low-level API

bool Ndt::connect_tcp(const std::string &hostname, const std::string &port,
                      Socket *sock) noexcept {
  assert(sock != nullptr);
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
  addrinfo *rp = nullptr;
  int rv = this->getaddrinfo(hostname.data(), port.data(), &hints, &rp);
  if (rv != 0) {
    hints.ai_flags &= ~AI_NUMERICHOST;
    rv = this->getaddrinfo(hostname.data(), port.data(), &hints, &rp);
    if (rv != 0) {
      EMIT_WARNING("getaddrinfo() failed: " << gai_strerror(rv));
      return false;
    }
    // FALLTHROUGH
  }
  EMIT_DEBUG("getaddrinfo(): okay");
  for (auto aip = rp; (aip); aip = aip->ai_next) {
    *sock = this->socket(aip->ai_family, aip->ai_socktype, 0);
    if (*sock == -1) {
      EMIT_WARNING("socket() failed: " << get_last_error());
      continue;
    }
    if (this->connect(*sock, aip->ai_addr, aip->ai_addrlen) == 0) {
      EMIT_DEBUG("connect(): okay");
      break;
    }
    EMIT_WARNING("connect() failed: " << get_last_error());
    this->closesocket(*sock);
    *sock = -1;
  }
  this->freeaddrinfo(rp);
  return *sock != -1;
}

bool Ndt::msg_write_login() noexcept {
  static_assert(sizeof(settings.test_suite) == 1, "test_suite too large");
  uint8_t code = 0;
  settings.test_suite |= nettest_status | nettest_meta;
  if ((settings.test_suite & nettest_middlebox)) {
    EMIT_WARNING("msg_write_login(): nettest_middlebox: not implemented");
    settings.test_suite &= ~nettest_middlebox;
  }
  if ((settings.test_suite & nettest_simple_firewall)) {
    EMIT_WARNING("msg_write_login(): nettest_simple_firewall: not implemented");
    settings.test_suite &= ~nettest_simple_firewall;
  }
  if ((settings.test_suite & nettest_upload_ext)) {
    EMIT_WARNING("msg_write_login(): nettest_upload_ext: not implemented");
    settings.test_suite &= ~nettest_upload_ext;
  }
  std::string serio;
  switch (settings.proto) {
    case NdtProtocol::proto_legacy: {
      serio = std::string{(char *)&settings.test_suite,
                          sizeof(settings.test_suite)};
      code = msg_login;
      break;
    }
    case NdtProtocol::proto_json: {
      code = msg_extended_login;
      nlohmann::json msg{
          {"msg", ndt_version_compat},
          {"tests", std::to_string((int)settings.test_suite)},
      };
      try {
        serio = msg.dump();
      } catch (nlohmann::json::exception &) {
        return false;
      }
      break;
    }
    default:
      EMIT_WARNING("msg_write_login: protocol not supported");
      return false;
  }
  assert(code != 0);
  if (!msg_write_legacy(code, std::move(serio))) {
    return false;
  }
  return true;
}

bool Ndt::msg_write(uint8_t code, std::string &&msg) noexcept {
  EMIT_DEBUG("msg_write: message to send: " << msg);
  std::string s;
  switch (settings.proto) {
    case NdtProtocol::proto_legacy: {
      std::swap(s, msg);
      break;
    }
    case NdtProtocol::proto_json: {
      nlohmann::json json;
      json["msg"] = msg;
      try {
        s = json.dump();
      } catch (const nlohmann::json::exception &) {
        EMIT_WARNING("msg_write: cannot serialize JSON");
        return false;
      }
    }
    default:
      EMIT_WARNING("msg_write: protocol not supported");
      return false;
  }
  if (!msg_write_legacy(code, std::move(s))) {
    return false;
  }
  return true;
}

bool Ndt::msg_write_legacy(uint8_t code, std::string &&msg) noexcept {
  {
    EMIT_DEBUG("msg_write_legacy: raw message: " << msg);
    EMIT_DEBUG("msg_write_legacy: message length: " << msg.size());
    char header[3];
    header[0] = code;
    if (msg.size() > UINT16_MAX) {
      EMIT_WARNING("msg_write: message too long");
      return false;
    }
    uint16_t len = msg.size();
    len = htons(len);
    memcpy(&header[1], &len, sizeof(len));
    EMIT_DEBUG("msg_write_legacy: header[0] (type): " << (int)header[0]);
    EMIT_DEBUG("msg_write_legacy: header[1] (len-high): " << (int)header[1]);
    EMIT_DEBUG("msg_write_legacy: header[2] (len-low): " << (int)header[2]);
    for (Size off = 0; off < sizeof(header);) {
      Ssize n = this->send(impl->sock, header + off, sizeof(header) - off);
      if (n <= 0) {
        EMIT_WARNING("msg_write_legacy: send() failed: " << get_last_error());
        return false;
      }
      off += (Size)n;
    }
    EMIT_DEBUG("msg_write_legacy: sent message header");
  }
  for (Size off = 0; off < msg.size();) {
    Ssize n = this->send(impl->sock, msg.data() + off, msg.size() - off);
    if (n <= 0) {
      EMIT_WARNING("msg_write_legacy: send() failed: " << get_last_error());
      return false;
    }
    off += (Size)n;
  }
  EMIT_DEBUG("msg_write_legacy: sent message body");
  return true;
}

bool Ndt::msg_expect_empty(uint8_t expected_code) noexcept {
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

bool Ndt::msg_expect(uint8_t expected_code, std::string *s) noexcept {
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

bool Ndt::msg_read(uint8_t *code, std::string *msg) noexcept {
  assert(code != nullptr && msg != nullptr);
  std::string s;
  if (!msg_read_legacy(code, &s)) {
    return false;
  }
  switch (settings.proto) {
    case NdtProtocol::proto_legacy: {
      std::swap(s, *msg);
      break;
    }
    case NdtProtocol::proto_json: {
      nlohmann::json json;
      try {
        json = nlohmann::json::parse(s);
      } catch (const nlohmann::json::exception &) {
        EMIT_WARNING("msg_read: cannot parse JSON");
        return false;
      }
      try {
        *msg = json["msg"];
      } catch (const nlohmann::json::exception &) {
        EMIT_WARNING("msg_read: cannot find 'msg' field");
        return false;
      }
      break;
    }
    default:
      EMIT_WARNING("msg_read: protocol not supported");
      return false;
  }
  EMIT_DEBUG("msg_read: message: " << *msg);
  return true;
}

bool Ndt::msg_read_legacy(uint8_t *code, std::string *msg) noexcept {
  assert(code != nullptr && msg != nullptr);
  uint16_t len = 0;
  {
    char header[3];
    for (Size off = 0; off < sizeof(header);) {
      Ssize n = this->recv(impl->sock, header + off, sizeof(header) - off);
      if (n <= 0) {
        EMIT_WARNING("msg_read_legacy: recv() failed: " << get_last_error());
        return false;
      }
      off += (Size)n;
    }
    EMIT_DEBUG("msg_read_legacy: header[0] (type): " << (int)header[0]);
    EMIT_DEBUG("msg_read_legacy: header[1] (len-high): " << (int)header[1]);
    EMIT_DEBUG("msg_read_legacy: header[2] (len-low): " << (int)header[2]);
    *code = header[0];
    memcpy(&len, &header[1], sizeof(len));
    len = ntohs(len);
    EMIT_DEBUG("msg_read_legacy: message length: " << len);
  }
  char buf[len];
  for (Size off = 0; off < len;) {
    Ssize n = this->recv(impl->sock, buf + off, len - off);
    if (n <= 0) {
      EMIT_WARNING("msg_read_legacy: recv() failed: " << get_last_error());
      return false;
    }
    off += (Size)n;
  }
  *msg = std::string{buf, len};
  EMIT_DEBUG("msg_read_legacy: raw message: " << *msg);
  return true;
}

// Dependencies

#ifdef _WIN32
#define AS_OS_SOCKET(s) ((SOCKET)s)
#define AS_OS_SOCKLEN(n) ((int)n)
#define OS_SSIZE_MAX INT_MAX
#define OS_EINVAL WSAEINVAL
#define AS_OS_BUFFER(b) ((char *)b)
#define AS_OS_BUFFER_LEN(n) ((int)n)
#else
#define AS_OS_SOCKET(s) ((int)s)
#define AS_OS_SOCKLEN(n) ((socklen_t)n)
#define OS_SSIZE_MAX SSIZE_MAX
#define OS_EINVAL EINVAL
#define AS_OS_BUFFER(b) ((char *)b)
#define AS_OS_BUFFER_LEN(n) ((size_t)n)
#endif

int Ndt::get_last_error() noexcept {
#ifdef _WIN32
  return GetLastError();
#else
  return errno;
#endif
}

void Ndt::set_last_error(int err) noexcept {
#ifdef _WIN32
  SetLastError(err);
#else
  errno = err;
#endif
}

int Ndt::getaddrinfo(const char *domain, const char *port,
                     const addrinfo *hints, addrinfo **res) noexcept {
  return ::getaddrinfo(domain, port, hints, res);
}

void Ndt::freeaddrinfo(addrinfo *aip) noexcept { ::freeaddrinfo(aip); }

Socket Ndt::socket(int domain, int type, int protocol) noexcept {
  return (Socket)::socket(domain, type, protocol);
}

int Ndt::connect(Socket fd, const sockaddr *sa, SockLen len) noexcept {
  return ::connect(AS_OS_SOCKET(fd), sa, AS_OS_SOCKLEN(len));
}

Ssize Ndt::recv(Socket fd, void *base, Size count) noexcept {
  if (count > OS_SSIZE_MAX) {
    set_last_error(OS_EINVAL);
    return -1;
  }
  return (Ssize)::recv(AS_OS_SOCKET(fd), AS_OS_BUFFER(base),
                       AS_OS_BUFFER_LEN(count), 0);
}

Ssize Ndt::send(Socket fd, const void *base, Size count) noexcept {
  if (count > OS_SSIZE_MAX) {
    set_last_error(OS_EINVAL);
    return -1;
  }
  return (Ssize)::send(AS_OS_SOCKET(fd), AS_OS_BUFFER(base),
                       AS_OS_BUFFER_LEN(count), 0);
}

int Ndt::shutdown(Socket fd, int how) noexcept { return ::shutdown(fd, how); }

int Ndt::closesocket(Socket fd) noexcept {
#ifdef _WIN32
  return ::closesocket(fd);
#else
  return ::close(fd);
#endif
}

int Ndt::select(int numfd, fd_set *readset, fd_set *writeset, fd_set *exceptset,
                timeval *timeout) noexcept {
  return ::select(numfd, readset, writeset, exceptset, timeout);
}

long long Ndt::strtonum(const char *s, long long minval, long long maxval,
                        const char **errp) noexcept {
  return ::strtonum(s, minval, maxval, errp);
}

// Constructor and destructor

Ndt::Ndt() noexcept { impl.reset(new Ndt::Impl); }

Ndt::~Ndt() noexcept {
  if (impl->sock != -1) {
    this->closesocket(impl->sock);
  }
  for (auto &sock : impl->dload_socks) {
    this->closesocket(sock);
  }
  for (auto &sock : impl->upload_socks) {
    this->closesocket(sock);
  }
}

}  // namespace libndt
}  // namespace measurement_kit
