#ifndef MEASUREMENT_KIT_LIBNDT_NDT_HPP
#define MEASUREMENT_KIT_LIBNDT_NDT_HPP

#ifndef _WIN32
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

namespace measurement_kit {
namespace libndt {

constexpr uint64_t api_major = 0;
constexpr uint64_t api_minor = 1;
constexpr uint64_t api_patch = 0;

constexpr uint64_t nettest_middlebox = 1 << 0;
constexpr uint64_t nettest_upload = 1 << 1;
constexpr uint64_t nettest_download = 1 << 2;
constexpr uint64_t nettest_simple_firewall = 1 << 3;
constexpr uint64_t nettest_status = 1 << 4;
constexpr uint64_t nettest_meta = 1 << 5;
constexpr uint64_t nettest_upload_ext = 1 << 6;
constexpr uint64_t nettest_download_ext = 1 << 7;

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

constexpr const char *ndt_version_compat = "v3.7.0";

constexpr char msg_kickoff[] = "123456 654321";
constexpr size_t msg_kickoff_size = sizeof(msg_kickoff) - 1;

constexpr uint64_t verbosity_quiet = 0;
constexpr uint64_t verbosity_warning = 1;
constexpr uint64_t verbosity_info = 2;
constexpr uint64_t verbosity_debug = 3;

constexpr auto max_loops = 256;

using Size = uint64_t;
using Ssize = int64_t;
using Socket = int64_t;
using SockLen = int;

class Ndt {
public:
  // Settings

  std::string hostname;
  std::string port;
  uint64_t test_suite = 0;
  uint64_t verbosity = verbosity_quiet;
  std::map<std::string, std::string> metadata{
    {"client.version", "v3.7.0"},
    {"client.application", "measurement-kit/libndt"},
  };

  // Top-level API

  bool run() noexcept;
  virtual void on_warning(const std::string &s) noexcept;
  virtual void on_info(const std::string &s) noexcept;
  virtual void on_debug(const std::string &s) noexcept;

  // High-level API

  bool connect() noexcept;
  bool send_login() noexcept;
  bool recv_kickoff() noexcept;
  bool wait_in_queue() noexcept;
  bool recv_version() noexcept;
  bool recv_tests_ids() noexcept;
  bool run_tests() noexcept;
  bool recv_results_and_logout() noexcept;
  bool wait_close() noexcept;

  // Mid-level API

  bool run_download() noexcept;
  bool run_meta() noexcept;
  bool run_upload() noexcept;

  // Low-level API

  bool msg_write_json(uint8_t code, const std::string &msg) noexcept;

  bool msg_write(uint8_t code, const std::string &msg) noexcept;

  bool msg_expect_empty(uint8_t code) noexcept;

  bool msg_expect(uint8_t code, std::string *msg) noexcept;

  bool msg_read_json(uint8_t *code, std::string *msg) noexcept;

  bool msg_read(uint8_t *code, std::string *msg) noexcept;

  // Dependencies

  virtual int get_last_error() noexcept;
  virtual void set_last_error(int err) noexcept;

  virtual int getaddrinfo(const char *domain, const char *port,
                          const addrinfo *hints, addrinfo **res) noexcept;
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

  // Constructor and destructor

  Ndt() noexcept;
  virtual ~Ndt() noexcept;

private:
  Socket sock = -1;
  std::vector<uint64_t> granted_suite;
  std::vector<Socket> dload_socks;
  std::vector<Socket> upload_socks;
};

} // namespace libndt
} // namespace measurement_kit
#endif
