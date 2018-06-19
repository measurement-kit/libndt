// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt.hpp"

#ifndef _WIN32
#include <arpa/inet.h>  // IWYU pragma: keep
#include <netdb.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <deque>
#include <vector>

#include "catch.hpp"
#include "json.hpp"

#ifdef _WIN32
#define OS_EINVAL WSAEINVAL
#define OS_EWOULDBLOCK WSAEWOULDBLOCK
#else
#define OS_EINVAL EINVAL
#define OS_EWOULDBLOCK EWOULDBLOCK
#endif

// Unit tests
// ==========
//
// Speaking of coverage, if specific code is already tested by running the
// example client, we don't need to write also a test for it here.

using namespace measurement_kit;

// Client::run() tests
// -------------------

class FailQueryMlabns : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::query_mlabns() failure") {
  FailQueryMlabns client;
  REQUIRE(client.run() == false);
}

class FailConnect : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return true; }
  bool connect() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::connect() failure") {
  FailConnect client;
  REQUIRE(client.run() == false);
}

class FailSendLogin : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return true; }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::send_login() failure") {
  FailSendLogin client;
  REQUIRE(client.run() == false);
}

class FailRecvKickoff : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return true; }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return true; }
  bool recv_kickoff() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::recv_kickoff() failure") {
  FailRecvKickoff client;
  REQUIRE(client.run() == false);
}

class FailWaitInQueue : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return true; }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return true; }
  bool recv_kickoff() noexcept override { return true; }
  bool wait_in_queue() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::wait_in_queue() failure") {
  FailWaitInQueue client;
  REQUIRE(client.run() == false);
}

class FailRecvVersion : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return true; }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return true; }
  bool recv_kickoff() noexcept override { return true; }
  bool wait_in_queue() noexcept override { return true; }
  bool recv_version() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::recv_version() failure") {
  FailRecvVersion client;
  REQUIRE(client.run() == false);
}

class FailRecvTestsId : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return true; }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return true; }
  bool recv_kickoff() noexcept override { return true; }
  bool wait_in_queue() noexcept override { return true; }
  bool recv_version() noexcept override { return true; }
  bool recv_tests_ids() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::recv_tests_ids() failure") {
  FailRecvTestsId client;
  REQUIRE(client.run() == false);
}

class FailRunTests : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return true; }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return true; }
  bool recv_kickoff() noexcept override { return true; }
  bool wait_in_queue() noexcept override { return true; }
  bool recv_version() noexcept override { return true; }
  bool recv_tests_ids() noexcept override { return true; }
  bool run_tests() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::run_tests() failure") {
  FailRunTests client;
  REQUIRE(client.run() == false);
}

class FailRecvResultsAndLogout : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return true; }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return true; }
  bool recv_kickoff() noexcept override { return true; }
  bool wait_in_queue() noexcept override { return true; }
  bool recv_version() noexcept override { return true; }
  bool recv_tests_ids() noexcept override { return true; }
  bool run_tests() noexcept override { return true; }
  bool recv_results_and_logout() noexcept override { return false; }
};

TEST_CASE(  //
    "Client::run() deals with Client::recv_results_and_logout() failure") {
  FailRecvResultsAndLogout client;
  REQUIRE(client.run() == false);
}

class FailWaitClose : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns() noexcept override { return true; }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return true; }
  bool recv_kickoff() noexcept override { return true; }
  bool wait_in_queue() noexcept override { return true; }
  bool recv_version() noexcept override { return true; }
  bool recv_tests_ids() noexcept override { return true; }
  bool run_tests() noexcept override { return true; }
  bool recv_results_and_logout() noexcept override { return true; }
  bool wait_close() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::wait_close() failure") {
  FailWaitClose client;
  REQUIRE(client.run() == false);
}

// Client::on_warning() tests
// --------------------------

TEST_CASE("Client::on_warning() works as expected") {
  libndt::Client client;
  client.on_warning("calling on_warning() to increase coverage");
}

// Client::query_mlabns() tests
// ----------------------------

class FailQueryMlabnsCurl : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns_curl(const std::string &, long,
                         std::string *) noexcept override {
    return false;
  }
};

TEST_CASE("Client::query_mlabns() does nothing when we already know hostname") {
  libndt::Settings settings;
  settings.hostname = "neubot.mlab.mlab1.trn01.measurement-lab.org";
  FailQueryMlabnsCurl client{settings};
  REQUIRE(client.query_mlabns() == true);
}

TEST_CASE(
    "Client::query_mlabns() deals with Client::query_mlabns_curl() failure") {
  FailQueryMlabnsCurl client;
  REQUIRE(client.query_mlabns() == false);
}

class EmptyMlabnsJson : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns_curl(const std::string &, long,
                         std::string *body) noexcept override {
    *body = "";
    return true;
  }
};

TEST_CASE("Client::query_mlabns() deals with empty JSON") {
  EmptyMlabnsJson client;
  REQUIRE(client.query_mlabns() == false);
}

class InvalidMlabnsJson : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns_curl(const std::string &, long,
                         std::string *body) noexcept override {
    *body = "{{{{";
    return true;
  }
};

TEST_CASE("Client::query_mlabns() deals with invalid JSON") {
  InvalidMlabnsJson client;
  REQUIRE(client.query_mlabns() == false);
}

class IncompleteMlabnsJson : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns_curl(const std::string &, long,
                         std::string *body) noexcept override {
    *body = "{}";
    return true;
  }
};

TEST_CASE("Client::query_mlabns() deals with incomplete JSON") {
  IncompleteMlabnsJson client;
  REQUIRE(client.query_mlabns() == false);
}

// Client::recv_kickoff() tests
// ----------------------------

class FailNetxRecvn : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_recvn(libndt::Socket, void *,
                         libndt::Size) noexcept override {
    return libndt::Err::io_error;
  }
};

TEST_CASE("Client::recv_kickoff() deals with Client::recvn() failure") {
  FailNetxRecvn client;
  REQUIRE(client.recv_kickoff() == false);
}

class NetxRecvnEof : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_recvn(libndt::Socket, void *,
                         libndt::Size) noexcept override {
    return libndt::Err::eof;
  }
};

TEST_CASE("Client::recv_kickoff() deals with Client::recvn() EOF") {
  NetxRecvnEof client;
  REQUIRE(client.recv_kickoff() == false);
}

class NetxRecvnInvalidKickoff : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_recvn(  //
      libndt::Socket, void *buf, libndt::Size siz) noexcept override {
    REQUIRE(buf != nullptr);
    REQUIRE(siz >= 1);
    for (libndt::Size i = 0; i < siz; ++i) {
      ((char *)buf)[i] = 'x';
    }
    return libndt::Err::none;
  }
};

TEST_CASE("Client::recv_kickoff() deals with invalid kickoff") {
  NetxRecvnInvalidKickoff client;
  REQUIRE(client.recv_kickoff() == false);
}

// Client::wait_in_queue() tests
// ----------------------------

class FailMsgExpect : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect(uint8_t, std::string *) noexcept override { return false; }
};

TEST_CASE("Client::wait_in_queue() deals with Client::msg_expect() failure") {
  FailMsgExpect client;
  REQUIRE(client.wait_in_queue() == false);
}

class ServerBusy : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect(uint8_t, std::string *val) noexcept override {
    *val = "9999";
    return true;
  }
};

TEST_CASE("Client::wait_in_queue() fails when server is busy") {
  ServerBusy client;
  REQUIRE(client.wait_in_queue() == false);
}

// Client::recv_version() tests
// ----------------------------

TEST_CASE("Client::recv_version() deals with Client::msg_expect() failure") {
  FailMsgExpect client;
  REQUIRE(client.recv_version() == false);
}

// Client::recv_tests_ids() tests
// ------------------------------

TEST_CASE("Client::recv_tests_ids() deals with Client::msg_expect() failure") {
  FailMsgExpect client;
  REQUIRE(client.recv_tests_ids() == false);
}

class InvalidTestsIds : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect(uint8_t, std::string *val) noexcept override {
    *val = "777 888 999";
    return true;
  }
};

TEST_CASE("Client::recv_tests_ids() fails with invalid tests ids") {
  InvalidTestsIds client;
  REQUIRE(client.recv_tests_ids() == false);
}

// Client::run_tests() tests
// -------------------------

class RunTestsMock : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect(uint8_t, std::string *val) noexcept override {
    *val = tests_ids;
    return true;
  }

  bool run_upload() noexcept override { return false; }
  bool run_meta() noexcept override { return false; }
  bool run_download() noexcept override { return false; }

  std::string tests_ids;
};

TEST_CASE("Client::run_tests() deals with Client::run_upload() failure") {
  RunTestsMock client;
  client.tests_ids = std::to_string(libndt::nettest::upload);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

TEST_CASE("Client::run_tests() deals with Client::run_meta() failure") {
  RunTestsMock client;
  client.tests_ids = std::to_string(libndt::nettest::meta);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

TEST_CASE("Client::run_tests() deals with Client::run_download() failure") {
  RunTestsMock client;
  client.tests_ids = std::to_string(libndt::nettest::download);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

TEST_CASE("Client::run_tests() deals with unexpected test-id") {
  RunTestsMock client;
  client.tests_ids = std::to_string(libndt::nettest::status);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

// Client::recv_results_and_logout() tests
// ---------------------------------------

class FailMsgRead : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_read(uint8_t *, std::string *) noexcept override { return false; }
};

TEST_CASE(
    "Client::recv_results_and_logout() deals with Client::msg_read() failure") {
  FailMsgRead client;
  REQUIRE(client.recv_results_and_logout() == false);
}

class NeitherResultsNorLogout : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_read(uint8_t *code, std::string *msg) noexcept override {
    *code = libndt::msg_comm_failure;
    *msg = "";
    return true;
  }
};

TEST_CASE("Client::recv_results_and_logout() deals with unexpected message") {
  NeitherResultsNorLogout client;
  REQUIRE(client.recv_results_and_logout() == false);
}

class InvalidResults : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_read(uint8_t *code, std::string *msg) noexcept override {
    *code = libndt::msg_results;
    *msg = "antani-antani";
    return true;
  }
};

TEST_CASE("Client::recv_results_and_logout() deals with invalid results") {
  InvalidResults client;
  REQUIRE(client.recv_results_and_logout() == false);
}

class TooManyResults : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_read(uint8_t *code, std::string *msg) noexcept override {
    *code = libndt::msg_results;
    *msg = "antani:antani";
    return true;
  }
};

TEST_CASE("Client::recv_results_and_logout() deals with too many results") {
  TooManyResults client;
  REQUIRE(client.recv_results_and_logout() == false);
}

// Client::wait_close() tests
// --------------------------

class SelectHardFailure : public libndt::Client {
 public:
  using libndt::Client::Client;
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
#ifdef _WIN32
    set_last_system_error(WSAEBADF);
#else
    set_last_system_error(EBADF);
#endif
    return -1;
  }
};

TEST_CASE("Client::wait_close() deals with Client::select() hard failure") {
  SelectHardFailure client;
  REQUIRE(client.wait_close() == false);
}

#ifndef _WIN32
class SelectEintr : public libndt::Client {
 public:
  using libndt::Client::Client;
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    set_last_system_error(EINTR);
    return -1;
  }
};

TEST_CASE("Client::wait_close() deals with Client::select() EINTR") {
  SelectEintr client;
  REQUIRE(client.wait_close() == true /* Being tolerant */);
}
#endif

class SelectTimeout : public libndt::Client {
 public:
  using libndt::Client::Client;
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 0;
  }
};

TEST_CASE("Client::wait_close() deals with Client::select() timeout") {
  SelectTimeout client;
  REQUIRE(client.wait_close() == true /* Being tolerant */);
}

class NotEofAfterGoodSelect : public libndt::Client {
 public:
  using libndt::Client::Client;
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::wait_close() deals with Client::recv() failure different from "
    "EOF") {
  NotEofAfterGoodSelect client;
  REQUIRE(client.wait_close() == false);
}

class SuccessAfterGoodSelect : public libndt::Client {
 public:
  using libndt::Client::Client;
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size size,
                        libndt::Size *tot) noexcept override {
    *tot = size;
    return libndt::Err::none;
  }
};

TEST_CASE(
    "Client::wait_close() deals with Client::recv() success (unexpected)") {
  SuccessAfterGoodSelect client;
  REQUIRE(client.wait_close() == false);
}

// Client::run_download() tests
// ----------------------------

class FailMsgExpectTestPrepare : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return false;
  }
};

TEST_CASE(
    "Client::run_download() deals with Client::msg_expect_test_prepare() "
    "failure") {
  FailMsgExpectTestPrepare client;
  REQUIRE(client.run_download() == false);
}

class FailNetxMaybesocks5hConnect : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *) noexcept override {
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::run_download() deals with Client::netx_maybesocks5h_dial() "
    "failure") {
  FailNetxMaybesocks5hConnect client;
  REQUIRE(client.run_download() == false);
}

class FailMsgExpectEmpty : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return false; }
};

TEST_CASE(
    "Client::run_download() deals with Client::msg_expect_empty() failure") {
  FailMsgExpectEmpty client;
  REQUIRE(client.run_download() == false);
}

class FailSelectDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    set_last_system_error(0);  // The code checks whether it's EINTR
    return -1;
  }
};

TEST_CASE("Client::run_download() deals with Client::select() failure") {
  FailSelectDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class FailRecvDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::invalid_argument;
  }
};

TEST_CASE("Client::run_download() deals with Client::recv() failure") {
  FailRecvDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class RecvEofDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::eof;
  }
};

TEST_CASE("Client::run_download() honours max_runtime") {
  libndt::Settings settings;
  settings.max_runtime = 0;
  RecvEofDuringDownload client{settings};
  REQUIRE(client.run_download() == false);
}

class FailMsgReadLegacyDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::eof;
  }
  bool msg_read_legacy(uint8_t *, std::string *) noexcept override {
    return false;
  }
};

TEST_CASE(
    "Client::run_download() deals with Client::msg_read_legacy_failure()") {
  FailMsgReadLegacyDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class RecvNonTestMsgDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::eof;
  }
  bool msg_read_legacy(uint8_t *code, std::string *) noexcept override {
    *code = libndt::msg_logout;
    return true;
  }
};

TEST_CASE("Client::run_download() deals with non-msg_test_msg receipt") {
  RecvNonTestMsgDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class FailMsgWriteDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::eof;
  }
  bool msg_read_legacy(uint8_t *code, std::string *) noexcept override {
    *code = libndt::msg_test_msg;
    return true;
  }
  bool msg_write(uint8_t, std::string &&) noexcept override { return false; }
};

TEST_CASE("Client::run_download() deals with Client::msg_write() failure") {
  FailMsgWriteDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class FailMsgReadDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::eof;
  }
  bool msg_read_legacy(uint8_t *code, std::string *) noexcept override {
    *code = libndt::msg_test_msg;
    return true;
  }
  bool msg_write(uint8_t, std::string &&) noexcept override { return true; }
  bool msg_read(uint8_t *, std::string *) noexcept override { return false; }
};

TEST_CASE("Client::run_download() deals with Client::msg_read() failure") {
  FailMsgReadDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class RecvNonTestOrLogoutMsgDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::eof;
  }
  bool msg_read_legacy(uint8_t *code, std::string *) noexcept override {
    *code = libndt::msg_test_msg;
    return true;
  }
  bool msg_write(uint8_t, std::string &&) noexcept override { return true; }
  bool msg_read(uint8_t *code, std::string *) noexcept override {
    *code = libndt::msg_login;
    return true;
  }
};

TEST_CASE("Client::run_download() deals with non-logout-or-test msg") {
  RecvNonTestOrLogoutMsgDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class FailEmitResultDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::eof;
  }
  bool msg_read_legacy(uint8_t *code, std::string *) noexcept override {
    *code = libndt::msg_test_msg;
    return true;
  }
  bool msg_write(uint8_t, std::string &&) noexcept override { return true; }
  bool msg_read(uint8_t *code, std::string *s) noexcept override {
    *code = libndt::msg_test_msg;
    *s = "antani-antani";  // Causes emit_result() to fail
    return true;
  }
};

TEST_CASE("Client::run_download() deals with emit_result() failure") {
  FailEmitResultDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class TooManyTestMsgsDuringDownload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_recv(libndt::Socket, void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::eof;
  }
  bool msg_read_legacy(uint8_t *code, std::string *) noexcept override {
    *code = libndt::msg_test_msg;
    return true;
  }
  bool msg_write(uint8_t, std::string &&) noexcept override { return true; }
  bool msg_read(uint8_t *code, std::string *s) noexcept override {
    *code = libndt::msg_test_msg;
    *s = "antani:antani";  // Accepted by emit_result()
    return true;
  }
};

TEST_CASE("Client::run_download() deals with too many results messages") {
  TooManyTestMsgsDuringDownload client;
  REQUIRE(client.run_download() == false);
}

// Client::run_meta() tests
// ------------------------

class FailFirstMsgExpectEmpty : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_empty(uint8_t) noexcept override { return false; }
};

TEST_CASE(
    "Client::run_meta() deals with first Client::msg_expect_empty() failure") {
  FailFirstMsgExpectEmpty client;
  REQUIRE(client.run_meta() == false);
}

class FailSecondMsgExpectEmpty : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_empty(uint8_t code) noexcept override {
    return code == libndt::msg_test_prepare;
  }
};

TEST_CASE(
    "Client::run_meta() deals with second Client::msg_expect_empty() failure") {
  FailSecondMsgExpectEmpty client;
  REQUIRE(client.run_meta() == false);
}

class FailMsgWriteDuringMeta : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  bool msg_write(uint8_t, std::string &&) noexcept override { return false; }
};

TEST_CASE("Client::run_meta() deals with Client::msg_write() failure") {
  FailMsgWriteDuringMeta client;
  REQUIRE(client.run_meta() == false);
}

class FailFinalMsgWriteDuringMeta : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  bool msg_write(uint8_t, std::string &&s) noexcept override { return s != ""; }
};

TEST_CASE("Client::run_meta() deals with final Client::msg_write() failure") {
  FailFinalMsgWriteDuringMeta client;
  REQUIRE(client.run_meta() == false);
}

class FailFinalMsgExpectEmptyDuringMeta : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_empty(uint8_t code) noexcept override {
    return code != libndt::msg_test_finalize;
  }
  bool msg_write(uint8_t, std::string &&) noexcept override { return true; }
};

TEST_CASE(
    "Client::run_meta() deals with final Client::msg_expect_empty() failure") {
  FailFinalMsgExpectEmptyDuringMeta client;
  REQUIRE(client.run_meta() == false);
}

// Client::run_upload() tests
// --------------------------

TEST_CASE(
    "Client::run_upload() deals with Client::msg_expect_test_prepare() "
    "failure") {
  FailMsgExpectTestPrepare client;
  REQUIRE(client.run_upload() == false);
}

class TestPrepareMoreThanOneFlow : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *,
                               uint8_t *nflows) noexcept override {
    *nflows = 11;
    return true;
  }
};

TEST_CASE("Client::run_upload() deals with more than one flow") {
  TestPrepareMoreThanOneFlow client;
  REQUIRE(client.run_upload() == false);
}

TEST_CASE(
    "Client::run_upload() deals with Client::netx_maybesocks5h_dial() "
    "failure") {
  FailNetxMaybesocks5hConnect client;
  REQUIRE(client.run_upload() == false);
}

TEST_CASE(
    "Client::run_upload() deals with Client::msg_expect_empty() failure") {
  FailMsgExpectEmpty client;
  REQUIRE(client.run_upload() == false);
}

TEST_CASE("Client::run_upload() deals with Client::select() failure") {
  FailSelectDuringDownload client;  // Works also for upload phase
  REQUIRE(client.run_upload() == false);
}

class FailSendDuringUpload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_send(libndt::Socket, const void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::io_error;
  }
};

TEST_CASE("Client::run_upload() deals with Client::send() failure") {
  FailSendDuringUpload client;
  REQUIRE(client.run_upload() == false);
}

TEST_CASE("Client::run_upload() honours max_runtime") {
  libndt::Settings settings;
  settings.max_runtime = 0;
  FailSendDuringUpload client{settings};
  REQUIRE(client.run_upload() == false);
}

class FailMsgExpectDuringUpload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t) noexcept override { return true; }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_send(libndt::Socket, const void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::io_error;
  }
  bool msg_expect(uint8_t, std::string *) noexcept override { return false; }
};

TEST_CASE("Client::run_upload() deals with Client::msg_expect() failure") {
  FailMsgExpectDuringUpload client;
  REQUIRE(client.run_upload() == false);
}

class FailFinalMsgExpectEmptyDuringUpload : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  libndt::Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  bool msg_expect_empty(uint8_t code) noexcept override {
    return code != libndt::msg_test_finalize;
  }
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Err netx_send(libndt::Socket, const void *, libndt::Size,
                        libndt::Size *) noexcept override {
    return libndt::Err::io_error;
  }
  bool msg_expect(uint8_t, std::string *) noexcept override { return true; }
};

TEST_CASE(
    "Client::run_upload() deals with final Client::msg_expect_empty() "
    "failure") {
  FailFinalMsgExpectEmptyDuringUpload client;
  REQUIRE(client.run_upload() == false);
}

// Client::msg_write_login() tests
// -------------------------------

TEST_CASE("Client::msg_write_login() deals with invalid protocol") {
  libndt::Settings settings;
  // That is, more precisely, a valid but unimplemented proto
  settings.proto = libndt::protocol::websockets;
  libndt::Client client{settings};
  REQUIRE(client.msg_write_login(libndt::ndt_version_compat) == false);
}

class FailMsgWriteLegacy : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_write_legacy(uint8_t, std::string &&) noexcept override {
    return false;
  }
};

TEST_CASE(
    "Client::msg_write_login() deals with Client::msg_write_legacy() failure") {
  FailMsgWriteLegacy client;
  REQUIRE(client.msg_write_login(libndt::ndt_version_compat) == false);
}

class ValidatingMsgWriteLegacy : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_write_legacy(uint8_t, std::string &&value) noexcept override {
    auto doc = nlohmann::json::parse(value);
    std::string tests_string = doc.at("tests");
    const char *errstr = nullptr;
    auto tests = this->strtonum(tests_string.c_str(), 0, 256, &errstr);
    REQUIRE(errstr == nullptr);
    REQUIRE((tests & libndt::nettest::middlebox) == 0);
    REQUIRE((tests & libndt::nettest::simple_firewall) == 0);
    REQUIRE((tests & libndt::nettest::upload_ext) == 0);
    return true;
  }
};

TEST_CASE("Client::msg_write_login() does not propagate unknown tests ids") {
  libndt::Settings settings;
  settings.proto = libndt::protocol::json;
  settings.test_suite = 0xff;
  ValidatingMsgWriteLegacy client{settings};
  REQUIRE(client.msg_write_login(libndt::ndt_version_compat) == true);
}

static std::string non_serializable() noexcept {
  // This should be a `gzip -9`-ed `build.ninja` file. It's not something
  // we can serialize as JSON. So helps to fail this kind of tests.
  static std::vector<uint8_t> v = {
      31,  139, 8,   0,   8,   13,  239, 90,  2,   3,   101, 144, 205, 10,  194,
      48,  16,  132, 239, 121, 138, 57,  136, 151, 146, 74,  69,  68,  10,  250,
      10,  30,  61,  74,  154, 172, 18,  141, 73,  73,  19,  232, 193, 135, 215,
      212, 150, 254, 120, 9,   153, 229, 219, 153, 221, 245, 209, 16,  100, 219,
      50,  64,  186, 215, 75,  88,  133, 35,  238, 89,  6,   126, 17,  198, 124,
      95,  106, 131, 23,  224, 53,  41,  97,  131, 150, 224, 77,  80,  71,  153,
      101, 69,  1,   126, 222, 130, 75,  172, 180, 5,   119, 88,  185, 24,  152,
      79,  118, 70,  219, 231, 191, 223, 143, 72,  244, 143, 18,  126, 198, 8,
      15,  233, 23,  136, 143, 118, 198, 228, 155, 148, 181, 61,  173, 11,  188,
      17,  136, 18,  153, 27,  119, 103, 172, 138, 218, 40,  84,  162, 161, 253,
      238, 74,  86,  58,  69,  185, 43,  211, 98,  139, 162, 172, 235, 30,  142,
      225, 118, 184, 42,  154, 162, 211, 210, 8,   26,  93,  61,  26,  103, 7,
      104, 144, 255, 128, 40,  211, 22,  139, 33,  230, 57,  163, 89,  223, 27,
      168, 9,   131, 115, 247, 31,  109, 147, 44,  187, 99,  142, 9,   61,  63,
      109, 254, 238, 95,  166, 75,  117, 138, 125, 0,   96,  224, 123, 120, 208,
      1,   0,   0};
  return std::string{(char *)v.data(), v.size()};
}

TEST_CASE("Client::msg_write_login() deals with unserializable JSON") {
  libndt::Settings settings;
  settings.proto = libndt::protocol::json;
  libndt::Client client{settings};
  auto s = non_serializable();
  REQUIRE(client.msg_write_login(s) == false);
}

// Client::msg_write() tests
// -------------------------

TEST_CASE("Client::msg_write() deals with unserializable JSON") {
  libndt::Settings settings;
  settings.proto = libndt::protocol::json;
  libndt::Client client{settings};
  auto s = non_serializable();
  REQUIRE(client.msg_write(libndt::msg_test_start, std::move(s)) == false);
}

TEST_CASE("Client::msg_write() deals with invalid protocol") {
  libndt::Settings settings;
  // That is, more precisely, a valid but unimplemented proto
  settings.proto = libndt::protocol::websockets;
  libndt::Client client{settings};
  REQUIRE(client.msg_write(libndt::msg_test_start, "foo") == false);
}

TEST_CASE("Client::msg_write() deals with Client::msg_write_legacy() failure") {
  FailMsgWriteLegacy client;
  REQUIRE(client.msg_write(libndt::msg_test_start, "foo") == false);
}

// Client::msg_write_legacy() tests
// --------------------------------

TEST_CASE("Client::msg_write_legacy() deals with too-big messages") {
  libndt::Client client;
  std::string m;
  m.resize(UINT16_MAX + 1);
  REQUIRE(client.msg_write_legacy(  //
              libndt::msg_test_start, std::move(m)) == false);
}

class FailNetxSendn : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::msg_write_legacy() deals with Client::netx_sendn() failure when "
    "sending header") {
  FailNetxSendn client;
  std::string m{"foo"};
  client.set_last_system_error(0);
  REQUIRE(client.msg_write_legacy(  //
              libndt::msg_test_start, std::move(m)) == false);
}

class FailLargeNetxSendn : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size siz) noexcept override {
    return siz == 3 ? libndt::Err::none : libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::msg_write_legacy() deals with Client::netx_sendn() failure when "
    "sending message") {
  FailLargeNetxSendn client;
  std::string m{"foobar"};
  client.set_last_system_error(0);
  REQUIRE(client.msg_write_legacy(  //
              libndt::msg_test_start, std::move(m)) == false);
}

// Client::msg_expect_test_prepare() tests
// ---------------------------------------

TEST_CASE(
    "Client::msg_expect_test_prepare() deals with Client::msg_expect() "
    "failure") {
  FailMsgExpect client;
  std::string port;
  uint8_t nflows = 0;
  REQUIRE(client.msg_expect_test_prepare(&port, &nflows) == false);
}

class TooShortVector : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect(uint8_t, std::string *) noexcept override { return true; }
};

TEST_CASE("Client::msg_expect_test_prepare() deals with too-short vector") {
  TooShortVector client;
  std::string port;
  uint8_t nflows = 0;
  REQUIRE(client.msg_expect_test_prepare(&port, &nflows) == false);
}

class InvalidPortVector : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect(uint8_t, std::string *s) noexcept override {
    *s = "65536";
    return true;
  }
};

TEST_CASE("Client::msg_expect_test_prepare() deals with invalid port") {
  InvalidPortVector client;
  std::string port;
  uint8_t nflows = 0;
  REQUIRE(client.msg_expect_test_prepare(&port, &nflows) == false);
}

class InvalidNumFlowsVector : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect(uint8_t, std::string *s) noexcept override {
    *s = "65530 xx xx xx xx 32";
    return true;
  }
};

TEST_CASE("Client::msg_expect_test_prepare() deals with invalid num-flows") {
  InvalidNumFlowsVector client;
  std::string port;
  uint8_t nflows = 0;
  REQUIRE(client.msg_expect_test_prepare(&port, &nflows) == false);
}

// Client::msg_expect_empty() tests
// --------------------------------

TEST_CASE(
    "Client::msg_expect_empty() deals with Client::msg_expect() failure") {
  FailMsgExpect client;
  REQUIRE(client.msg_expect_empty(libndt::msg_test_start) == false);
}

class NonEmptyMessage : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_expect(uint8_t, std::string *s) noexcept override {
    *s = "asd asd asd";
    return true;
  }
};

TEST_CASE("Client::msg_expect_empty() deals with nonempty message") {
  NonEmptyMessage client;
  REQUIRE(client.msg_expect_empty(libndt::msg_test_start) == false);
}

// Client::msg_expect() tests
// --------------------------

TEST_CASE("Client::msg_expect() deals with Client::msg_read() failure") {
  FailMsgRead client;
  std::string s;
  REQUIRE(client.msg_expect(libndt::msg_test_start, &s) == false);
}

TEST_CASE("Client::msg_expect() deals with unexpected message") {
  NeitherResultsNorLogout client;
  std::string s;
  REQUIRE(client.msg_expect(libndt::msg_logout, &s) == false);
}

// Client::msg_read() tests
// ------------------------

class FailMsgReadLegacy : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_read_legacy(uint8_t *, std::string *) noexcept override {
    return false;
  }
};

TEST_CASE("Client::msg_read() deals with Client::msg_read_legacy() failure") {
  FailMsgReadLegacy client;
  uint8_t code = 0;
  std::string s;
  REQUIRE(client.msg_read(&code, &s) == false);
}

class ReadInvalidJson : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_read_legacy(uint8_t *, std::string *s) noexcept override {
    *s = "{{{";
    return true;
  }
};

TEST_CASE("Client::msg_read() deals with invalid JSON") {
  libndt::Settings settings;
  settings.proto = libndt::protocol::json;
  ReadInvalidJson client{settings};
  uint8_t code = 0;
  std::string s;
  REQUIRE(client.msg_read(&code, &s) == false);
}

class ReadIncompleteJson : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_read_legacy(uint8_t *, std::string *s) noexcept override {
    *s = "{}";
    return true;
  }
};

TEST_CASE("Client::msg_read() deals with incomplete JSON") {
  libndt::Settings settings;
  settings.proto = libndt::protocol::json;
  ReadIncompleteJson client{settings};
  uint8_t code = 0;
  std::string s;
  REQUIRE(client.msg_read(&code, &s) == false);
}

class OkayMsgReadLegacy : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool msg_read_legacy(uint8_t *, std::string *) noexcept override {
    return true;
  }
};

TEST_CASE("Client::msg_read() deals with unknown protocol") {
  libndt::Settings settings;
  // That is, more precisely, a valid but unimplemented proto
  settings.proto = libndt::protocol::websockets;
  OkayMsgReadLegacy client{settings};
  uint8_t code = 0;
  std::string s;
  REQUIRE(client.msg_read(&code, &s) == false);
}

// Client::msg_read_legacy() tests
// -------------------------------

TEST_CASE(
    "Client::msg_read_legacy() deals with Client::recv() failure when reading "
    "header") {
  FailNetxRecvn client;
  client.set_last_system_error(0);
  uint8_t code = 0;
  std::string s;
  REQUIRE(client.msg_read_legacy(&code, &s) == false);
}

class FailLargeNetxRecvn : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_recvn(libndt::Socket, void *p,
                         libndt::Size siz) noexcept override {
    if (siz == 3) {
      char *usablep = (char *)p;
      usablep[0] = libndt::msg_login;
      uint16_t len = htons(155);
      memcpy(&usablep[1], &len, 2);
      return libndt::Err::none;
    }
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::msg_read_legacy() deals with Client::recvn() failure when reading "
    "message") {
  FailLargeNetxRecvn client;
  client.set_last_system_error(0);
  uint8_t code = 0;
  std::string s;
  REQUIRE(client.msg_read_legacy(&code, &s) == false);
}

// Client::netx_maybesocks5h_dial() tests
// --------------------------------------

class FailNetxConnect : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *) noexcept override {
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::netx_dial() "
    "error when a socks5 port is specified") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  FailNetxConnect client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

class Maybesocks5hConnectFailFirstNetxSendn : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::netx_sendn() "
    "failure when sending auth_request") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailFirstNetxSendn client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err ::io_error);
}

class Maybesocks5hConnectFailFirstNetxRecvn : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  libndt::Err netx_recvn(libndt::Socket, void *,
                         libndt::Size) noexcept override {
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::netx_sendn() "
    "failure when receiving auth_response") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailFirstNetxRecvn client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

class Maybesocks5hConnectInvalidAuthResponseVersion : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    assert(size == 2);
    (void)size;
    ((char *)buf)[0] = 4;  // unexpected
    ((char *)buf)[1] = 0;
    return libndt::Err::none;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with invalid version "
    "number in the auth_response") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInvalidAuthResponseVersion client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::socks5h);
}

class Maybesocks5hConnectInvalidAuthResponseMethod : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    assert(size == 2);
    (void)size;
    ((char *)buf)[0] = 5;
    ((char *)buf)[1] = 1;
    return libndt::Err::none;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with invalid method "
    "number in the auth_response") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInvalidAuthResponseMethod client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::socks5h);
}

class Maybesocks5hConnectInitialHandshakeOkay : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    assert(size == 2);
    (void)size;
    ((char *)buf)[0] = 5;
    ((char *)buf)[1] = 0;
    return libndt::Err::none;
  }
};

TEST_CASE("Client::netx_maybesocks5h_dial() deals with too long hostname") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInitialHandshakeOkay client{settings};
  libndt::Socket sock = -1;
  std::string hostname;
  for (size_t i = 0; i < 300; ++i) {
    hostname += "A";
  }
  REQUIRE(client.netx_maybesocks5h_dial(hostname, "80", &sock) ==
          libndt::Err::invalid_argument);
}

TEST_CASE("Client::netx_maybesocks5h_dial() deals with invalid port") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInitialHandshakeOkay client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "xx", &sock) ==
          libndt::Err::invalid_argument);
}

class Maybesocks5hConnectFailSecondNetxSendn : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size size) noexcept override {
    return size == 3 ? libndt::Err::none : libndt::Err::io_error;
  }
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    assert(size == 2);
    (void)size;
    ((char *)buf)[0] = 5;
    ((char *)buf)[1] = 0;
    return libndt::Err::none;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::netx_sendn() "
    "error while sending connect_request") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailSecondNetxSendn client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

class Maybesocks5hConnectFailSecondNetxRecvn : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return libndt::Err::none;
    }
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error while receiving connect_response_hdr") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailSecondNetxRecvn client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

class Maybesocks5hConnectInvalidSecondVersion : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return libndt::Err::none;
    }
    if (size == 4) {
      ((char *)buf)[0] = 4;  // unexpected
      ((char *)buf)[1] = 0;
      return libndt::Err::none;
    }
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with receiving "
    "invalid version number in second Client::recvn()") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInvalidSecondVersion client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::socks5h);
}

class Maybesocks5hConnectErrorResult : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return libndt::Err::none;
    }
    if (size == 4) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 1;  // error occurred
      return libndt::Err::none;
    }
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with receiving "
    "an error code in second Client::recvn()") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectErrorResult client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

class Maybesocks5hConnectInvalidReserved : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return libndt::Err::none;
    }
    if (size == 4) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      ((char *)buf)[2] = 1;  // should instead be zero
      return libndt::Err::none;
    }
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with receiving "
    "an invalid reserved field in second Client::recvn()") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInvalidReserved client{settings};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::socks5h);
}

class Maybesocks5hConnectFailAddressNetxRecvn : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  uint8_t type = 0;
  bool seen = false;
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return libndt::Err::none;
    }
    if (size == 4 && !seen) {
      seen = true;  // use flag because IPv4 is also 4 bytes
      assert(type != 0);
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      ((char *)buf)[2] = 0;
      ((char *)buf)[3] = type;
      return libndt::Err::none;
    }
    // the subsequent recvn() will fail
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when reading a IPv4") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailAddressNetxRecvn client{settings};
  client.type = 1;
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when reading a IPv6") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailAddressNetxRecvn client{settings};
  client.type = 4;
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when reading a invalid address type") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailAddressNetxRecvn client{settings};
  client.type = 7;
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::socks5h);
}

class Maybesocks5hConnectWithArray : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_dial(const std::string &, const std::string &,
                        libndt::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return libndt::Err::none;
  }
  libndt::Err netx_sendn(libndt::Socket, const void *,
                         libndt::Size) noexcept override {
    return libndt::Err::none;
  }
  std::deque<std::string> array;
  libndt::Err netx_recvn(libndt::Socket, void *buf,
                         libndt::Size size) noexcept override {
    if (!array.empty() && size == array[0].size()) {
      for (size_t idx = 0; idx < array[0].size(); ++idx) {
        ((char *)buf)[idx] = array[0][idx];
      }
      array.pop_front();
      return libndt::Err::none;
    }
    return libndt::Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when failing to read domain length") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\3", 4},
  };
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when failing to read domain") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\3", 4},
      std::string{"\7", 1},
  };
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when failing to read port") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\3", 4},
      std::string{"\7", 1},
      std::string{"123.org", 7},
  };
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::io_error);
}

TEST_CASE("Client::netx_maybesocks5h_dial() works with IPv4 (mocked)") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\1", 4},
      std::string{"\0\0\0\0", 4},
      std::string{"\0\0", 2},
  };
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::none);
}

TEST_CASE("Client::netx_maybesocks5h_dial() works with IPv6 (mocked)") {
  libndt::Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\4", 4},
      std::string{"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16},
      std::string{"\0\0", 2},
  };
  libndt::Socket sock = -1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          libndt::Err::none);
}

// Client::netx_map_errno() tests
// ------------------------------

#ifdef _WIN32
#define E(name) WSAE##name
#else
#define E(name) E##name
#endif

TEST_CASE("Client::netx_map_errno() correctly maps all errors") {
  using namespace libndt;
#ifdef NDEBUG  // There is an assertion that would fail in DEBUG mode
  REQUIRE(Client::netx_map_errno(0) == Err::io_error);
#endif
#ifndef _WIN32
  REQUIRE(Client::netx_map_errno(E(PIPE)) == Err::broken_pipe);
#endif
  REQUIRE(Client::netx_map_errno(E(CONNABORTED)) == Err::connection_aborted);
  REQUIRE(Client::netx_map_errno(E(CONNREFUSED)) == Err::connection_refused);
  REQUIRE(Client::netx_map_errno(E(CONNRESET)) == Err::connection_reset);
  REQUIRE(Client::netx_map_errno(E(HOSTUNREACH)) == Err::host_unreachable);
  REQUIRE(Client::netx_map_errno(E(INTR)) == Err::interrupted);
  REQUIRE(Client::netx_map_errno(E(INVAL)) == Err::invalid_argument);
#ifndef _WIN32
  REQUIRE(Client::netx_map_errno(E(IO)) == Err::io_error);
#endif
  REQUIRE(Client::netx_map_errno(E(NETDOWN)) == Err::network_down);
  REQUIRE(Client::netx_map_errno(E(NETRESET)) == Err::network_reset);
  REQUIRE(Client::netx_map_errno(E(NETUNREACH)) == Err::network_unreachable);
  REQUIRE(Client::netx_map_errno(E(INPROGRESS)) == Err::operation_in_progress);
  REQUIRE(Client::netx_map_errno(E(WOULDBLOCK)) == Err::operation_would_block);
  REQUIRE(Client::netx_map_errno(E(TIMEDOUT)) == Err::timed_out);
#if !defined _WIN32 && EAGAIN != EWOULDBLOCK
  REQUIRE(Client::netx_map_errno(E(AGAIN)) == Err::operation_would_block);
#endif
}

// Client::netx_map_eai() tests
// ----------------------------

TEST_CASE("Client::netx_map_eai() correctly maps all errors") {
  using namespace libndt;
  Client client;
  REQUIRE(client.netx_map_eai(EAI_AGAIN) == Err::ai_again);
  REQUIRE(client.netx_map_eai(EAI_FAIL) == Err::ai_fail);
  REQUIRE(client.netx_map_eai(EAI_NONAME) == Err::ai_noname);
#ifdef EAI_SYSTEM
  {
    client.set_last_system_error(E(WOULDBLOCK));
    REQUIRE(client.netx_map_eai(EAI_SYSTEM) == Err::operation_would_block);
    client.set_last_system_error(0);
  }
#endif
}

#undef E  // Tidy

// Client::netx_dial() tests
// -------------------------

TEST_CASE("Client::netx_dial() requires initial socket to be -1") {
  libndt::Client client;
  libndt::Socket sock = 21;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) ==
          libndt::Err::invalid_argument);
}

class FailNetxResolve : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_resolve(const std::string &,
                           std::vector<std::string> *) noexcept override {
    return libndt::Err::ai_again;
  }
};

TEST_CASE("Client::netx_dial() deals with Client::netx_resolve() failure") {
  FailNetxResolve client;
  libndt::Socket sock = -1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == libndt::Err::ai_again);
}

class FailGetaddrinfoInNetxConnect : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Err netx_resolve(const std::string &str,
                           std::vector<std::string> *addrs) noexcept override {
    REQUIRE(str == "1.2.3.4");  // make sure it did not change
    addrs->push_back(str);
    return libndt::Err::none;
  }
  int getaddrinfo(const char *, const char *, const addrinfo *,
                  addrinfo **) noexcept override {
    return EAI_AGAIN;
  }
};

TEST_CASE("Client::netx_dial() deals with Client::getaddrinfo() failure") {
  FailGetaddrinfoInNetxConnect client;
  libndt::Socket sock = -1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == libndt::Err::ai_again);
}

class FailSocket : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Socket socket(int, int, int) noexcept override {
    set_last_system_error(OS_EINVAL);
    return -1;
  }
};

TEST_CASE("Client::netx_dial() deals with Client::socket() failure") {
  FailSocket client;
  libndt::Socket sock = -1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == libndt::Err::io_error);
}

class FailSocketConnect : public libndt::Client {
 public:
  using libndt::Client::Client;
  int connect(  //
      libndt::Socket, const sockaddr *, libndt::SockLen) noexcept override {
    set_last_system_error(OS_EINVAL);
    return -1;
  }
};

TEST_CASE("Client::netx_dial() deals with Client::connect() failure") {
  FailSocketConnect client{};
  libndt::Socket sock = -1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == libndt::Err::io_error);
}

// Client::netx_recv() tests
// -------------------------

TEST_CASE("Client::netx_recv() deals with zero recv correctly") {
  libndt::Client client;
  libndt::Size n = 0;
  REQUIRE(client.netx_recv(0, nullptr, 0, &n) == libndt::Err::invalid_argument);
}

// Client::netx_recvn() tests
// --------------------------

#ifdef _WIN32
#define OS_SSIZE_MAX INT_MAX
#else
#define OS_SSIZE_MAX SSIZE_MAX
#endif

TEST_CASE("Client::netx_recvn() deals with too-large buffer") {
  libndt::Client client;
  REQUIRE(client.netx_recvn(0, nullptr, (unsigned long long)OS_SSIZE_MAX + 1) ==
          libndt::Err::invalid_argument);
}

class FailRecv : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Ssize recv(libndt::Socket, void *, libndt::Size) noexcept override {
    set_last_system_error(OS_EWOULDBLOCK);
    return -1;
  }
};

TEST_CASE("Client::netx_recvn() deals with Client::recv() failure") {
  char buf[1024];
  FailRecv client;
  REQUIRE(client.netx_recvn(0, buf, sizeof(buf)) ==
          libndt::Err::operation_would_block);
}

class RecvEof : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Ssize recv(libndt::Socket, void *, libndt::Size) noexcept override {
    return 0;
  }
};

TEST_CASE("Client::netx_recvn() deals with Client::recv() EOF") {
  char buf[1024];
  RecvEof client;
  REQUIRE(client.netx_recvn(0, buf, sizeof(buf)) == libndt::Err::eof);
}

class PartialRecvAndThenError : public libndt::Client {
 public:
  using libndt::Client::Client;
  static constexpr libndt::Size amount = 11;
  static constexpr libndt::Size good_amount = 3;
  libndt::Ssize recv(libndt::Socket, void *buf,
                     libndt::Size size) noexcept override {
    if (size == amount) {
      assert(size >= good_amount);
      for (size_t i = 0; i < good_amount; ++i) {
        ((char *)buf)[i] = 'A';
      }
      return good_amount;
    }
    set_last_system_error(OS_EWOULDBLOCK);
    return -1;
  }
};

TEST_CASE(
    "Client::netx_recvn() deals with partial Client::recv() and then error") {
  char buf[PartialRecvAndThenError::amount] = {};
  PartialRecvAndThenError client;
  REQUIRE(client.netx_recvn(0, buf, sizeof(buf)) ==
          libndt::Err::operation_would_block);
  // Just to make sure the code path was entered correctly. We still think that
  // the right behaviour here is to return -1, not a short read.
  for (size_t i = 0; i < sizeof(buf); ++i) {
    if (i < PartialRecvAndThenError::good_amount) {
      REQUIRE(buf[i] == 'A');
    } else {
      REQUIRE(buf[i] == '\0');
    }
  }
}

class PartialRecvAndThenEof : public libndt::Client {
 public:
  using libndt::Client::Client;
  static constexpr libndt::Size amount = 7;
  static constexpr libndt::Size good_amount = 5;
  libndt::Ssize recv(libndt::Socket, void *buf,
                     libndt::Size size) noexcept override {
    if (size == amount) {
      assert(size >= good_amount);
      for (size_t i = 0; i < good_amount; ++i) {
        ((char *)buf)[i] = 'B';
      }
      return good_amount;
    }
    return 0;
  }
};

TEST_CASE(
    "Client::netx_recvn() deals with partial Client::recv() and then EOF") {
  char buf[PartialRecvAndThenEof::amount] = {};
  PartialRecvAndThenEof client;
  REQUIRE(client.netx_recvn(0, buf, sizeof(buf)) == libndt::Err::eof);
  // Just to make sure the code path was entered correctly. We still think that
  // the right behaviour here is to return zero, not a short read.
  for (size_t i = 0; i < sizeof(buf); ++i) {
    if (i < PartialRecvAndThenEof::good_amount) {
      REQUIRE(buf[i] == 'B');
    } else {
      REQUIRE(buf[i] == '\0');
    }
  }
}

// Client::netx_send() tests
// -------------------------

TEST_CASE("Client::netx_send() deals with zero send correctly") {
  libndt::Client client;
  libndt::Size n = 0;
  REQUIRE(client.netx_send(0, nullptr, 0, &n) == libndt::Err::invalid_argument);
}

// Client::netx_sendn() tests
// --------------------------

TEST_CASE("Client::netx_sendn() deals with too-large buffer") {
  libndt::Client client;
  REQUIRE(client.netx_sendn(0, nullptr, (unsigned long long)OS_SSIZE_MAX + 1) ==
          libndt::Err::invalid_argument);
}

class FailSend : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Ssize send(libndt::Socket, const void *,
                     libndt::Size) noexcept override {
    set_last_system_error(OS_EWOULDBLOCK);
    return -1;
  }
};

TEST_CASE("Client::netx_sendn() deals with Client::send() failure") {
  char buf[1024];
  FailSend client;
  REQUIRE(client.netx_sendn(0, buf, sizeof(buf)) ==
          libndt::Err::operation_would_block);
}

// As much as EOF should not appear on a socket when sending, be ready.
class SendEof : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Ssize send(libndt::Socket, const void *,
                     libndt::Size) noexcept override {
    return 0;
  }
};

TEST_CASE("Client::netx_sendn() deals with Client::send() EOF") {
  char buf[1024];
  SendEof client;
  REQUIRE(client.netx_sendn(0, buf, sizeof(buf)) == libndt::Err::io_error);
}

class PartialSendAndThenError : public libndt::Client {
 public:
  using libndt::Client::Client;
  static constexpr libndt::Size amount = 11;
  static constexpr libndt::Size good_amount = 3;
  libndt::Size successful = 0;
  libndt::Ssize send(libndt::Socket, const void *,
                     libndt::Size size) noexcept override {
    if (size == amount) {
      assert(size >= good_amount);
      successful += good_amount;
      return good_amount;
    }
    set_last_system_error(OS_EWOULDBLOCK);
    return -1;
  }
};

TEST_CASE("Client::send() deals with partial Client::send() and then error") {
  char buf[PartialSendAndThenError::amount] = {};
  PartialSendAndThenError client;
  REQUIRE(client.netx_sendn(0, buf, sizeof(buf)) ==
          libndt::Err::operation_would_block);
  // Just to make sure the code path was entered correctly. We still think that
  // the right behaviour here is to return -1, not a short write.
  //
  // Usage of `exp` is required to make clang compile (unclear to me why).
  auto exp = PartialSendAndThenError::good_amount;
  REQUIRE(client.successful == exp);
}

// See above comment regarding likelihood of send returning EOF (i.e. zero)
class PartialSendAndThenEof : public libndt::Client {
 public:
  using libndt::Client::Client;
  static constexpr libndt::Size amount = 7;
  static constexpr libndt::Size good_amount = 5;
  libndt::Size successful = 0;
  libndt::Ssize send(libndt::Socket, const void *,
                     libndt::Size size) noexcept override {
    if (size == amount) {
      assert(size >= good_amount);
      successful += good_amount;
      return good_amount;
    }
    return 0;
  }
};

TEST_CASE(
    "Client::netx_sendn() deals with partial Client::send() and then EOF") {
  char buf[PartialSendAndThenEof::amount] = {};
  PartialSendAndThenEof client;
  REQUIRE(client.netx_sendn(0, buf, sizeof(buf)) == libndt::Err::io_error);
  // Just to make sure the code path was entered correctly. We still think that
  // the right behaviour here is to return zero, not a short write.
  //
  // Usage of `exp` is required to make clang compile (unclear to me why).
  auto exp = PartialSendAndThenEof::good_amount;
  REQUIRE(client.successful == exp);
}

// Client::netx_resolve() tests
// ----------------------------

class FailGetaddrinfo : public libndt::Client {
 public:
  using libndt::Client::Client;
  int getaddrinfo(const char *, const char *, const addrinfo *,
                  addrinfo **) noexcept override {
    return EAI_AGAIN;
  }
};

TEST_CASE("Client::netx_resolve() deals with Client::getaddrinfo() failure") {
  FailGetaddrinfo client;
  std::vector<std::string> addrs;
  REQUIRE(client.netx_resolve("x.org", &addrs) == libndt::Err::ai_again);
}

class FailGetnameinfo : public libndt::Client {
 public:
  using libndt::Client::Client;
  int getnameinfo(const sockaddr *, libndt::SockLen, char *, libndt::SockLen,
                  char *, libndt::SockLen, int) noexcept override {
    return EAI_AGAIN;
  }
};

TEST_CASE("Client::netx_resolve() deals with Client::getnameinfo() failure") {
  FailGetnameinfo client;
  std::vector<std::string> addrs;
  REQUIRE(client.netx_resolve("x.org", &addrs) == libndt::Err::ai_generic);
}

// Client::query_mlabns_curl() tests
// ---------------------------------

#ifdef HAVE_CURL
TEST_CASE("Client::query_mlabns_curl() deals with Curl{} failure") {
  libndt::Client client;
  // Note: passing `nullptr` should cause Curl{} to fail and hence we can
  // also easily check for cases where Curl{} fails.
  REQUIRE(client.query_mlabns_curl("", 3, nullptr) == false);
}
#endif

// Client::get_last_system_error() tests
// -------------------------------------

#ifdef _WIN32
#define OS_EINVAL WSAEINVAL
#else
#define OS_EINVAL EINVAL
#endif

TEST_CASE("Client::get_last_system_error() works as expected") {
  libndt::Client client;
  client.set_last_system_error(OS_EINVAL);
  REQUIRE(client.get_last_system_error() == OS_EINVAL);
  client.set_last_system_error(0);  // clear
}

// Client::recv() tests
// --------------------

TEST_CASE("Client::recv() deals with too-large buffer") {
  libndt::Client client;
  REQUIRE(client.recv(0, nullptr, (unsigned long long)OS_SSIZE_MAX + 1) == -1);
}

// Client::send() tests
// --------------------

TEST_CASE("Client::send() deals with too-large buffer") {
  libndt::Client client;
  REQUIRE(client.send(0, nullptr, (unsigned long long)OS_SSIZE_MAX + 1) == -1);
}
