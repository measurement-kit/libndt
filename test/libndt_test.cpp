// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "third_party/github.com/nlohmann/json/json.hpp"

#include "libndt/libndt.hpp"

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <errno.h>
#ifndef _WIN32
#include <fcntl.h>
#endif
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <deque>
#include <vector>

#define CATCH_CONFIG_MAIN
#include "third_party/github.com/catchorg/Catch2/catch.hpp"

#ifdef _WIN32
#define OS_EINVAL WSAEINVAL
#define OS_EWOULDBLOCK WSAEWOULDBLOCK
#else
#define OS_EINVAL EINVAL
#define OS_EWOULDBLOCK EWOULDBLOCK
#endif

using namespace measurement_kit::libndt;

// Unit tests
// ==========
//
// Speaking of coverage, if specific code is already tested by running the
// example client, we don't need to write also a test for it here.

// Client::run() tests
// -------------------

class FailQueryMlabns : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return false;
  }
};

TEST_CASE("Client::run() deals with Client::query_mlabns() failure") {
  FailQueryMlabns client;
  REQUIRE(client.run() == false);
}

class FailConnect : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return true;
  }
  bool connect() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::connect() failure") {
  FailConnect client;
  REQUIRE(client.run() == false);
}

class FailSendLogin : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return true;
  }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::send_login() failure") {
  FailSendLogin client;
  REQUIRE(client.run() == false);
}

class FailRecvKickoff : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return true;
  }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return true; }
  bool recv_kickoff() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::recv_kickoff() failure") {
  FailRecvKickoff client;
  REQUIRE(client.run() == false);
}

class FailWaitInQueue : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return true;
  }
  bool connect() noexcept override { return true; }
  bool send_login() noexcept override { return true; }
  bool recv_kickoff() noexcept override { return true; }
  bool wait_in_queue() noexcept override { return false; }
};

TEST_CASE("Client::run() deals with Client::wait_in_queue() failure") {
  FailWaitInQueue client;
  REQUIRE(client.run() == false);
}

class FailRecvVersion : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return true;
  }
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

class FailRecvTestsId : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return true;
  }
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

class FailRunTests : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return true;
  }
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

class FailRecvResultsAndLogout : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return true;
  }
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

class FailWaitClose : public Client {
 public:
  using Client::Client;
  bool query_mlabns(std::vector<std::string> *) noexcept override {
    return true;
  }
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
  Client client;
  client.on_warning("calling on_warning() to increase coverage");
}

// Client::query_mlabns() tests
// ----------------------------

class FailQueryMlabnsCurl : public Client {
 public:
  using Client::Client;
  bool query_mlabns_curl(const std::string &, long,
                         std::string *) noexcept override {
    return false;
  }
};

TEST_CASE("Client::query_mlabns() does nothing when we already know hostname") {
  Settings settings;
  settings.hostname = "neubot.mlab.mlab1.trn01.measurement-lab.org";
  FailQueryMlabnsCurl client{settings};
  std::vector<std::string> v;
  REQUIRE(client.query_mlabns(&v) == true);
}

TEST_CASE(
    "Client::query_mlabns() deals with Client::query_mlabns_curl() failure") {
  FailQueryMlabnsCurl client;
  std::vector<std::string> v;
  REQUIRE(client.query_mlabns(&v) == false);
}

class EmptyMlabnsJson : public Client {
 public:
  using Client::Client;
  bool query_mlabns_curl(const std::string &, long,
                         std::string *body) noexcept override {
    *body = "";
    return true;
  }
};

TEST_CASE("Client::query_mlabns() deals with empty JSON") {
  EmptyMlabnsJson client;
  std::vector<std::string> v;
  REQUIRE(client.query_mlabns(&v) == false);
}

class InvalidMlabnsJson : public Client {
 public:
  using Client::Client;
  bool query_mlabns_curl(const std::string &, long,
                         std::string *body) noexcept override {
    *body = "{{{{";
    return true;
  }
};

TEST_CASE("Client::query_mlabns() deals with invalid JSON") {
  InvalidMlabnsJson client;
  std::vector<std::string> v;
  REQUIRE(client.query_mlabns(&v) == false);
}

class IncompleteMlabnsJson : public Client {
 public:
  using Client::Client;
  bool query_mlabns_curl(const std::string &, long,
                         std::string *body) noexcept override {
    *body = "{}";
    return true;
  }
};

TEST_CASE("Client::query_mlabns() deals with incomplete JSON") {
  IncompleteMlabnsJson client;
  std::vector<std::string> v;
  REQUIRE(client.query_mlabns(&v) == false);
}

// Client::recv_kickoff() tests
// ----------------------------

class FailNetxRecvn : public Client {
 public:
  using Client::Client;
  Err netx_recvn(internal::Socket, void *, internal::Size) const noexcept override {
    return Err::io_error;
  }
};

TEST_CASE("Client::recv_kickoff() deals with Client::recvn() failure") {
  FailNetxRecvn client;
  REQUIRE(client.recv_kickoff() == false);
}

class NetxRecvnEof : public Client {
 public:
  using Client::Client;
  Err netx_recvn(internal::Socket, void *, internal::Size) const noexcept override {
    return Err::eof;
  }
};

TEST_CASE("Client::recv_kickoff() deals with Client::recvn() EOF") {
  NetxRecvnEof client;
  REQUIRE(client.recv_kickoff() == false);
}

class NetxRecvnInvalidKickoff : public Client {
 public:
  using Client::Client;
  Err netx_recvn(  //
      internal::Socket, void *buf, internal::Size siz) const noexcept override {
    REQUIRE(buf != nullptr);
    REQUIRE(siz >= 1);
    for (internal::Size i = 0; i < siz; ++i) {
      ((char *)buf)[i] = 'x';
    }
    return Err::none;
  }
};

TEST_CASE("Client::recv_kickoff() deals with invalid kickoff") {
  NetxRecvnInvalidKickoff client;
  REQUIRE(client.recv_kickoff() == false);
}

// Client::wait_in_queue() tests
// ----------------------------

class FailMsgExpect : public Client {
 public:
  using Client::Client;
  bool msg_expect(MsgType, std::string *) noexcept override {
    return false;
  }
};

TEST_CASE("Client::wait_in_queue() deals with Client::msg_expect() failure") {
  FailMsgExpect client;
  REQUIRE(client.wait_in_queue() == false);
}

class ServerBusy : public Client {
 public:
  using Client::Client;
  bool msg_expect(MsgType, std::string *val) noexcept override {
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

class InvalidTestsIds : public Client {
 public:
  using Client::Client;
  bool msg_expect(MsgType, std::string *val) noexcept override {
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

class RunTestsMock : public Client {
 public:
  using Client::Client;
  bool msg_expect(MsgType, std::string *val) noexcept override {
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
  client.tests_ids = std::to_string((uint64_t)nettest_flag_upload);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

TEST_CASE("Client::run_tests() deals with Client::run_meta() failure") {
  RunTestsMock client;
  client.tests_ids = std::to_string((uint64_t)nettest_flag_meta);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

TEST_CASE("Client::run_tests() deals with Client::run_download() failure") {
  RunTestsMock client;
  client.tests_ids = std::to_string((uint64_t)nettest_flag_download);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

TEST_CASE("Client::run_tests() deals with unexpected test-id") {
  RunTestsMock client;
  client.tests_ids = std::to_string((uint64_t)nettest_flag_status);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

// Client::recv_results_and_logout() tests
// ---------------------------------------

class FailMsgRead : public Client {
 public:
  using Client::Client;
  bool msg_read(MsgType *, std::string *) noexcept override {
    return false;
  }
};

TEST_CASE(
    "Client::recv_results_and_logout() deals with Client::msg_read() failure") {
  FailMsgRead client;
  REQUIRE(client.recv_results_and_logout() == false);
}

class NeitherResultsNorLogout : public Client {
 public:
  using Client::Client;
  bool msg_read(MsgType *code, std::string *msg) noexcept override {
    *code = msg_comm_failure;
    *msg = "";
    return true;
  }
};

TEST_CASE("Client::recv_results_and_logout() deals with unexpected message") {
  NeitherResultsNorLogout client;
  REQUIRE(client.recv_results_and_logout() == false);
}

class InvalidResults : public Client {
 public:
  using Client::Client;
  bool msg_read(MsgType *code, std::string *msg) noexcept override {
    *code = msg_results;
    *msg = "antani-antani";
    return true;
  }
};

TEST_CASE("Client::recv_results_and_logout() deals with invalid results") {
  InvalidResults client;
  REQUIRE(client.recv_results_and_logout() == false);
}

class TooManyResults : public Client {
 public:
  using Client::Client;
  bool msg_read(MsgType *code, std::string *msg) noexcept override {
    *code = msg_results;
    *msg = "antani:antani";
    return true;
  }
};

TEST_CASE("Client::recv_results_and_logout() deals with too many results") {
  TooManyResults client;
  REQUIRE(client.recv_results_and_logout() == false);
}

// Client::run_download() tests
// ----------------------------

class FailMsgExpectTestPrepare : public Client {
 public:
  using Client::Client;
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

class FailNetxMaybesocks5hConnect : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *) noexcept override {
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::run_download() deals with Client::netx_maybesocks5h_dial() "
    "failure") {
  FailNetxMaybesocks5hConnect client;
  REQUIRE(client.run_download() == false);
}

class FailMsgExpectEmpty : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return false; }
};

TEST_CASE(
    "Client::run_download() deals with Client::msg_expect_empty() failure") {
  FailMsgExpectEmpty client;
  REQUIRE(client.run_download() == false);
}

class FailNetxSelectDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::io_error;
  }
};

TEST_CASE("Client::run_download() deals with Client::netx_poll() failure") {
  FailNetxSelectDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class FailRecvDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_recv_nonblocking(internal::Socket, void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::invalid_argument;
  }
};

TEST_CASE("Client::run_download() deals with Client::recv() failure") {
  FailRecvDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class RecvEofDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_recv_nonblocking(internal::Socket, void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::eof;
  }
};

TEST_CASE("Client::run_download() honours max_runtime") {
  Settings settings;
  settings.max_runtime = Timeout{0};
  RecvEofDuringDownload client{settings};
  REQUIRE(client.run_download() == false);
}

class FailMsgReadLegacyDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_recv_nonblocking(internal::Socket, void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::eof;
  }
  bool msg_read_legacy(MsgType *, std::string *) noexcept override {
    return false;
  }
};

TEST_CASE(
    "Client::run_download() deals with Client::msg_read_legacy_failure()") {
  FailMsgReadLegacyDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class RecvNonTestMsgDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_recv_nonblocking(internal::Socket, void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::eof;
  }
  bool msg_read_legacy(MsgType *code, std::string *) noexcept override {
    *code = msg_logout;
    return true;
  }
};

TEST_CASE("Client::run_download() deals with non-msg_test_msg receipt") {
  RecvNonTestMsgDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class FailMsgWriteDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_recv_nonblocking(internal::Socket, void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::eof;
  }
  bool msg_read_legacy(MsgType *code, std::string *) noexcept override {
    *code = msg_test_msg;
    return true;
  }
  bool msg_write(MsgType, std::string &&) noexcept override {
    return false;
  }
};

TEST_CASE("Client::run_download() deals with Client::msg_write() failure") {
  FailMsgWriteDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class FailMsgReadDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_recv_nonblocking(internal::Socket, void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::eof;
  }
  bool msg_read_legacy(MsgType *code, std::string *) noexcept override {
    *code = msg_test_msg;
    return true;
  }
  bool msg_write(MsgType, std::string &&) noexcept override {
    return true;
  }
  bool msg_read(MsgType *, std::string *) noexcept override {
    return false;
  }
};

TEST_CASE("Client::run_download() deals with Client::msg_read() failure") {
  FailMsgReadDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class RecvNonTestOrLogoutMsgDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_recv_nonblocking(internal::Socket, void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::eof;
  }
  bool msg_read_legacy(MsgType *code, std::string *) noexcept override {
    *code = msg_test_msg;
    return true;
  }
  bool msg_write(MsgType, std::string &&) noexcept override {
    return true;
  }
  bool msg_read(MsgType *code, std::string *) noexcept override {
    *code = msg_login;
    return true;
  }
};

TEST_CASE("Client::run_download() deals with non-logout-or-test msg") {
  RecvNonTestOrLogoutMsgDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class FailEmitResultDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_recv_nonblocking(internal::Socket, void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::eof;
  }
  bool msg_read_legacy(MsgType *code, std::string *) noexcept override {
    *code = msg_test_msg;
    return true;
  }
  bool msg_write(MsgType, std::string &&) noexcept override {
    return true;
  }
  bool msg_read(MsgType *code, std::string *s) noexcept override {
    *code = msg_test_msg;
    *s = "antani-antani";  // Causes emit_result() to fail
    return true;
  }
};

TEST_CASE("Client::run_download() deals with emit_result() failure") {
  FailEmitResultDuringDownload client;
  REQUIRE(client.run_download() == false);
}

class TooManyTestMsgsDuringDownload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_recv_nonblocking(internal::Socket, void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::eof;
  }
  bool msg_read_legacy(MsgType *code, std::string *) noexcept override {
    *code = msg_test_msg;
    return true;
  }
  bool msg_write(MsgType, std::string &&) noexcept override {
    return true;
  }
  bool msg_read(MsgType *code, std::string *s) noexcept override {
    *code = msg_test_msg;
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

class FailFirstMsgExpectEmpty : public Client {
 public:
  using Client::Client;
  bool msg_expect_empty(MsgType) noexcept override { return false; }
};

TEST_CASE(
    "Client::run_meta() deals with first Client::msg_expect_empty() failure") {
  FailFirstMsgExpectEmpty client;
  REQUIRE(client.run_meta() == false);
}

class FailSecondMsgExpectEmpty : public Client {
 public:
  using Client::Client;
  bool msg_expect_empty(MsgType code) noexcept override {
    return code == msg_test_prepare;
  }
};

TEST_CASE(
    "Client::run_meta() deals with second Client::msg_expect_empty() failure") {
  FailSecondMsgExpectEmpty client;
  REQUIRE(client.run_meta() == false);
}

class FailMsgWriteDuringMeta : public Client {
 public:
  using Client::Client;
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  bool msg_write(MsgType, std::string &&) noexcept override {
    return false;
  }
};

TEST_CASE("Client::run_meta() deals with Client::msg_write() failure") {
  FailMsgWriteDuringMeta client;
  REQUIRE(client.run_meta() == false);
}

class FailFinalMsgWriteDuringMeta : public Client {
 public:
  using Client::Client;
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  bool msg_write(MsgType, std::string &&s) noexcept override {
    return s != "";
  }
};

TEST_CASE("Client::run_meta() deals with final Client::msg_write() failure") {
  FailFinalMsgWriteDuringMeta client;
  REQUIRE(client.run_meta() == false);
}

class FailFinalMsgExpectEmptyDuringMeta : public Client {
 public:
  using Client::Client;
  bool msg_expect_empty(MsgType code) noexcept override {
    return code != msg_test_finalize;
  }
  bool msg_write(MsgType, std::string &&) noexcept override {
    return true;
  }
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

class TestPrepareMoreThanOneFlow : public Client {
 public:
  using Client::Client;
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

TEST_CASE("Client::run_upload() deals with Client::netx_poll() failure") {
  FailNetxSelectDuringDownload client;  // Works also for upload phase
  REQUIRE(client.run_upload() == false);
}

class FailSendDuringUpload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_send_nonblocking(internal::Socket, const void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::io_error;
  }
};

TEST_CASE("Client::run_upload() deals with Client::send() failure") {
  FailSendDuringUpload client;
  REQUIRE(client.run_upload() == false);
}

TEST_CASE("Client::run_upload() honours max_runtime") {
  Settings settings;
  settings.max_runtime = Timeout{0};
  FailSendDuringUpload client{settings};
  REQUIRE(client.run_upload() == false);
}

class FailMsgExpectDuringUpload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType) noexcept override { return true; }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_send_nonblocking(internal::Socket, const void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::io_error;
  }
  bool msg_expect(MsgType, std::string *) noexcept override {
    return false;
  }
};

TEST_CASE("Client::run_upload() deals with Client::msg_expect() failure") {
  FailMsgExpectDuringUpload client;
  REQUIRE(client.run_upload() == false);
}

class FailFinalMsgExpectEmptyDuringUpload : public Client {
 public:
  using Client::Client;
  bool msg_expect_test_prepare(std::string *, uint8_t *) noexcept override {
    return true;
  }
  Err netx_maybesocks5h_dial(const std::string &, const std::string &,
                                     internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  bool msg_expect_empty(MsgType code) noexcept override {
    return code != msg_test_finalize;
  }
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::none;
  }
  Err netx_send_nonblocking(internal::Socket, const void *, internal::Size,
                                    internal::Size *) const noexcept override {
    return Err::io_error;
  }
  bool msg_expect(MsgType, std::string *) noexcept override {
    return true;
  }
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
  Settings settings;
  settings.protocol_flags = (1 << 11); // nonexisting protocol
  Client client{settings};
  REQUIRE(client.msg_write_login(ndt_version_compat) == false);
}

class FailMsgWriteLegacy : public Client {
 public:
  using Client::Client;
  bool msg_write_legacy(MsgType, std::string &&) noexcept override {
    return false;
  }
};

TEST_CASE(
    "Client::msg_write_login() deals with Client::msg_write_legacy() failure") {
  FailMsgWriteLegacy client;
  REQUIRE(client.msg_write_login(ndt_version_compat) == false);
}

class ValidatingMsgWriteLegacy : public Client {
 public:
  using Client::Client;
  bool msg_write_legacy(MsgType,
                        std::string &&value) noexcept override {
    auto doc = nlohmann::json::parse(value);
    std::string tests_string = doc.at("tests");
    const char *errstr = nullptr;
    NettestFlags tests{
        (uint8_t)internal::Sys{}.Strtonum(tests_string.c_str(), 0, 256, &errstr)};
    REQUIRE(errstr == nullptr);
    REQUIRE((tests & nettest_flag_middlebox) ==
            NettestFlags{0});
    REQUIRE((tests & nettest_flag_simple_firewall) ==
            NettestFlags{0});
    REQUIRE((tests & nettest_flag_upload_ext) ==
            NettestFlags{0});
    return true;
  }
};

TEST_CASE("Client::msg_write_login() does not propagate unknown tests ids") {
  Settings settings;
  settings.protocol_flags = protocol_flag_json;
  settings.nettest_flags = NettestFlags{0xff};
  ValidatingMsgWriteLegacy client{settings};
  REQUIRE(client.msg_write_login(ndt_version_compat) == true);
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
  Settings settings;
  settings.protocol_flags = protocol_flag_json;
  Client client{settings};
  auto s = non_serializable();
  REQUIRE(client.msg_write_login(s) == false);
}

// Client::msg_write() tests
// -------------------------

TEST_CASE("Client::msg_write() deals with unserializable JSON") {
  Settings settings;
  settings.protocol_flags = protocol_flag_json;
  Client client{settings};
  auto s = non_serializable();
  REQUIRE(client.msg_write(msg_test_start, std::move(s)) == false);
}

TEST_CASE("Client::msg_write() deals with invalid protocol") {
  Settings settings;
  settings.protocol_flags = (1 << 11); // nonexisting protocol
  Client client{settings};
  REQUIRE(client.msg_write(msg_test_start, "foo") == false);
}

TEST_CASE("Client::msg_write() deals with Client::msg_write_legacy() failure") {
  FailMsgWriteLegacy client;
  REQUIRE(client.msg_write(msg_test_start, "foo") == false);
}

// Client::msg_write_legacy() tests
// --------------------------------

TEST_CASE("Client::msg_write_legacy() deals with too-big messages") {
  Client client;
  std::string m;
  m.resize(UINT16_MAX + 1);
  REQUIRE(client.msg_write_legacy(  //
              msg_test_start, std::move(m)) == false);
}

class FailNetxSendn : public Client {
 public:
  using Client::Client;
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::msg_write_legacy() deals with Client::netx_sendn() failure when "
    "sending header") {
  FailNetxSendn client;
  std::string m{"foo"};
  client.sys->SetLastError(0);
  REQUIRE(client.msg_write_legacy(  //
              msg_test_start, std::move(m)) == false);
}

class FailLargeNetxSendn : public Client {
 public:
  using Client::Client;
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size siz) const noexcept override {
    return siz == 3 ? Err::none : Err::io_error;
  }
};

TEST_CASE(
    "Client::msg_write_legacy() deals with Client::netx_sendn() failure when "
    "sending message") {
  FailLargeNetxSendn client;
  std::string m{"foobar"};
  client.sys->SetLastError(0);
  REQUIRE(client.msg_write_legacy(  //
              msg_test_start, std::move(m)) == false);
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

class TooShortVector : public Client {
 public:
  using Client::Client;
  bool msg_expect(MsgType, std::string *) noexcept override {
    return true;
  }
};

TEST_CASE("Client::msg_expect_test_prepare() deals with too-short vector") {
  TooShortVector client;
  std::string port;
  uint8_t nflows = 0;
  REQUIRE(client.msg_expect_test_prepare(&port, &nflows) == false);
}

class InvalidPortVector : public Client {
 public:
  using Client::Client;
  bool msg_expect(MsgType, std::string *s) noexcept override {
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

class InvalidNumFlowsVector : public Client {
 public:
  using Client::Client;
  bool msg_expect(MsgType, std::string *s) noexcept override {
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
  REQUIRE(client.msg_expect_empty(msg_test_start) == false);
}

class NonEmptyMessage : public Client {
 public:
  using Client::Client;
  bool msg_expect(MsgType, std::string *s) noexcept override {
    *s = "asd asd asd";
    return true;
  }
};

TEST_CASE("Client::msg_expect_empty() deals with nonempty message") {
  NonEmptyMessage client;
  REQUIRE(client.msg_expect_empty(msg_test_start) == false);
}

// Client::msg_expect() tests
// --------------------------

TEST_CASE("Client::msg_expect() deals with Client::msg_read() failure") {
  FailMsgRead client;
  std::string s;
  REQUIRE(client.msg_expect(msg_test_start, &s) == false);
}

TEST_CASE("Client::msg_expect() deals with unexpected message") {
  NeitherResultsNorLogout client;
  std::string s;
  REQUIRE(client.msg_expect(msg_logout, &s) == false);
}

// Client::msg_read() tests
// ------------------------

class FailMsgReadLegacy : public Client {
 public:
  using Client::Client;
  bool msg_read_legacy(MsgType *, std::string *) noexcept override {
    return false;
  }
};

TEST_CASE("Client::msg_read() deals with Client::msg_read_legacy() failure") {
  FailMsgReadLegacy client;
  MsgType code = MsgType{0};
  std::string s;
  REQUIRE(client.msg_read(&code, &s) == false);
}

class ReadInvalidJson : public Client {
 public:
  using Client::Client;
  bool msg_read_legacy(MsgType *, std::string *s) noexcept override {
    *s = "{{{";
    return true;
  }
};

TEST_CASE("Client::msg_read() deals with invalid JSON") {
  Settings settings;
  settings.protocol_flags = protocol_flag_json;
  ReadInvalidJson client{settings};
  MsgType code = MsgType{0};
  std::string s;
  REQUIRE(client.msg_read(&code, &s) == false);
}

class ReadIncompleteJson : public Client {
 public:
  using Client::Client;
  bool msg_read_legacy(MsgType *, std::string *s) noexcept override {
    *s = "{}";
    return true;
  }
};

TEST_CASE("Client::msg_read() deals with incomplete JSON") {
  Settings settings;
  settings.protocol_flags = protocol_flag_json;
  ReadIncompleteJson client{settings};
  MsgType code = MsgType{0};
  std::string s;
  REQUIRE(client.msg_read(&code, &s) == false);
}

class OkayMsgReadLegacy : public Client {
 public:
  using Client::Client;
  bool msg_read_legacy(MsgType *, std::string *) noexcept override {
    return true;
  }
};

// Client::msg_read_legacy() tests
// -------------------------------

TEST_CASE(
    "Client::msg_read_legacy() deals with Client::recv() failure when reading "
    "header") {
  FailNetxRecvn client;
  client.sys->SetLastError(0);
  MsgType code = MsgType{0};
  std::string s;
  REQUIRE(client.msg_read_legacy(&code, &s) == false);
}

class FailLargeNetxRecvn : public Client {
 public:
  using Client::Client;
  Err netx_recvn(internal::Socket, void *p,
                         internal::Size siz) const noexcept override {
    if (siz == 3) {
      char *usablep = (char *)p;
      usablep[0] = msg_login;
      uint16_t len = htons(155);
      memcpy(&usablep[1], &len, 2);
      return Err::none;
    }
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::msg_read_legacy() deals with Client::recvn() failure when reading "
    "message") {
  FailLargeNetxRecvn client;
  client.sys->SetLastError(0);
  MsgType code = MsgType{0};
  std::string s;
  REQUIRE(client.msg_read_legacy(&code, &s) == false);
}

// Client::netx_maybesocks5h_dial() tests
// --------------------------------------

class FailNetxConnect : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *) noexcept override {
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::netx_dial() "
    "error when a socks5 port is specified") {
  Settings settings;
  settings.socks5h_port = "9050";
  FailNetxConnect client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

class Maybesocks5hConnectFailFirstNetxSendn : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::netx_sendn() "
    "failure when sending auth_request") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailFirstNetxSendn client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err ::io_error);
}

class Maybesocks5hConnectFailFirstNetxRecvn : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  Err netx_recvn(internal::Socket, void *,
                         internal::Size) const noexcept override {
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::netx_sendn() "
    "failure when receiving auth_response") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailFirstNetxRecvn client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

class Maybesocks5hConnectInvalidAuthResponseVersion : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    assert(size == 2);
    (void)size;
    ((char *)buf)[0] = 4;  // unexpected
    ((char *)buf)[1] = 0;
    return Err::none;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with invalid version "
    "number in the auth_response") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInvalidAuthResponseVersion client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::socks5h);
}

class Maybesocks5hConnectInvalidAuthResponseMethod : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    assert(size == 2);
    (void)size;
    ((char *)buf)[0] = 5;
    ((char *)buf)[1] = 1;
    return Err::none;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with invalid method "
    "number in the auth_response") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInvalidAuthResponseMethod client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::socks5h);
}

class Maybesocks5hConnectInitialHandshakeOkay : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    assert(size == 2);
    (void)size;
    ((char *)buf)[0] = 5;
    ((char *)buf)[1] = 0;
    return Err::none;
  }
};

TEST_CASE("Client::netx_maybesocks5h_dial() deals with too long hostname") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInitialHandshakeOkay client{settings};
	internal::Socket sock = (internal::Socket)-1;
  std::string hostname;
  for (size_t i = 0; i < 300; ++i) {
    hostname += "A";
  }
  REQUIRE(client.netx_maybesocks5h_dial(hostname, "80", &sock) ==
          Err::invalid_argument);
}

TEST_CASE("Client::netx_maybesocks5h_dial() deals with invalid port") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInitialHandshakeOkay client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "xx", &sock) ==
          Err::invalid_argument);
}

class Maybesocks5hConnectFailSecondNetxSendn : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size size) const noexcept override {
    return size == 3 ? Err::none : Err::io_error;
  }
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    assert(size == 2);
    (void)size;
    ((char *)buf)[0] = 5;
    ((char *)buf)[1] = 0;
    return Err::none;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::netx_sendn() "
    "error while sending connect_request") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailSecondNetxSendn client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

class Maybesocks5hConnectFailSecondNetxRecvn : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return Err::none;
    }
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error while receiving connect_response_hdr") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailSecondNetxRecvn client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

class Maybesocks5hConnectInvalidSecondVersion : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return Err::none;
    }
    if (size == 4) {
      ((char *)buf)[0] = 4;  // unexpected
      ((char *)buf)[1] = 0;
      return Err::none;
    }
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with receiving "
    "invalid version number in second Client::recvn()") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInvalidSecondVersion client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::socks5h);
}

class Maybesocks5hConnectErrorResult : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return Err::none;
    }
    if (size == 4) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 1;  // error occurred
      return Err::none;
    }
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with receiving "
    "an error code in second Client::recvn()") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectErrorResult client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

class Maybesocks5hConnectInvalidReserved : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return Err::none;
    }
    if (size == 4) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      ((char *)buf)[2] = 1;  // should instead be zero
      return Err::none;
    }
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with receiving "
    "an invalid reserved field in second Client::recvn()") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectInvalidReserved client{settings};
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::socks5h);
}

class Maybesocks5hConnectFailAddressNetxRecvn : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  uint8_t type = 0;
  std::shared_ptr<bool> seen = std::make_shared<bool>(false);
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    if (size == 2) {
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      return Err::none;
    }
    if (size == 4 && !*seen) {
      *seen = true;  // use flag because IPv4 is also 4 bytes
      assert(type != 0);
      ((char *)buf)[0] = 5;
      ((char *)buf)[1] = 0;
      ((char *)buf)[2] = 0;
      ((char *)buf)[3] = (char)type;  // Sign change safe b/c we're serializing
      return Err::none;
    }
    // the subsequent recvn() will fail
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when reading a IPv4") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailAddressNetxRecvn client{settings};
  client.type = 1;
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when reading a IPv6") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailAddressNetxRecvn client{settings};
  client.type = 4;
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when reading a invalid address type") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectFailAddressNetxRecvn client{settings};
  client.type = 7;
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::socks5h);
}

class Maybesocks5hConnectWithArray : public Client {
 public:
  using Client::Client;
  Err netx_dial(const std::string &, const std::string &,
                        internal::Socket *sock) noexcept override {
    *sock = 17 /* Something "valid" */;
    return Err::none;
  }
  Err netx_sendn(internal::Socket, const void *,
                         internal::Size) const noexcept override {
    return Err::none;
  }
  std::shared_ptr<std::deque<std::string>> array = std::make_shared<
      std::deque<std::string>>();
  Err netx_recvn(internal::Socket, void *buf,
                         internal::Size size) const noexcept override {
    if (!array->empty() && size == (*array)[0].size()) {
      for (size_t idx = 0; idx < (*array)[0].size(); ++idx) {
        ((char *)buf)[idx] = (*array)[0][idx];
      }
      array->pop_front();
      return Err::none;
    }
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when failing to read domain length") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  *client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\3", 4},
  };
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when failing to read domain") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  *client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\3", 4},
      std::string{"\7", 1},
  };
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

TEST_CASE(
    "Client::netx_maybesocks5h_dial() deals with Client::recvn() "
    "error when failing to read port") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  *client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\3", 4},
      std::string{"\7", 1},
      std::string{"123.org", 7},
  };
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::io_error);
}

TEST_CASE("Client::netx_maybesocks5h_dial() works with IPv4 (mocked)") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  *client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\1", 4},
      std::string{"\0\0\0\0", 4},
      std::string{"\0\0", 2},
  };
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::none);
}

TEST_CASE("Client::netx_maybesocks5h_dial() works with IPv6 (mocked)") {
  Settings settings;
  settings.socks5h_port = "9050";
  Maybesocks5hConnectWithArray client{settings};
  *client.array = {
      std::string{"\5\0", 2},
      std::string{"\5\0\0\4", 4},
      std::string{"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16},
      std::string{"\0\0", 2},
  };
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_maybesocks5h_dial("www.google.com", "80", &sock) ==
          Err::none);
}

// Client::netx_map_errno() tests
// ------------------------------

#ifdef _WIN32
#define E(name) WSAE##name
#else
#define E(name) E##name
#endif

TEST_CASE("Client::netx_map_errno() correctly maps all errors") {
  using namespace measurement_kit::libndt;
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
  using namespace measurement_kit::libndt;
  Client client;
  REQUIRE(client.netx_map_eai(EAI_AGAIN) == Err::ai_again);
  REQUIRE(client.netx_map_eai(EAI_FAIL) == Err::ai_fail);
  REQUIRE(client.netx_map_eai(EAI_NONAME) == Err::ai_noname);
#ifdef EAI_SYSTEM
  {
    client.sys->SetLastError(E(WOULDBLOCK));
    REQUIRE(client.netx_map_eai(EAI_SYSTEM) == Err::operation_would_block);
    client.sys->SetLastError(0);
  }
#endif
}

#undef E  // Tidy

// Client::netx_dial() tests
// -------------------------

TEST_CASE("Client::netx_dial() requires initial socket to be -1") {
  Client client;
	internal::Socket sock = 21;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) ==
          Err::invalid_argument);
}

class FailNetxResolve : public Client {
 public:
  using Client::Client;
  Err netx_resolve(const std::string &,
                           std::vector<std::string> *) noexcept override {
    return Err::ai_again;
  }
};

TEST_CASE("Client::netx_dial() deals with Client::netx_resolve() failure") {
  FailNetxResolve client;
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == Err::ai_again);
}

class FailGetaddrinfoInNetxConnectClient : public Client {
 public:
  using Client::Client;
  Err netx_resolve(const std::string &str,
                           std::vector<std::string> *addrs) noexcept override {
    REQUIRE(str == "1.2.3.4");  // make sure it did not change
    addrs->push_back(str);
    return Err::none;
  }
};

class FailGetaddrinfoInNetxConnectSys : public internal::Sys {
 public:
  using Sys::Sys;
  int Getaddrinfo(const char *, const char *, const addrinfo *,
                  addrinfo **) const noexcept override {
    return EAI_AGAIN;
  }
};

TEST_CASE("Client::netx_dial() deals with Client::getaddrinfo() failure") {
  FailGetaddrinfoInNetxConnectClient client;
  client.sys.reset(new FailGetaddrinfoInNetxConnectSys{});
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == Err::ai_again);
}

class FailSocket : public internal::Sys {
 public:
  using Sys::Sys;
	internal::Socket NewSocket(int, int, int) const noexcept override {
    this->SetLastError(OS_EINVAL);
    return (internal::Socket)-1;
  }
};

TEST_CASE("Client::netx_dial() deals with Client::socket() failure") {
  Client client;
  client.sys.reset(new FailSocket{});
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == Err::io_error);
}

class FailSetnonblocking : public Client {
 public:
  using Client::Client;
  Err netx_setnonblocking(internal::Socket, bool) noexcept override {
    return Err::io_error;
  }
};

TEST_CASE(
    "Client::netx_dial() deals with Client::netx_setnonblocking() failure") {
  FailSetnonblocking client;
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == Err::io_error);
}

class FailSocketConnectImmediate : public internal::Sys {
 public:
  using Sys::Sys;
  int Connect(  //
      internal::Socket, const sockaddr *, socklen_t) const noexcept override {
    this->SetLastError(OS_EINVAL);
    return -1;
  }
};

TEST_CASE(
    "Client::netx_dial() deals with immediate Client::connect() failure") {
  Client client{};
  client.sys.reset(new FailSocketConnectImmediate);
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == Err::io_error);
}

#ifdef _WIN32
#define OS_EINPROGRESS WSAEWOULDBLOCK
#else
#define OS_EINPROGRESS EINPROGRESS
#endif

class FailSocketConnectTimeoutClient : public Client {
 public:
  using Client::Client;
  Err netx_poll(std::vector<pollfd> *, int) const noexcept override {
    return Err::timed_out;
  }
};

class FailSocketConnectTimeoutSys : public internal::Sys {
 public:
  using Sys::Sys;
  int Connect(  //
      internal::Socket, const sockaddr *, socklen_t) const noexcept override {
    this->SetLastError(OS_EINPROGRESS);
    return -1;
  }
};

TEST_CASE("Client::netx_dial() deals with Client::connect() timeout") {
  FailSocketConnectTimeoutClient client{};
  client.sys.reset(new FailSocketConnectTimeoutSys{});
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == Err::io_error);
}

class FailSocketConnectGetsockoptErrorClient : public Client {
 public:
  using Client::Client;
  Err netx_poll(
      std::vector<pollfd> *pfds, int) const noexcept override {
    for (auto &fd : *pfds) {
      fd.revents = fd.events;
    }
    return Err::none;
  }
};

class FailSocketConnectGetsockoptErrorSys : public internal::Sys {
 public:
  using Sys::Sys;
  int Connect(  //
      internal::Socket, const sockaddr *, socklen_t) const noexcept override {
    this->SetLastError(OS_EINPROGRESS);
    return -1;
  }
  int Getsockopt(internal::Socket, int, int, void *,
                 socklen_t *) const noexcept override {
    this->SetLastError(OS_EINVAL);
    return -1;
  }
};

TEST_CASE(
    "Client::netx_dial() deals with Client::connect() getsockopt() error") {
  FailSocketConnectGetsockoptErrorClient client{};
  client.sys.reset(new FailSocketConnectGetsockoptErrorSys{});
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == Err::io_error);
}

class FailSocketConnectSocketErrorClient : public Client {
 public:
  using Client::Client;
  Err netx_poll(
      std::vector<pollfd> *pfds, int) const noexcept override {
    for (auto &fd : *pfds) {
      fd.revents = fd.events;
    }
    return Err::none;
  }
};

class FailSocketConnectSocketErrorSys : public internal::Sys {
 public:
  using Sys::Sys;
  int Connect(  //
      internal::Socket, const sockaddr *, socklen_t) const noexcept override {
    this->SetLastError(OS_EINPROGRESS);
    return -1;
  }
  virtual int Getsockopt(internal::Socket, int, int, void *value,
                         socklen_t *) const noexcept override {
    int *ivalue = static_cast<int *>(value);
    *ivalue = OS_EINVAL;  // Any error would actually do here
    return 0;
  }
};

TEST_CASE("Client::netx_dial() deals with Client::connect() socket error") {
  FailSocketConnectSocketErrorClient client{};
  client.sys.reset(new FailSocketConnectSocketErrorSys{});
	internal::Socket sock = (internal::Socket)-1;
  REQUIRE(client.netx_dial("1.2.3.4", "33", &sock) == Err::io_error);
}

// Client::netx_recv_nonblocking() tests
// -------------------------------------

TEST_CASE("Client::netx_recv_nonblocking() deals with zero recv correctly") {
  Client client;
  char buf{};
	internal::Size n = 0;
  REQUIRE(client.netx_recv_nonblocking(0, &buf, 0, &n) ==
          Err::invalid_argument);
}

// Client::netx_recvn() tests
// --------------------------

#ifdef _WIN32
#define OS_SSIZE_MAX INT_MAX
#else
#define OS_SSIZE_MAX SSIZE_MAX
#endif

TEST_CASE("Client::netx_recvn() deals with too-large buffer") {
  Client client;
  char buf{};
  REQUIRE(client.netx_recvn(0, &buf, (unsigned long long)OS_SSIZE_MAX + 1) ==
          Err::invalid_argument);
}

class FailNetxRecv : public Client {
 public:
  using Client::Client;
  Err netx_recv(internal::Socket, void *, internal::Size,
                        internal::Size *) const noexcept override {
    return Err::invalid_argument;
  }
};

TEST_CASE("Client::netx_recvn() deals with Client::netx_recv() failure") {
  char buf[1024];
  FailNetxRecv client;
  REQUIRE(client.netx_recvn(0, buf, sizeof(buf)) ==
          Err::invalid_argument);
}

class RecvEof : public internal::Sys {
 public:
  using Sys::Sys;
	internal::Ssize Recv(internal::Socket, void *,
                     internal::Size) const noexcept override {
    return 0;
  }
};

TEST_CASE("Client::netx_recvn() deals with Client::recv() EOF") {
  char buf[1024];
  Client client;
  client.sys.reset(new RecvEof{});
  REQUIRE(client.netx_recvn(0, buf, sizeof(buf)) == Err::eof);
}

class PartialNetxRecvAndThenError : public Client {
 public:
  using Client::Client;
  static constexpr internal::Size amount = 11;
  static constexpr internal::Size good_amount = 3;
  Err netx_recv(internal::Socket, void *buf, internal::Size size,
                        internal::Size *rv) const noexcept override {
    if (size == amount) {
      assert(size >= good_amount);
      for (size_t i = 0; i < good_amount; ++i) {
        ((char *)buf)[i] = 'A';
      }
      *rv = good_amount;
      return Err::none;
    }
    *rv = 0;
    return Err::invalid_argument;
  }
};

TEST_CASE(
    "Client::netx_recvn() deals with partial Client::netx_recv() and then "
    "error") {
  char buf[PartialNetxRecvAndThenError::amount] = {};
  PartialNetxRecvAndThenError client;
  REQUIRE(client.netx_recvn(0, buf, sizeof(buf)) ==
          Err::invalid_argument);
  // Just to make sure the code path was entered correctly. We still think that
  // the right behaviour here is to return -1, not a short read.
  for (size_t i = 0; i < sizeof(buf); ++i) {
    if (i < PartialNetxRecvAndThenError::good_amount) {
      REQUIRE(buf[i] == 'A');
    } else {
      REQUIRE(buf[i] == '\0');
    }
  }
}

class PartialRecvAndThenEof : public internal::Sys {
 public:
  using Sys::Sys;
  static constexpr internal::Size amount = 7;
  static constexpr internal::Size good_amount = 5;
	internal::Ssize Recv(internal::Socket, void *buf,
                     internal::Size size) const noexcept override {
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
  Client client;
  client.sys.reset(new PartialRecvAndThenEof{});
  REQUIRE(client.netx_recvn(0, buf, sizeof(buf)) == Err::eof);
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

// Client::netx_send_nonblocking() tests
// -------------------------------------

TEST_CASE("Client::netx_send() deals with zero send correctly") {
  Client client;
	internal::Size n = 0;
  char buf{};
  REQUIRE(client.netx_send_nonblocking(0, &buf, 0, &n) ==
          Err::invalid_argument);
}

// Client::netx_sendn() tests
// --------------------------

TEST_CASE("Client::netx_sendn() deals with too-large buffer") {
  Client client;
  char buf{};
  REQUIRE(client.netx_sendn(0, &buf, (unsigned long long)OS_SSIZE_MAX + 1) ==
          Err::invalid_argument);
}

class FailSend : public internal::Sys {
 public:
  using Sys::Sys;
	internal::Ssize Send(internal::Socket, const void *,
                     internal::Size) const noexcept override {
    this->SetLastError(OS_EINVAL);
    return -1;
  }
};

TEST_CASE("Client::netx_sendn() deals with Client::send() failure") {
  char buf[1024];
  Client client;
  client.sys.reset(new FailSend{});
  REQUIRE(client.netx_sendn(0, buf, sizeof(buf)) ==
          Err::invalid_argument);
}

// As much as EOF should not appear on a socket when sending, be ready.
class SendEof : public internal::Sys {
 public:
  using Sys::Sys;
	internal::Ssize Send(internal::Socket, const void *,
                     internal::Size) const noexcept override {
    return 0;
  }
};

TEST_CASE("Client::netx_sendn() deals with Client::send() EOF") {
  char buf[1024];
  Client client;
  client.sys.reset(new SendEof{});
  REQUIRE(client.netx_sendn(0, buf, sizeof(buf)) == Err::io_error);
}

class PartialSendAndThenError : public internal::Sys {
 public:
  using Sys::Sys;
  static constexpr internal::Size amount = 11;
  static constexpr internal::Size good_amount = 3;
  std::shared_ptr<internal::Size> successful = std::make_shared<internal::Size>(0);
	internal::Ssize Send(internal::Socket, const void *,
                     internal::Size size) const noexcept override {
    if (size == amount) {
      assert(size >= good_amount);
      *successful += good_amount;
      return good_amount;
    }
    this->SetLastError(OS_EINVAL);
    return -1;
  }
};

TEST_CASE("Client::send() deals with partial Client::send() and then error") {
  char buf[PartialSendAndThenError::amount] = {};
  Client client;
  auto sys = new PartialSendAndThenError{}; // managed by client
  client.sys.reset(sys);
  REQUIRE(client.netx_sendn(0, buf, sizeof(buf)) ==
          Err::invalid_argument);
  // Just to make sure the code path was entered correctly. We still think that
  // the right behaviour here is to return -1, not a short write.
  //
  // Usage of `exp` is required to make clang compile (unclear to me why).
  auto exp = PartialSendAndThenError::good_amount;
  REQUIRE((*sys->successful) == exp);
}

// See above comment regarding likelihood of send returning EOF (i.e. zero)
class PartialSendAndThenEof : public internal::Sys {
 public:
  using Sys::Sys;
  static constexpr internal::Size amount = 7;
  static constexpr internal::Size good_amount = 5;
  std::shared_ptr<internal::Size> successful = std::make_shared<internal::Size>(0);
	internal::Ssize Send(internal::Socket, const void *,
                     internal::Size size) const noexcept override {
    if (size == amount) {
      assert(size >= good_amount);
      *successful += good_amount;
      return good_amount;
    }
    return 0;
  }
};

TEST_CASE(
    "Client::netx_sendn() deals with partial Client::send() and then EOF") {
  char buf[PartialSendAndThenEof::amount] = {};
  Client client;
  auto sys = new PartialSendAndThenEof{}; // managed by client
  client.sys.reset(sys);
  REQUIRE(client.netx_sendn(0, buf, sizeof(buf)) == Err::io_error);
  // Just to make sure the code path was entered correctly. We still think that
  // the right behaviour here is to return zero, not a short write.
  //
  // Usage of `exp` is required to make clang compile (unclear to me why).
  auto exp = PartialSendAndThenEof::good_amount;
  REQUIRE((*sys->successful) == exp);
}

// Client::netx_resolve() tests
// ----------------------------

class FailGetaddrinfo : public internal::Sys {
 public:
  using Sys::Sys;
  int Getaddrinfo(const char *, const char *, const addrinfo *,
                  addrinfo **) const noexcept override {
    return EAI_AGAIN;
  }
};

TEST_CASE("Client::netx_resolve() deals with Client::getaddrinfo() failure") {
  Client client;
  client.sys.reset(new FailGetaddrinfo{});
  std::vector<std::string> addrs;
  REQUIRE(client.netx_resolve("x.org", &addrs) == Err::ai_again);
}

class FailGetnameinfo : public internal::Sys {
 public:
  using Sys::Sys;
  int Getnameinfo(const sockaddr *, socklen_t, char *, socklen_t, char *,
                  socklen_t, int) const noexcept override {
    return EAI_AGAIN;
  }
};

TEST_CASE("Client::netx_resolve() deals with Client::getnameinfo() failure") {
  Client client;
  client.sys.reset(new FailGetnameinfo{});
  std::vector<std::string> addrs;
  REQUIRE(client.netx_resolve("x.org", &addrs) == Err::ai_generic);
}

// Client::netx_setnonblocking() tests
// -----------------------------------

#ifdef _WIN32

class FailIoctlsocket : public internal::Sys {
 public:
  using Sys::Sys;
  u_long expect = 2UL;  // value that should not be used
  int Ioctlsocket(internal::Socket, long cmd,
                  u_long *value) const noexcept override {
    REQUIRE(cmd == FIONBIO);
    REQUIRE(*value == expect);
    this->SetLastError(WSAEINVAL);
    return -1;
  }
};

TEST_CASE(
    "Client::netx_setnonblocking() deals with Client::ioctlsocket() failure") {
  Client client;
  auto sys = new FailIoctlsocket{}; // managed by client
  client.sys.reset(sys);
  {
    sys->expect = 1UL;
    REQUIRE(client.netx_setnonblocking(17, true) ==
            Err::invalid_argument);
  }
  {
    sys->expect = 0UL;
    REQUIRE(client.netx_setnonblocking(17, false) ==
            Err::invalid_argument);
  }
}

#else

class FailFcntlGet : public internal::Sys {
 public:
  using Sys::Sys;
  using Sys::Fcntl;
  int Fcntl(internal::Socket, int cmd) const noexcept override {
    REQUIRE(cmd == F_GETFL);
    errno = EINVAL;
    return -1;
  }
};

TEST_CASE(
    "Client::netx_setnonblocking() deals with Client::fcntl(F_GETFL) failure") {
  Client client;
  client.sys.reset(new FailFcntlGet{});
  REQUIRE(client.netx_setnonblocking(17, true) ==
          Err::invalid_argument);
}

class FailFcntlSet : public internal::Sys {
 public:
  using Sys::Sys;
  int Fcntl(internal::Socket, int cmd) const noexcept override {
    REQUIRE(cmd == F_GETFL);
    return 0;
  }
  int expect = ~0;  // value that should never appear
  int Fcntl(internal::Socket, int cmd, int flags) const noexcept override {
    REQUIRE(cmd == F_SETFL);
    REQUIRE(flags == expect);
    errno = EINVAL;
    return -1;
  }
};

TEST_CASE(
    "Client::netx_setnonblocking() deals with Client::fcntl(F_SETFL) failure") {
  Client client;
  auto sys = new FailFcntlSet{}; // managed by client
  client.sys.reset(sys);
  {
    sys->expect = O_NONBLOCK;
    REQUIRE(client.netx_setnonblocking(17, true) ==
            Err::invalid_argument);
  }
  {
    sys->expect = 0;
    REQUIRE(client.netx_setnonblocking(17, false) ==
            Err::invalid_argument);
  }
}

#endif  // _WIN32

// Client::netx_poll() tests
// ---------------------------

#ifndef _WIN32

class InterruptPoll : public internal::Sys {
 public:
  using Sys::Sys;
  std::shared_ptr<unsigned int> count = std::make_shared<unsigned int>();
  int Poll(pollfd *, nfds_t, int) const noexcept override {
    if ((*count)++ == 0) {
      this->SetLastError(EINTR);
    } else {
      this->SetLastError(EIO);
    }
    return -1;
  }
};

TEST_CASE("Client::netx_poll() deals with EINTR") {
  pollfd pfd{};
  constexpr internal::Socket sock = 17;
  pfd.fd = sock;
  pfd.events |= POLLIN;
  std::vector<pollfd> pfds;
  pfds.push_back(pfd);
  Client client;
  auto sys = new InterruptPoll{}; // managed by client
  client.sys.reset(sys);
  constexpr int timeout = 100;
  REQUIRE(client.netx_poll(&pfds, timeout) == Err::io_error);
  REQUIRE(*sys->count == 2);
}

#endif  // !_WIN32

class TimeoutPoll : public internal::Sys {
 public:
  using Sys::Sys;
#ifdef _WIN32
  int Poll(LPWSAPOLLFD, ULONG, INT) const noexcept override
#else
  int Poll(pollfd *, nfds_t, int) const noexcept override
#endif
  {
    return 0;
  }
};

TEST_CASE("Client::netx_poll() deals with timeout") {
  pollfd pfd{};
  constexpr internal::Socket sock = 17;
  pfd.fd = sock;
  pfd.events |= POLLIN;
  std::vector<pollfd> pfds;
  pfds.push_back(pfd);
  Client client;
  client.sys.reset(new TimeoutPoll{});
  constexpr int timeout = 100;
  REQUIRE(client.netx_poll(&pfds, timeout) == Err::timed_out);
}

// Client::query_mlabns_curl() tests
// ---------------------------------

#ifdef HAVE_CURL
TEST_CASE("Client::query_mlabns_curl() deals with Curl{} failure") {
  Client client;
  // Note: passing `nullptr` should cause Curl{} to fail and hence we can
  // also easily check for cases where Curl{} fails.
  REQUIRE(client.query_mlabns_curl("", 3, nullptr) == false);
}
#endif

// Client::sys->GetLastError() tests
// ----------------------------------

#ifdef _WIN32
#define OS_EINVAL WSAEINVAL
#else
#define OS_EINVAL EINVAL
#endif

TEST_CASE("Client::sys->GetLastError() works as expected") {
  Client client;
  client.sys->SetLastError(OS_EINVAL);
  REQUIRE(client.sys->GetLastError() == OS_EINVAL);
  client.sys->SetLastError(0);  // clear
  REQUIRE(client.sys->GetLastError() == 0);
}

// Client::recv() tests
// --------------------

TEST_CASE("Sys::recv() deals with too-large buffer") {
  Client client;
  REQUIRE(client.sys->Recv(
        0, nullptr, (unsigned long long)OS_SSIZE_MAX + 1) == -1);
}

// Client::send() tests
// --------------------

TEST_CASE("Sys::send() deals with too-large buffer") {
  Client client;
  REQUIRE(client.sys->Send(
        0, nullptr, (unsigned long long)OS_SSIZE_MAX + 1) == -1);
}
