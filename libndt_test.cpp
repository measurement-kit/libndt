// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt.hpp"

#include <assert.h>

#include "catch.hpp"
#include "json.hpp"

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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.run() == false);
}

// Client::query_mlabns() tests
// ----------------------------

class FailQueryMlabnsCurl : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns_curl(const std::string &, long, std::string *) noexcept {
    return false;
  }
};

TEST_CASE(
    "Client::query_mlabns() deals with Client::query_mlabns_curl() failure") {
  FailQueryMlabnsCurl client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.query_mlabns() == false);
}

class EmptyMlabnsJson : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns_curl(const std::string &, long, std::string *body) noexcept {
    *body = "";
    return true;
  }
};

TEST_CASE("Client::query_mlabns() deals with empty JSON") {
  EmptyMlabnsJson client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.query_mlabns() == false);
}

class InvalidMlabnsJson : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns_curl(const std::string &, long, std::string *body) noexcept {
    *body = "{{{{";
    return true;
  }
};

TEST_CASE("Client::query_mlabns() deals with invalid JSON") {
  InvalidMlabnsJson client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.query_mlabns() == false);
}

class IncompleteMlabnsJson : public libndt::Client {
 public:
  using libndt::Client::Client;
  bool query_mlabns_curl(const std::string &, long, std::string *body) noexcept {
    *body = "{}";
    return true;
  }
};

TEST_CASE("Client::query_mlabns() deals with incomplete JSON") {
  IncompleteMlabnsJson client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.query_mlabns() == false);
}

// Client::recv_kickoff() tests
// ----------------------------

class FailRecv : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Ssize recv(libndt::Socket, void *, libndt::Size) noexcept override {
    return -1;
  }
};

TEST_CASE("Client::recv_kickoff() deals with Client::recv() failure") {
  FailRecv client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.recv_kickoff() == false);
}

class RecvEof : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Ssize recv(libndt::Socket, void *, libndt::Size) noexcept override {
    return 0;
  }
};

TEST_CASE("Client::recv_kickoff() deals with Client::recv() EOF") {
  RecvEof client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.recv_kickoff() == false);
}

class RecvInvalidKickoff : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Ssize recv(  //
      libndt::Socket, void *buf, libndt::Size siz) noexcept override {
    REQUIRE(buf != nullptr);
    REQUIRE(siz >= 1);
    ((char *)buf)[0] = 'x';
    return 1;
  }
};

TEST_CASE("Client::recv_kickoff() deals with invalid kickoff") {
  RecvInvalidKickoff client;
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.wait_in_queue() == false);
}

// Client::recv_version() tests
// ----------------------------

TEST_CASE("Client::recv_version() deals with Client::msg_expect() failure") {
  FailMsgExpect client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.recv_version() == false);
}

// Client::recv_tests_ids() tests
// ------------------------------

TEST_CASE("Client::recv_tests_ids() deals with Client::msg_expect() failure") {
  FailMsgExpect client;
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
  client.tests_ids = std::to_string(libndt::nettest_upload);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

TEST_CASE("Client::run_tests() deals with Client::run_meta() failure") {
  RunTestsMock client;
  client.settings.verbosity = libndt::verbosity_quiet;
  client.tests_ids = std::to_string(libndt::nettest_meta);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

TEST_CASE("Client::run_tests() deals with Client::run_download() failure") {
  RunTestsMock client;
  client.settings.verbosity = libndt::verbosity_quiet;
  client.tests_ids = std::to_string(libndt::nettest_download);
  REQUIRE(client.recv_tests_ids() == true);
  REQUIRE(client.run_tests() == false);
}

TEST_CASE("Client::run_tests() deals with unexpected test-id") {
  RunTestsMock client;
  client.settings.verbosity = libndt::verbosity_quiet;
  client.tests_ids = std::to_string(libndt::nettest_status);
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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

TEST_CASE("Client::recv_results_and_logout() deals too many results") {
  TooManyResults client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.recv_results_and_logout() == false);
}

// Client::wait_close() tests
// --------------------------

class SelectHardFailure : public libndt::Client {
 public:
  using libndt::Client::Client;
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
#ifdef _WIN32
    set_last_error(WSAEBADF);
#else
    set_last_error(EBADF);
#endif
    return -1;
  }
};

TEST_CASE("Client::wait_close() deals with Client::select() hard failure") {
  SelectHardFailure client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.wait_close() == false);
}

#ifndef _WIN32
class SelectEintr : public libndt::Client {
 public:
  using libndt::Client::Client;
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    set_last_error(EINTR);
    return -1;
  }
};

TEST_CASE("Client::wait_close() deals with Client::select() EINTR") {
  SelectEintr client;
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.wait_close() == true /* Being tolerant */);
}

class FailRecvAfterGoodSelect : public libndt::Client {
 public:
  using libndt::Client::Client;
  int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept override {
    return 1;
  }
  libndt::Ssize recv(libndt::Socket, void *, libndt::Size) noexcept override {
    return -1;
  }
};

TEST_CASE("Client::wait_close() deals Client::recv() failure") {
  FailRecvAfterGoodSelect client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.wait_close() == false);
}

// Client::connect_tcp() tests
// ---------------------------

TEST_CASE("Client::connect_tcp() requires initial socket to be -1") {
  libndt::Client client;
  libndt::Socket sock = 21;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.connect_tcp("1.2.3.4", "33", &sock) == false);
}

class FailGetaddrinfo : public libndt::Client {
 public:
  using libndt::Client::Client;
  int getaddrinfo(const char *, const char *, const addrinfo *,
                  addrinfo **) noexcept override {
    return EAI_AGAIN;
  }
};

TEST_CASE("Client::connect_tcp() deals with Client::getaddrinfo() failure") {
  FailGetaddrinfo client;
  libndt::Socket sock = -1;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.connect_tcp("1.2.3.4", "33", &sock) == false);
}

class FailSocket : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Socket socket(int, int, int) noexcept override { return -1; }
};

TEST_CASE("Client::connect_tcp() deals with Client::socket() failure") {
  FailSocket client;
  libndt::Socket sock = -1;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.connect_tcp("1.2.3.4", "33", &sock) == false);
}

class FailSocketConnect : public libndt::Client {
 public:
  using libndt::Client::Client;
  int connect(  //
      libndt::Socket, const sockaddr *, libndt::SockLen) noexcept override {
    return -1;
  }
};

TEST_CASE("Client::connect_tcp() deals with Client::connect() failure") {
  FailSocketConnect client{};
  libndt::Socket sock = -1;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.connect_tcp("1.2.3.4", "33", &sock) == false);
}

// Client::msg_write_login() tests
// -------------------------------

TEST_CASE("Client::msg_write_login() deals with invalid protocol") {
  libndt::Client client;
  // That is, more precisely, a valid but unimplemented proto
  client.settings.proto = libndt::NdtProtocol::proto_websockets;
  client.settings.verbosity = libndt::verbosity_quiet;
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
  client.settings.verbosity = libndt::verbosity_quiet;
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
    REQUIRE((tests & libndt::nettest_middlebox) == 0);
    REQUIRE((tests & libndt::nettest_simple_firewall) == 0);
    REQUIRE((tests & libndt::nettest_upload_ext) == 0);
    return true;
  }
};

TEST_CASE("Client::msg_write_login() does not propagate unknown tests ids") {
  ValidatingMsgWriteLegacy client;
  client.settings.verbosity = libndt::verbosity_quiet;
  client.settings.proto = libndt::NdtProtocol::proto_json;
  client.settings.test_suite = 0xff;
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
  libndt::Client client;
  client.settings.proto = libndt::NdtProtocol::proto_json;
  auto s = non_serializable();
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.msg_write_login(s) == false);
}

// Client::msg_write() tests
// -------------------------

TEST_CASE("Client::msg_write() deals with unserializable JSON") {
  libndt::Client client;
  client.settings.proto = libndt::NdtProtocol::proto_json;
  auto s = non_serializable();
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.msg_write(libndt::msg_test_start, std::move(s)) == false);
}

TEST_CASE("Client::msg_write() deals with invalid protocol") {
  libndt::Client client;
  // That is, more precisely, a valid but unimplemented proto
  client.settings.proto = libndt::NdtProtocol::proto_websockets;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.msg_write(libndt::msg_test_start, "foo") == false);
}

TEST_CASE("Client::msg_write() deals with Client::msg_write_legacy() failure") {
  FailMsgWriteLegacy client;
  client.settings.verbosity = libndt::verbosity_quiet;
  REQUIRE(client.msg_write(libndt::msg_test_start, "foo") == false);
}

// Client::msg_write_legacy() tests
// --------------------------------

TEST_CASE("Client::msg_write_legacy() deals with too-big messages") {
  libndt::Client client;
  client.settings.verbosity = libndt::verbosity_quiet;
  std::string m;
  m.resize(UINT16_MAX + 1);
  REQUIRE(client.msg_write_legacy(  //
              libndt::msg_test_start, std::move(m)) == false);
}

class FailSend : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Ssize send(libndt::Socket, const void *,
                     libndt::Size) noexcept override {
    return -1;
  }
};

TEST_CASE(
    "Client::msg_write_legacy() deals with Client::send() failure when sending "
    "header") {
  FailSend client;
  client.settings.verbosity = libndt::verbosity_quiet;
  std::string m{"foo"};
  client.set_last_error(0);
  REQUIRE(client.msg_write_legacy(  //
              libndt::msg_test_start, std::move(m)) == false);
}

class FailLargeSend : public libndt::Client {
 public:
  using libndt::Client::Client;
  libndt::Ssize send(libndt::Socket, const void *,
                     libndt::Size siz) noexcept override {
    return siz <= 3 ? 3 : -1;
  }
};

TEST_CASE(
    "Client::msg_write_legacy() deals with Client::send() failure when sending "
    "message") {
  FailLargeSend client;
  client.settings.verbosity = libndt::verbosity_quiet;
  std::string m{"foobar"};
  client.set_last_error(0);
  REQUIRE(client.msg_write_legacy(  //
              libndt::msg_test_start, std::move(m)) == false);
}
