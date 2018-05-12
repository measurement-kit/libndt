// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt.hpp"

#include <assert.h>

#include "catch.hpp"

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

// Client::connect_tcp() tests
// ---------------------------

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
