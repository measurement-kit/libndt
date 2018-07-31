// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "json.hpp"
#include "libndt.hpp"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

using namespace measurement_kit;

// Client::curlx_get_maybe_socks5() tests
// --------------------------------------

class FailCurlxEasyInit : public libndt::Client {
 public:
  using libndt::Client::Client;
  virtual libndt::Client::UniqueCurl curlx_easy_init() noexcept override {
      return {};
  }
};

TEST_CASE("Client::curlx_get_maybe_socks5() deals with Client::curlx_easy_init() failure") {
  FailCurlxEasyInit client;
  std::string body;
  REQUIRE(!client.curlx_get_maybe_socks5("", "http://x.org", 1, &body));
}

class FailCurlxSetoptProxy : public libndt::Client {
 public:
  using libndt::Client::Client;
  virtual CURLcode curlx_setopt_proxy(
      libndt::Client::UniqueCurl &, const std::string &) noexcept override {
    return CURLE_UNSUPPORTED_PROTOCOL; // any error is okay here
  }
};

TEST_CASE(
    "Client::curlx_get_maybe_socks5() deals with Client::curlx_setopt_proxy() failure") {
  FailCurlxSetoptProxy client;
  std::string body;
  REQUIRE(!client.curlx_get_maybe_socks5("9050", "http://x.org", 1, &body));
}

// Client::curlx_get() tests
// -------------------------

TEST_CASE("Client::curlx_get() deals with null body") {
  libndt::Client client;
  libndt::Client::UniqueCurl handle{client.curlx_easy_init()};
  REQUIRE(client.curlx_get(handle, "http://x.org", 1, nullptr) == false);
}

class FailCurlxSetoptUrl : public libndt::Client {
 public:
  using libndt::Client::Client;
  virtual CURLcode curlx_setopt_url(
      libndt::Client::UniqueCurl &, const std::string &) noexcept {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Client::curlx_get() deals with Client::curlx_setopt_url() failure") {
  FailCurlxSetoptUrl client;
  libndt::Client::UniqueCurl handle{client.curlx_easy_init()};
  std::string body;
  REQUIRE(client.curlx_get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptWritefunction : public libndt::Client {
 public:
  using libndt::Client::Client;
  virtual CURLcode curlx_setopt_writefunction(
      libndt::Client::UniqueCurl &, size_t (*)(
        char *ptr, size_t size, size_t nmemb, void *userdata))
          noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Client::curlx_get() deals with Client::curlx_setopt_writefunction() failure") {
  FailCurlxSetoptWritefunction client;
  libndt::Client::UniqueCurl handle{client.curlx_easy_init()};
  std::string body;
  REQUIRE(client.curlx_get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptWritedata : public libndt::Client {
 public:
  using libndt::Client::Client;
  virtual CURLcode curlx_setopt_writedata(
      libndt::Client::UniqueCurl &, void *) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Client::curlx_get() deals with Client::curlx_setopt_writedata() failure") {
  FailCurlxSetoptWritedata client;
  libndt::Client::UniqueCurl handle{client.curlx_easy_init()};
  std::string body;
  REQUIRE(client.curlx_get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptTimeout : public libndt::Client {
 public:
  using libndt::Client::Client;
  virtual CURLcode curlx_setopt_timeout(
      libndt::Client::UniqueCurl &, long) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Client::curlx_get() deals with Client::curlx_setopt_timeout() failure") {
  FailCurlxSetoptTimeout client;
  libndt::Client::UniqueCurl handle{client.curlx_easy_init()};
  std::string body;
  REQUIRE(client.curlx_get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxPerform : public libndt::Client {
 public:
  using libndt::Client::Client;
  virtual CURLcode curlx_perform(
    libndt::Client::UniqueCurl &) noexcept override { return CURLE_AGAIN; }
};

TEST_CASE("Client::curlx_get() deals with Client::curlx_perform() failure") {
  FailCurlxPerform client;
  libndt::Client::UniqueCurl handle{client.curlx_easy_init()};
  std::string body;
  REQUIRE(client.curlx_get(handle, "http://x.org", 1, &body) == false);
}

// Client::curlx_setopt_proxy() tests
// ----------------------------------

TEST_CASE("Client::setopt_proxy() works") {
  libndt::Client client;
  libndt::Client::UniqueCurl handle{client.curlx_easy_init()};
  REQUIRE(client.curlx_setopt_proxy(
    handle, "socks5h://127.0.0.1:9050") == CURLE_OK);
}
