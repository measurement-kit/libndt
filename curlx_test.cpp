// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifdef HAVE_CURL

#include "curlx.hpp"

#include "catch.hpp"

using namespace measurement_kit;

// Curl::method_get_maybe_socks5() tests
// -------------------------------------

class FailInit : public libndt::Curl {
 public:
  using libndt::Curl::Curl;
  virtual bool init() noexcept override { return false; }
};

TEST_CASE("Curl::method_get_maybe_socks5() deals with Curl::init() failure") {
  FailInit curl;
  std::string body;
  std::string err;
  REQUIRE(!curl.method_get_maybe_socks5("", "http://x.org", 1, &body, &err));
}

class FailSetoptProxy : public libndt::Curl {
 public:
  using libndt::Curl::Curl;
  virtual CURLcode setopt_proxy(const std::string &) noexcept override {
    return CURLE_UNSUPPORTED_PROTOCOL; // any error is okay here
  }
};

TEST_CASE(
    "Curl::method_get_maybe_socks5() deals with Curl::setopt_proxy() failure") {
  FailSetoptProxy curl;
  std::string body;
  std::string err;
  REQUIRE(
      !curl.method_get_maybe_socks5("9050", "http://x.org", 1, &body, &err));
  REQUIRE(err == "cannot set proxy");
}

// Curl::method_get() tests
// ------------------------

TEST_CASE("Curl::method_get() deals with null body") {
  libndt::Curl curl;
  std::string err;
  REQUIRE(curl.method_get("http://x.org", 1, nullptr, &err) == false);
}

TEST_CASE("Curl::method_get() deals with null err") {
  libndt::Curl curl;
  std::string body;
  REQUIRE(curl.method_get("http://x.org", 1, &body, nullptr) == false);
}

TEST_CASE("Curl::method_get() deals with Curl::init() failure") {
  FailInit curl;
  std::string body;
  std::string err;
  REQUIRE(curl.method_get("http://x.org", 1, &body, &err) == false);
}

class FailSetoptUrl : public libndt::Curl {
 public:
  using libndt::Curl::Curl;
  virtual CURLcode setopt_url(const std::string &) noexcept {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curl::method_get() deals with Curl::setopt_url() failure") {
  FailSetoptUrl curl;
  std::string body;
  std::string err;
  REQUIRE(curl.method_get("http://x.org", 1, &body, &err) == false);
}

class FailSetoptWritefunction : public libndt::Curl {
 public:
  using libndt::Curl::Curl;
  virtual CURLcode setopt_writefunction(size_t (*)(
      char *ptr, size_t size, size_t nmemb, void *userdata)) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE(  //
    "Curl::method_get() deals with Curl::setopt_writefunction() failure") {
  FailSetoptWritefunction curl;
  std::string body;
  std::string err;
  REQUIRE(curl.method_get("http://x.org", 1, &body, &err) == false);
}

class FailSetoptWritedata : public libndt::Curl {
 public:
  using libndt::Curl::Curl;
  virtual CURLcode setopt_writedata(void *) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curl::method_get() deals with Curl::setopt_writedata() failure") {
  FailSetoptWritedata curl;
  std::string body;
  std::string err;
  REQUIRE(curl.method_get("http://x.org", 1, &body, &err) == false);
}

class FailSetoptTimeout : public libndt::Curl {
 public:
  using libndt::Curl::Curl;
  virtual CURLcode setopt_timeout(long) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curl::method_get() deals with Curl::setopt_timeout() failure") {
  FailSetoptTimeout curl;
  std::string body;
  std::string err;
  REQUIRE(curl.method_get("http://x.org", 1, &body, &err) == false);
}

class FailPerform : public libndt::Curl {
 public:
  using libndt::Curl::Curl;
  virtual CURLcode perform() noexcept override { return CURLE_AGAIN; }
};

TEST_CASE("Curl::method_get() deals with Curl::perform() failure") {
  FailPerform curl;
  std::string body;
  std::string err;
  REQUIRE(curl.method_get("http://x.org", 1, &body, &err) == false);
}

// Curl::init() tests
// ------------------

class FailEasyInit : public libndt::Curl {
 public:
  using libndt::Curl::Curl;
  CURL *easy_init() noexcept override { return nullptr; }
};

TEST_CASE("Curl::init() deals with curl_easy_init() failure") {
  FailEasyInit curl;
  REQUIRE(curl.init() == false);
}

TEST_CASE("Curl::init() is idempotent") {
  libndt::Curl curl;
  REQUIRE(curl.init() == true);
  REQUIRE(curl.init() == true);
}

// Curl::setopt_proxy() tests
// --------------------------

TEST_CASE("Curl::setopt_proxy() works") {
  libndt::Curl curl;
  REQUIRE(curl.init() == true);
  REQUIRE(curl.setopt_proxy("socks5h://127.0.0.1:9050") == CURLE_OK);
}

#endif  // HAVE_CURL
