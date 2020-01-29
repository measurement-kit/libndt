// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "curlx.hpp"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "logger.hpp"

using namespace measurement_kit;

// Curlx::GetMaybeSOCKS5() tests
// -----------------------------

class FailCurlxEasyInit : public libndt::Curlx {
 public:
  using libndt::Curlx::Curlx;
  virtual libndt::UniqueCurl NewUniqueCurl() noexcept override {
      return {};
  }
};

TEST_CASE("Curlx::GetMaybeSOSCKS5() deals with Curlx::NewUniqueCurl() failure") {
  FailCurlxEasyInit curlx{libndt::NoLogger{}};
  std::string body;
  REQUIRE(!curlx.GetMaybeSOCKS5("", "http://x.org", 1, &body));
}

class FailCurlxSetoptProxy : public libndt::Curlx {
 public:
  using libndt::Curlx::Curlx;
  virtual CURLcode SetoptProxy(
      libndt::UniqueCurl &, const std::string &) noexcept override {
    return CURLE_UNSUPPORTED_PROTOCOL; // any error is okay here
  }
};

TEST_CASE(
    "Curlx::GetMaybeSOCKS5() deals with Curlx::SetoptProxy() failure") {
  FailCurlxSetoptProxy curlx{libndt::NoLogger{}};
  std::string body;
  REQUIRE(!curlx.GetMaybeSOCKS5("9050", "http://x.org", 1, &body));
}

// Curlx::Get() tests
// ------------------

TEST_CASE("Curlx::Get() deals with null body") {
  libndt::Curlx curlx{libndt::NoLogger{}};
  libndt::UniqueCurl handle{curlx.NewUniqueCurl()};
  REQUIRE(curlx.Get(handle, "http://x.org", 1, nullptr) == false);
}

class FailCurlxSetoptUrl : public libndt::Curlx {
 public:
  using libndt::Curlx::Curlx;
  virtual CURLcode SetoptURL(
      libndt::UniqueCurl &, const std::string &) noexcept {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptURL() failure") {
  FailCurlxSetoptUrl curlx{libndt::NoLogger{}};
  libndt::UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptWritefunction : public libndt::Curlx {
 public:
  using libndt::Curlx::Curlx;
  virtual CURLcode SetoptWriteFunction(
      libndt::UniqueCurl &, libndt::CurlWriteCb) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptWriteFunction() failure") {
  FailCurlxSetoptWritefunction curlx{libndt::NoLogger{}};
  libndt::UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptWritedata : public libndt::Curlx {
 public:
  using libndt::Curlx::Curlx;
  virtual CURLcode SetoptWriteData(
      libndt::UniqueCurl &, void *) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptWriteData() failure") {
  FailCurlxSetoptWritedata curlx{libndt::NoLogger{}};
  libndt::UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptTimeout : public libndt::Curlx {
 public:
  using libndt::Curlx::Curlx;
  virtual CURLcode SetoptTimeout(
      libndt::UniqueCurl &, long) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptTimeout() failure") {
  FailCurlxSetoptTimeout curlx{libndt::NoLogger{}};
  libndt::UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptFailonerror : public libndt::Curlx {
 public:
  using libndt::Curlx::Curlx;
  virtual CURLcode SetoptFailonerr(
      libndt::UniqueCurl &) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptFailonerror() failure") {
  FailCurlxSetoptFailonerror curlx{libndt::NoLogger{}};
  libndt::UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxPerform : public libndt::Curlx {
 public:
  using libndt::Curlx::Curlx;
  virtual CURLcode Perform(
    libndt::UniqueCurl &) noexcept override { return CURLE_AGAIN; }
};

TEST_CASE("Curlx::Get() deals with Curlx::Perform() failure") {
  FailCurlxPerform curlx{libndt::NoLogger{}};
  libndt::UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

// Curlx::SetoptProxy() tests
// --------------------------

TEST_CASE("Curlx::SetoptProxy() works") {
  libndt::Curlx curlx{libndt::NoLogger{}};
  libndt::UniqueCurl handle{curlx.NewUniqueCurl()};
  REQUIRE(curlx.SetoptProxy(
    handle, "socks5h://127.0.0.1:9050") == CURLE_OK);
}
