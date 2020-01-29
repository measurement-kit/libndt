// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt/internal/curlx.hpp"

#define CATCH_CONFIG_MAIN
#include "third_party/github.com/catchorg/Catch2/catch.hpp"

using namespace measurement_kit::libndt::internal;

// Curlx::GetMaybeSOCKS5() tests
// -----------------------------

class FailCurlxEasyInit : public Curlx {
 public:
  using Curlx::Curlx;
  virtual UniqueCurl NewUniqueCurl() noexcept override {
      return {};
  }
};

TEST_CASE("Curlx::GetMaybeSOSCKS5() deals with Curlx::NewUniqueCurl() failure") {
  FailCurlxEasyInit curlx{NoLogger{}};
  std::string body;
  REQUIRE(!curlx.GetMaybeSOCKS5("", "http://x.org", 1, &body));
}

class FailCurlxSetoptProxy : public Curlx {
 public:
  using Curlx::Curlx;
  virtual CURLcode SetoptProxy(
      UniqueCurl &, const std::string &) noexcept override {
    return CURLE_UNSUPPORTED_PROTOCOL; // any error is okay here
  }
};

TEST_CASE(
    "Curlx::GetMaybeSOCKS5() deals with Curlx::SetoptProxy() failure") {
  FailCurlxSetoptProxy curlx{NoLogger{}};
  std::string body;
  REQUIRE(!curlx.GetMaybeSOCKS5("9050", "http://x.org", 1, &body));
}

// Curlx::Get() tests
// ------------------

TEST_CASE("Curlx::Get() deals with null body") {
  Curlx curlx{NoLogger{}};
  UniqueCurl handle{curlx.NewUniqueCurl()};
  REQUIRE(curlx.Get(handle, "http://x.org", 1, nullptr) == false);
}

class FailCurlxSetoptUrl : public Curlx {
 public:
  using Curlx::Curlx;
  virtual CURLcode SetoptURL(
      UniqueCurl &, const std::string &) noexcept {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptURL() failure") {
  FailCurlxSetoptUrl curlx{NoLogger{}};
  UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptWritefunction : public Curlx {
 public:
  using Curlx::Curlx;
  virtual CURLcode SetoptWriteFunction(
      UniqueCurl &, CurlWriteCb) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptWriteFunction() failure") {
  FailCurlxSetoptWritefunction curlx{NoLogger{}};
  UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptWritedata : public Curlx {
 public:
  using Curlx::Curlx;
  virtual CURLcode SetoptWriteData(
      UniqueCurl &, void *) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptWriteData() failure") {
  FailCurlxSetoptWritedata curlx{NoLogger{}};
  UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptTimeout : public Curlx {
 public:
  using Curlx::Curlx;
  virtual CURLcode SetoptTimeout(
      UniqueCurl &, long) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptTimeout() failure") {
  FailCurlxSetoptTimeout curlx{NoLogger{}};
  UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxSetoptFailonerror : public Curlx {
 public:
  using Curlx::Curlx;
  virtual CURLcode SetoptFailonerr(
      UniqueCurl &) noexcept override {
    return CURLE_AGAIN;
  }
};

TEST_CASE("Curlx::Get() deals with Curlx::SetoptFailonerror() failure") {
  FailCurlxSetoptFailonerror curlx{NoLogger{}};
  UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

class FailCurlxPerform : public Curlx {
 public:
  using Curlx::Curlx;
  virtual CURLcode Perform(
    UniqueCurl &) noexcept override { return CURLE_AGAIN; }
};

TEST_CASE("Curlx::Get() deals with Curlx::Perform() failure") {
  FailCurlxPerform curlx{NoLogger{}};
  UniqueCurl handle{curlx.NewUniqueCurl()};
  std::string body;
  REQUIRE(curlx.Get(handle, "http://x.org", 1, &body) == false);
}

// Curlx::SetoptProxy() tests
// --------------------------

TEST_CASE("Curlx::SetoptProxy() works") {
  Curlx curlx{NoLogger{}};
  UniqueCurl handle{curlx.NewUniqueCurl()};
  REQUIRE(curlx.SetoptProxy(
    handle, "socks5h://127.0.0.1:9050") == CURLE_OK);
}
