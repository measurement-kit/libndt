// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifdef HAVE_CURL

#include "curlx.hpp"

#include "catch.hpp"

using namespace measurement_kit;

class MockedCurl : public libndt::Curl {
 public:
  using libndt::Curl::Curl;

  CURL *easy_init() noexcept override {
    return nullptr;
  }
};

TEST_CASE("Curl::init() deals with curl_easy_init() failure") {
  MockedCurl curl;
  REQUIRE(curl.init() == false);
}

#endif  // HAVE_CURL
