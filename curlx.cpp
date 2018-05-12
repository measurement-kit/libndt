// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifdef HAVE_CURL

#include "curlx.hpp"

#include <assert.h>

#include <sstream>

extern "C" {

static size_t curl_callback(char *ptr, size_t size, size_t nmemb,
                            void *userdata) {
  if (nmemb <= 0) {
    return 0;  // This means "no body"
  }
  if (size > SIZE_MAX / nmemb) {
    assert(false);  // Also catches case where size is zero
    return 0;
  }
  auto realsiz = size * nmemb;  // Overflow not possible (see above)
  auto ss = static_cast<std::stringstream *>(userdata);
  (*ss) << std::string{ptr, realsiz};
  // From fwrite(3): "[the return value] equals the number of bytes
  // written _only_ when `size` equals `1`".
  return nmemb;
}

} // extern "C"

namespace measurement_kit {
namespace libndt {

void CurlDeleter::operator()(CURL *handle) noexcept {
  if (handle != nullptr) {
    curl_easy_cleanup(handle);
  }
}

Curl::Curl() noexcept {}

bool Curl::method_get(const std::string &url, long timeout,
                      std::string *body, std::string *err) noexcept {
  if (body == nullptr || err == nullptr) {
    return false;
  }
  std::stringstream ss;
  if (!init()) {
    *err = "cannot initialize cURL";
    return false;
  }
  if (setopt_url(url) != CURLE_OK) {
    *err = "cannot set URL";
    return false;
  }
  if (setopt_writefunction(curl_callback) != CURLE_OK) {
    *err = "cannot set write callback";
    return false;
  }
  if (setopt_writedata(&ss) != CURLE_OK) {
    *err = "cannot set write callback opaque context";
    return false;
  }
  if (setopt_timeout(timeout) != CURLE_OK) {
    *err = "cannot set timeout";
    return false;
  }
  auto rv = perform();
  if (rv != CURLE_OK) {
    *err = curl_easy_strerror(rv);
    return false;
  }
  *err = "";
  *body = ss.str();
  return true;
}

bool Curl::init() noexcept {
  if (!!handle_) {
    return false;
  }
  auto handle = this->easy_init();
  if (!handle) {
    return false;
  }
  handle_.reset(handle);
  return true;
}

CURLcode Curl::setopt_url(const std::string &url) noexcept {
  assert(handle_);
  return ::curl_easy_setopt(handle_.get(), CURLOPT_URL, url.c_str());
}

CURLcode Curl::setopt_writefunction(size_t (*callback)(
    char *ptr, size_t size, size_t nmemb, void *userdata)) noexcept {
  assert(handle_);
  return ::curl_easy_setopt(handle_.get(), CURLOPT_WRITEFUNCTION, callback);
}

CURLcode Curl::setopt_writedata(void *pointer) noexcept {
  assert(handle_);
  return ::curl_easy_setopt(handle_.get(), CURLOPT_WRITEDATA, pointer);
}

CURLcode Curl::setopt_timeout(long timeout) noexcept {
  assert(handle_);
  return ::curl_easy_setopt(handle_.get(), CURLOPT_TIMEOUT, timeout);
}

CURLcode Curl::perform() noexcept {
  assert(handle_);
  return ::curl_easy_perform(handle_.get());
}

Curl::~Curl() noexcept {}

CURL *Curl::easy_init() noexcept { return ::curl_easy_init(); }

}  // namespace libndt
}  // namespace measurement_kit
#endif  // HAVE_CURL
