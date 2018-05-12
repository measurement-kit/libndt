// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifdef HAVE_CURL

#include "curlx.hpp"

#include <assert.h>

namespace mk {
namespace libndt {

void CurlDeleter::operator()(CURL *handle) noexcept {
  if (handle != nullptr) {
    curl_easy_cleanup(handle);
  }
}

Curl::Curl() noexcept {}

bool Curl::init() noexcept {
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
}  // namespace mk
#endif  // HAVE_CURL
