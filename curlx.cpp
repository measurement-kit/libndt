// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifdef HAVE_CURL

#include "curlx.hpp"

#include <assert.h>
#include <stdint.h>

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

}  // extern "C"

namespace measurement_kit {
namespace libndt {

#define EMIT_WARNING(client, statements)                 \
  do {                                                   \
    if (client->get_verbosity() >= verbosity::warning) { \
      std::stringstream ss;                              \
      ss << statements;                                  \
      client->on_warning(ss.str());                      \
    }                                                    \
  } while (0)

#define EMIT_INFO(client, statements)                 \
  do {                                                \
    if (client->get_verbosity() >= verbosity::info) { \
      std::stringstream ss;                           \
      ss << statements;                               \
      client->on_info(ss.str());                      \
    }                                                 \
  } while (0)

#define EMIT_DEBUG(client, statements)                 \
  do {                                                 \
    if (client->get_verbosity() >= verbosity::debug) { \
      std::stringstream ss;                            \
      ss << statements;                                \
      client->on_debug(ss.str());                      \
    }                                                  \
  } while (0)

void CurlDeleter::operator()(CURL *handle) noexcept {
  if (handle != nullptr) {
    curl_easy_cleanup(handle);
  }
}

Curl::Curl(Client *client) noexcept : client_{client} {
  assert(client != nullptr);
}

bool Curl::method_get_maybe_socks5(const std::string &proxy_port,
                                   const std::string &url, long timeout,
                                   std::string *body) noexcept {
  if (!init()) {
    EMIT_WARNING(client_, "curlx: cannot initialize cURL");
    return false;
  }
  if (!proxy_port.empty()) {
    std::stringstream ss;
    ss << "socks5h://127.0.0.1:" << proxy_port;
    if (setopt_proxy(ss.str()) != CURLE_OK) {
      EMIT_WARNING(client_, "curlx: cannot configure proxy: " << ss.str());
      return false;
    }
  }
  return method_get(url, timeout, body);
}

bool Curl::method_get(const std::string &url, long timeout,
                      std::string *body) noexcept {
  if (body == nullptr) {
    EMIT_WARNING(client_, "curlx: passed a nullptr body");
    return false;
  }
  std::stringstream ss;
  if (!init()) {
    EMIT_WARNING(client_, "curlx: cannot initialize cURL");
    return false;
  }
  if (setopt_url(url) != CURLE_OK) {
    EMIT_WARNING(client_, "curlx: cannot set URL: " << url);
    return false;
  }
  if (setopt_writefunction(curl_callback) != CURLE_OK) {
    EMIT_WARNING(client_, "curlx: cannot set callback function");
    return false;
  }
  if (setopt_writedata(&ss) != CURLE_OK) {
    EMIT_WARNING(client_, "curlx: cannot set callback function context");
    return false;
  }
  if (setopt_timeout(timeout) != CURLE_OK) {
    EMIT_WARNING(client_, "curlx: cannot set timeout");
    return false;
  }
  EMIT_INFO(client_, "curlx: performing request");
  auto rv = perform();
  if (rv != CURLE_OK) {
    EMIT_WARNING(client_, "curlx: cURL failed: " << curl_easy_strerror(rv));
    return false;
  }
  EMIT_INFO(client_, "curlx: request complete");
  *body = ss.str();
  return true;
}

bool Curl::init() noexcept {
  if (!!handle_) {
    return true; // make the method idempotent
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

CURLcode Curl::setopt_proxy(const std::string &url) noexcept {
  assert(handle_);
  return ::curl_easy_setopt(handle_.get(), CURLOPT_PROXY, url.c_str());
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
