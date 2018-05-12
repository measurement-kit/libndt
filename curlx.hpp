// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_LIBNDT_CURLX_HPP
#define MEASUREMENT_KIT_LIBNDT_CURLX_HPP
#ifdef HAVE_CURL

#include <memory>
#include <string>

#include <curl/curl.h>

namespace mk {
namespace libndt {

class CurlDeleter {
 public:
  void operator()(CURL *handle) noexcept;
};

class Curl {
 public:
  // Top-level API

  Curl() noexcept;

  bool init() noexcept;

  virtual CURLcode setopt_url(const std::string &url) noexcept;

  virtual CURLcode setopt_writefunction(size_t (*callback)(
      char *ptr, size_t size, size_t nmemb, void *userdata)) noexcept;

  virtual CURLcode setopt_writedata(void *pointer) noexcept;

  virtual CURLcode setopt_timeout(long timeout) noexcept;

  virtual CURLcode perform() noexcept;

  ~Curl() noexcept;

  // For testability:

  virtual CURL *easy_init() noexcept;

 private:
  std::unique_ptr<CURL, CurlDeleter> handle_;
};

}  // namespace libndt
}  // namespace mk
#endif  // HAVE_CURL
#endif  // MEASUREMENT_KIT_LIBNDT_CURLX_HPP
