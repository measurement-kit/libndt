# Measurement Kit NDT engine

[![GitHub license](https://img.shields.io/github/license/measurement-kit/libndt.svg)](https://raw.githubusercontent.com/measurement-kit/libndt/master/LICENSE) [![Github Releases](https://img.shields.io/github/release/measurement-kit/libndt.svg)](https://github.com/measurement-kit/libndt/releases) [![Build Status](https://img.shields.io/travis/measurement-kit/libndt/master.svg)](https://travis-ci.org/measurement-kit/libndt) [![Coverage Status](https://img.shields.io/coveralls/measurement-kit/libndt/master.svg)](https://coveralls.io/github/measurement-kit/libndt?branch=master) [![Build status](https://img.shields.io/appveyor/ci/bassosimone/libndt/master.svg)](https://ci.appveyor.com/project/bassosimone/libndt/branch/master)

This repository compiles a NDT engine that is meant to be integrated into
the build of Measurement Kit.

## Synopsis

```C++
#include "libndt.hpp"

namespace measurement_kit {
namespace libndt {

constexpr uint64_t api_major = 0;
constexpr uint64_t api_minor = 20;
constexpr uint64_t api_patch = 1;

constexpr uint8_t nettest_middlebox = 1 << 0;
constexpr uint8_t nettest_upload = 1 << 1;
constexpr uint8_t nettest_download = 1 << 2;
constexpr uint8_t nettest_simple_firewall = 1 << 3;
constexpr uint8_t nettest_status = 1 << 4;
constexpr uint8_t nettest_meta = 1 << 5;
constexpr uint8_t nettest_upload_ext = 1 << 6;
constexpr uint8_t nettest_download_ext = 1 << 7;

constexpr const char *ndt_version_compat = "v3.7.0";

constexpr uint64_t verbosity_quiet = 0;
constexpr uint64_t verbosity_warning = 1;
constexpr uint64_t verbosity_info = 2;
constexpr uint64_t verbosity_debug = 3;

constexpr double default_max_runtime = 14.0 /* seconds */;

enum class NdtProtocol {
  proto_legacy = 0,
  proto_json = 1
};

class NdtSettings {
 public:
  std::string mlabns_url = "https://mlab-ns.appspot.com/ndt";
  long curl_timeout = 3 /* seconds */;
  std::string hostname;
  std::string port = "3001";
  uint8_t test_suite = 0;
  uint64_t verbosity = verbosity_info;
  std::map<std::string, std::string> metadata{
      {"client.version", ndt_version_compat},
      {"client.application", "measurement-kit/libndt"},
  };
  NdtProtocol proto = NdtProtocol::proto_legacy;
  double max_runtime = default_max_runtime;
};

class Client {
 public:
  NdtSettings settings;

  bool run() noexcept;

  virtual void on_warning(const std::string &s) noexcept;

  virtual void on_info(const std::string &s) noexcept;

  virtual void on_debug(const std::string &s) noexcept;

  virtual void on_performance(uint8_t tid, uint8_t nflows,
                              uint64_t measured_bytes,
                              double measurement_interval, double elapsed,
                              double max_runtime) noexcept;

  virtual void on_result(std::string scope, std::string name,
                         std::string value) noexcept;

  virtual void on_server_busy(std::string msg) noexcept;

  virtual int select(int numfd, fd_set *readset, fd_set *writeset,
                     fd_set *exceptset, timeval *timeout) noexcept;
};

}  // namespace libndt
}  // namespace measurement_kit
```

To run a NDT test, create a `Client` instance, configure its `settings`, and
then call `run()`. Measurement Kit will override the `virtual` methods
above to gather logs, and results, and allow to interrupt tests. See
[example_client.cpp](example_client.cpp).

## Clone

```
git clone --recursive https://github.com/measurement-kit/libndt
```

## Build and test

```
cmake .
cmake --build .
ctest -a --output-on-failure .
```
