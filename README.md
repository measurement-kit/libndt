# NDT Client Engine

[![GitHub license](https://img.shields.io/github/license/measurement-kit/libndt.svg)](https://raw.githubusercontent.com/measurement-kit/libndt/master/LICENSE) [![Github Releases](https://img.shields.io/github/release/measurement-kit/libndt.svg)](https://github.com/measurement-kit/libndt/releases) [![Build Status](https://img.shields.io/travis/measurement-kit/libndt/master.svg)](https://travis-ci.org/measurement-kit/libndt) [![Coverage Status](https://img.shields.io/coveralls/measurement-kit/libndt/master.svg)](https://coveralls.io/github/measurement-kit/libndt?branch=master) [![Build status](https://img.shields.io/appveyor/ci/bassosimone/libndt/master.svg)](https://ci.appveyor.com/project/bassosimone/libndt/branch/master) [![Documentation](https://codedocs.xyz/measurement-kit/libndt.svg)](https://codedocs.xyz/measurement-kit/libndt/)

`libndt` is a Network-Diagnostic-Tool (NDT) C++11 client engine.

## Synopsis

This example runs a NDT download-only nettest with a nearby server:

```C++
#include <libndt.hpp>

int main() {
  libndt::Client client;
  client.run();
}
```

See [codedocs.xyz/measurement-kit/libndt](
https://codedocs.xyz/measurement-kit/libndt/) for API documentation. See
[libndt-client.cpp](libndt-client.cpp) for a usage example. See
[libndt.hpp](libndt.hpp) for the full API.

## Clone

```
git clone --recursive https://github.com/measurement-kit/libndt
```

## Build and test

We use `cmake`. If you install `OpenSSL` library and headers, libndt will
have support for TLS based tests. If you install `cURL` library and headers,
libndt will perform server auto-discovery using the `mlab-ns` service.

(To see the exact dependencies required on Debian, you can see the content
of the [Dockerfile](.ci/docker/debian/Dockerfile) that we use to test
libndt in Travis-CI.)

```
cmake .
cmake --build .
ctest -a --output-on-failure .
./libndt-client
```
