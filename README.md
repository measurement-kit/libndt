# NDT Client Engine

[![GitHub license](https://img.shields.io/github/license/measurement-kit/libndt.svg)](https://raw.githubusercontent.com/measurement-kit/libndt/master/LICENSE) [![Github Releases](https://img.shields.io/github/release/measurement-kit/libndt.svg)](https://github.com/measurement-kit/libndt/releases) [![Build Status](https://img.shields.io/travis/measurement-kit/libndt/master.svg?label=travis)](https://travis-ci.org/measurement-kit/libndt) [![codecov](https://codecov.io/gh/measurement-kit/libndt/branch/master/graph/badge.svg)](https://codecov.io/gh/measurement-kit/libndt) [![Build status](https://img.shields.io/appveyor/ci/bassosimone/libndt/master.svg?label=appveyor)](https://ci.appveyor.com/project/bassosimone/libndt/branch/master) [![Documentation](https://codedocs.xyz/measurement-kit/libndt.svg)](https://codedocs.xyz/measurement-kit/libndt/)

Libndt is a [Network-Diagnostic-Tool](
https://github.com/ndt-project/ndt/wiki/NDTProtocol) (NDT) single-include
C++11 client library. NDT is a widely used network performance test that
measures the download and upload speed, and complements these measurements
with kernel-level measurements. NDT is the most popular network performance
test hosted by [Measurement Lab](https://www.measurementlab.net/).

## Getting started

Make sure you download [nlohmann/json](https://github.com/nlohmann/json)
single include header [json.hpp](
https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp)
before proceeding. The minimum supported version is v3.0.0. Put `json.hpp`
in the current working directory.

Then, download [libndt.hpp](
https://github.com/measurement-kit/libndt/blob/master/libndt.hpp) and
put it in the current working directory.

This example runs a NDT download-only nettest with a nearby server. Create
a file named `main.cpp` with this content.

```C++
#include "json.hpp"  // MUST be included before libndt
#include "libndt.hpp"

int main() {
  using namespace measurement_kit;
  libndt::Client client;
  client.run();
}
```

Compile with `g++ -std=c++11 -Wall -Wextra -I. -o main main.cpp`.

Libndt optionally depends on OpenSSL (for TLS support and in the future for
WebSocket support) and cURL (to autodiscover servers). You can use the following
preprocessor macros to tell libndt that such dependencies are available:

- `LIBNDT_HAVE_OPENSSL`: just define this macro to use OpenSSL (it does not
  matter whether the macro is defined to a true or false value);

- `LIBNDT_HAVE_CURL`: just define to use cURL (likewise).

If these dependencies are not installed in canonical locations, make sure you
add the pass the compiler the proper flags.

See [codedocs.xyz/measurement-kit/libndt](
https://codedocs.xyz/measurement-kit/libndt/) for API documentation;
[libndt.hpp](libndt.hpp) for the full API.

See [libndt-client.cpp](libndt-client.cpp) for a comprehensive usage example.

## Cloning the repository

To develop libndt or run tests, you need a clone of the repository. Make sure
you pass the `--recursive` flag to properly fetch all sub-repositories.

```
git clone --recursive https://github.com/measurement-kit/libndt
```

## Building and testing

We use CMake for building libndt for testing. CMake will search for OpenSSL
and cURL, defining the above described macros if they are found. CMake also
downloads a recent version of nlohmann/json and puts it in the current
directory, so you do not have to worry about this aspect.

To see the exact dependencies required on Debian, please check out the
[Dockerfile](https://github.com/measurement-kit/docker-ci/blob/master/debian/Dockerfile)
used when testing in Travis-CI.

Build and run tests with:

```
cmake .
cmake --build .
ctest -a --output-on-failure .
```

## Command line client 

Building with CMake also builds a simple command line client. Get usage info
by running:

```
./libndt-client -help
```
