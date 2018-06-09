# Measurement Kit NDT engine

[![GitHub license](https://img.shields.io/github/license/measurement-kit/libndt.svg)](https://raw.githubusercontent.com/measurement-kit/libndt/master/LICENSE) [![Github Releases](https://img.shields.io/github/release/measurement-kit/libndt.svg)](https://github.com/measurement-kit/libndt/releases) [![Build Status](https://img.shields.io/travis/measurement-kit/libndt/master.svg)](https://travis-ci.org/measurement-kit/libndt) [![Coverage Status](https://img.shields.io/coveralls/measurement-kit/libndt/master.svg)](https://coveralls.io/github/measurement-kit/libndt?branch=master) [![Build status](https://img.shields.io/appveyor/ci/bassosimone/libndt/master.svg)](https://ci.appveyor.com/project/bassosimone/libndt/branch/master) [![Documentation](https://codedocs.xyz/measurement-kit/libndt.svg)](https://codedocs.xyz/measurement-kit/libndt/)

This repository compiles a NDT engine that is meant to be integrated into
the build of Measurement Kit.

## Synopsis

This example runs a NDT download-only nettest with a nearby server:

```C++
#include <measurement_kit/libndt/libndt.hpp>

int main() {
  using namespace measurement_kit;
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

```
cmake .
cmake --build .
ctest -a --output-on-failure .
```
