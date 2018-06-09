// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt.hpp"

#include <signal.h>
#include <stdlib.h>

#include <iostream>
#include <sstream>

#include "argh.h"

static void usage() {
  std::clog << "\n";
  std::clog << "Usage: libndt-client [options] [<hostname>]\n";
  std::clog << "\n";
  std::clog << "  --download            : run download test\n";
  std::clog << "  --download-ext        : run multi-stream download test\n";
  std::clog << "  --json                : use the JSON protocol\n";
  std::clog << "  --port <port>         : use the specified port\n";
  std::clog << "  --upload              : run upload test\n";
  std::clog << "  --verbose             : be verbose\n";
  std::clog << "\n";
  std::clog << "If <hostname> is omitted, we pick a random server.\n";
  std::clog << std::endl;
}

int main(int, char **argv) {
  using namespace measurement_kit;
  libndt::Settings settings;
  settings.verbosity = libndt::verbosity::quiet;
  settings.test_suite = 0; // you need to enable tests explicitly

  {
    argh::parser cmdline;
    cmdline.add_param("port");
    cmdline.parse(argv);
    for (auto &flag : cmdline.flags()) {
      if (flag == "download") {
        settings.test_suite |= libndt::nettest::download;
        std::clog << "will run download" << std::endl;
      } else if (flag == "download-ext") {
        settings.test_suite |= libndt::nettest::download_ext;
        std::clog << "will run download-ext" << std::endl;
      } else if (flag == "json") {
        settings.proto = libndt::protocol::json;
        std::clog << "will use json" << std::endl;
      } else if (flag == "upload") {
        settings.test_suite |= libndt::nettest::upload;
        std::clog << "will run upload" << std::endl;
      } else if (flag == "verbose") {
        settings.verbosity = libndt::verbosity::debug;
        std::clog << "will be verbose" << std::endl;
      } else {
        std::clog << "fatal: unrecognized flag: " << flag << std::endl;
        usage();
        exit(EXIT_FAILURE);
      }
    }
    for (auto &param : cmdline.params()) {
      if (param.first == "port") {
        settings.port = param.second;
        std::clog << "will use port: " << param.second << std::endl;
      } else {
        std::clog << "fatal: unrecognized param: " << param.first << std::endl;
        usage();
        exit(EXIT_FAILURE);
      }
    }
    auto sz = cmdline.pos_args().size();
    if (sz != 1 && sz != 2) {
      usage();
      exit(EXIT_FAILURE);
    }
    if (sz == 2) {
      settings.hostname = cmdline.pos_args()[1];
      std::clog << "will use host: " << cmdline.pos_args()[1] << std::endl;
    } else {
      std::clog << "will find a suitable server" << std::endl;
      settings.mlabns_url += "?policy=random";
    }
  }

#ifndef _WIN32
  // Make sure you ignore SIGPIPE because you're quite likely to receive
  // one at the end of the uploading phase of the NDT test.
  (void)signal(SIGPIPE, SIG_IGN);
  std::clog << "will ignore any SIGPIPE signal" << std::endl;
#endif

#ifdef _WIN32
  {
    WORD requested = MAKEWORD(2, 2);
    WSADATA data;
    if (::WSAStartup(requested, &data) != 0) {
      std::clog << "fatal: WSAStartup() failed" << std::endl;
      exit(EXIT_FAILURE);
    }
    std::clog << "have initialized winsock v2.2." << std::endl;
  }
#endif

  libndt::Client client{settings};
  bool rv = client.run();
  return (rv) ? EXIT_SUCCESS : EXIT_FAILURE;
}
