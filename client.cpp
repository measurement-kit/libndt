// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt.hpp"

#include <signal.h>
#include <stdlib.h>

#include <iostream>

#include "argh.h"

static void usage() {
  std::clog << "\n";
  std::clog << "Usage: client [options] <hostname>\n";
  std::clog << "\n";
  std::clog << "  --download            : run download test\n";
  std::clog << "  --download-ext        : run multi-stream download test\n";
  std::clog << "  --json                : use the JSON protocol\n";
  std::clog << "  --port <port>         : use the specified port\n";
  std::clog << "  --upload              : run upload test\n";
  std::clog << "  --verbose             : be verbose\n";
  std::clog << std::endl;
}

int main(int, char **argv) {
  using namespace measurement_kit;
  libndt::Client client;

  {
    argh::parser cmdline;
    cmdline.add_param("port");
    cmdline.parse(argv);
    for (auto &flag : cmdline.flags()) {
      if (flag == "download") {
        client.settings.test_suite |= libndt::nettest_download;
        std::clog << "will run download" << std::endl;
      } else if (flag == "download-ext") {
        client.settings.test_suite |= libndt::nettest_download_ext;
        std::clog << "will run download-ext" << std::endl;
      } else if (flag == "json") {
        client.settings.proto = libndt::NdtProtocol::proto_json;
        std::clog << "will use json" << std::endl;
      } else if (flag == "upload") {
        client.settings.test_suite |= libndt::nettest_upload;
        std::clog << "will run upload" << std::endl;
      } else if (flag == "verbose") {
        client.settings.verbosity = libndt::verbosity_debug;
        std::clog << "will be verbose" << std::endl;
      } else {
        std::clog << "fatal: unrecognized flag: " << flag << std::endl;
        usage();
        exit(EXIT_FAILURE);
      }
    }
    for (auto &param : cmdline.params()) {
      if (param.first == "port") {
        client.settings.port = param.second;
        std::clog << "will use port: " << param.second << std::endl;
      } else {
        std::clog << "fatal: unrecognized param: " << param.first << std::endl;
        usage();
        exit(EXIT_FAILURE);
      }
    }
    if (cmdline.pos_args().size() != 2) {
      std::clog << "fatal: missing mandatory nostname" << std::endl;
      usage();
      exit(EXIT_FAILURE);
    }
    client.settings.hostname = cmdline.pos_args()[1];
    std::clog << "will use host: " << cmdline.pos_args()[1] << std::endl;
  }

  // Make sure you ignore SIGPIPE because you're quite likely to receive
  // one at the end of the uploading phase of the NDT test.
  (void)signal(SIGPIPE, SIG_IGN);

  bool rv = client.run();
  return (rv) ? EXIT_SUCCESS : EXIT_FAILURE;
}
