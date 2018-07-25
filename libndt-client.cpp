// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt.hpp"

#include <stdlib.h>

#include <iostream>
#include <sstream>

#include "argh.h"

static void usage() {
  // clang-format off
  std::clog << "\n";
  std::clog << "Usage: libndt-client [options] [<hostname>]\n";
  std::clog << "\n";
  std::clog << "  --ca-bundle-path <path> : path to OpenSSL CA bundle\n";
  std::clog << "  --download              : run download test\n";
  std::clog << "  --download-ext          : run multi-stream download test\n";
  std::clog << "  --insecure              : if --tls is specified, disable any kind of\n";
  std::clog << "                            TLS peer validation. This is insecure, hence\n";
  std::clog << "                            the flag name, but useful for testing.\n";
  std::clog << "  --json                  : use the JSON protocol\n";
  std::clog << "  --port <port>           : use the specified port\n";
  std::clog << "  --random                : if hostname is omitted, then use\n";
  std::clog << "                            a random NDT server.\n";
  std::clog << "  --tls                   : use transport layer security\n";
  std::clog << "  --socks5h <port>        : use socks5h proxy at 127.0.0.1:<port>\n";
  std::clog << "  --upload                : run upload test\n";
  std::clog << "  --verbose               : be verbose\n";
  std::clog << "  --websocket             : use the WebSocket protocol\n";
  std::clog << "\n";
  std::clog << "If <hostname> is omitted, we pick a nearby server, unless `--random'\n";
  std::clog << "is specified, in which case we pick a random server.\n";
  std::clog << std::endl;
  // clang-format on
}

int main(int, char **argv) {
  libndt::Settings settings;
  settings.verbosity = libndt::verbosity_quiet;
  // You need to enable tests explicitly:
  settings.nettest_flags = libndt::NettestFlags{0};

  {
    argh::parser cmdline;
    cmdline.add_param("ca-bundle-path");
    cmdline.add_param("port");
    cmdline.add_param("socks5h");
    cmdline.parse(argv);
    for (auto &flag : cmdline.flags()) {
      if (flag == "download") {
        settings.nettest_flags |= libndt::nettest_flag_download;
        std::clog << "will run download" << std::endl;
      } else if (flag == "download-ext") {
        settings.nettest_flags |= libndt::nettest_flag_download_ext;
        std::clog << "will run download-ext" << std::endl;
      } else if (flag == "insecure") {
        settings.tls_verify_peer = false;
        std::clog << "WILL NOT verify the TLS peer (INSECURE!)" << std::endl;
      } else if (flag == "json") {
        settings.protocol_flags |= libndt::protocol_flag_json;
        std::clog << "will use json" << std::endl;
      } else if (flag == "random") {
        settings.mlabns_policy = libndt::mlabns_policy_random;
        std::clog << "will use a random server" << std::endl;
      } else if (flag == "tls") {
        settings.protocol_flags |= libndt::protocol_flag_tls;
        std::clog << "will use TLS" << std::endl;
      } else if (flag == "upload") {
        settings.nettest_flags |= libndt::nettest_flag_upload;
        std::clog << "will run upload" << std::endl;
      } else if (flag == "verbose") {
        settings.verbosity = libndt::verbosity_debug;
        std::clog << "will be verbose" << std::endl;
      } else if (flag == "websocket") {
        settings.protocol_flags |= libndt::protocol_flag_websocket;
        std::clog << "will use WebSockets" << std::endl;
      } else {
        std::clog << "fatal: unrecognized flag: " << flag << std::endl;
        usage();
        exit(EXIT_FAILURE);
      }
    }
    for (auto &param : cmdline.params()) {
      if (param.first == "ca-bundle-path") {
        settings.ca_bundle_path = param.second;
        std::clog << "will use CA bundle path: " << param.second << std::endl;
      } else if (param.first == "port") {
        settings.port = param.second;
        std::clog << "will use port: " << param.second << std::endl;
      } else if (param.first == "socks5h") {
        settings.socks5h_port = param.second;
        std::clog << "will use socks5h proxy at: 127.0.0.1:" << param.second
                  << std::endl;
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
    }
  }

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
