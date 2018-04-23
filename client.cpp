// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libndt.hpp"

#include <signal.h>
#include <stdlib.h>

#include <iostream>
#include <sstream>

#include <curl/curl.h>

#include <argh.h>
#include <nlohmann/json.hpp>

static void usage() {
  std::clog << "\n";
  std::clog << "Usage: client [options] [<hostname>]\n";
  std::clog << "\n";
  std::clog << "  --download            : run download test\n";
  std::clog << "  --download-ext        : run multi-stream download test\n";
  std::clog << "  --json                : use the JSON protocol\n";
  std::clog << "  --port <port>         : use the specified port\n";
  std::clog << "  --upload              : run upload test\n";
  std::clog << "  --verbose             : be verbose\n";
  std::clog << "\n";
  std::clog << "If <hostname> is omitted, we pick a close-enough server.\n";
  std::clog << std::endl;
}

static size_t body_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
  if (nmemb <= 0) {
    return 0;  // This means "no body"
  }
  if (size > SIZE_MAX / nmemb) {
    std::clog << "fatal: unexpected sizes in cURL callback" << std::endl;
    return 0;
  }
  auto realsiz = size * nmemb;  // Overflow not possible (see above)
  auto ss = static_cast<std::stringstream *>(userdata);
  (*ss) << std::string{ptr, realsiz};
  return nmemb;
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
    auto sz = cmdline.pos_args().size();
    if (sz != 1 && sz != 2) {
      usage();
      exit(EXIT_FAILURE);
    }
    if (sz == 2) {
      client.settings.hostname = cmdline.pos_args()[1];
      std::clog << "will use host: " << cmdline.pos_args()[1] << std::endl;
    } else {
      std::clog << "will find a suitable server" << std::endl;
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

  // For this simple example, we use synchronous cURL to retrieve the
  // closest server from M-Lab's naming service (mlab-ns). In a real app
  // you probably want to use, at least, nonblocking cURL to do that.
  if (client.settings.hostname.empty()) {
    std::stringstream response_body;
    {
      CURL *curl = curl_easy_init();
      if (curl == nullptr) {
        std::clog << "fatal: curl_easy_init() failed" << std::endl;
        exit(EXIT_FAILURE);
      }
      std::clog << "cURL initialized" << std::endl;
      constexpr auto mlabns_url =
          "https://mlab-ns.appspot.com/ndt?policy=random";
      if (curl_easy_setopt(curl, CURLOPT_URL, mlabns_url) != CURLE_OK) {
        std::clog << "fatal: curl_easy_setopt(CURLOPT_URL, ...) failed"
                  << std::endl;
        curl_easy_cleanup(curl);
        exit(EXIT_FAILURE);
      }
      std::clog << "using mlab-ns URL: " << mlabns_url << std::endl;
      if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_cb) != CURLE_OK) {
        std::clog
            << "fatal: curl_easy_setopt(CURLOPT_WRITEFUNCTION, ...) failed"
            << std::endl;
        curl_easy_cleanup(curl);
        exit(EXIT_FAILURE);
      }
      std::clog << "configured write callback" << std::endl;
      if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body) !=
          CURLE_OK) {
        std::clog << "fatal: curl_easy_setopt(CURLOPT_WRITEDATA, ...) failed"
                  << std::endl;
        curl_easy_cleanup(curl);
        exit(EXIT_FAILURE);
      }
      std::clog << "configured write callback context" << std::endl;
      std::clog << "cURL-performing HTTP request..." << std::endl;
      auto rv = curl_easy_perform(curl);
      std::clog << "cURL-performing HTTP request... done" << std::endl;
      if (rv != CURLE_OK) {
        std::clog << "fatal: curl_easy_perform() failed: "
                  << curl_easy_strerror(rv) << std::endl;
        curl_easy_cleanup(curl);
        exit(EXIT_FAILURE);
      }
      curl_easy_cleanup(curl);
    }
    std::clog << "got this response body: " << response_body.str() << std::endl;
    nlohmann::json json;
    try {
      json = nlohmann::json::parse(response_body.str());
    } catch (const nlohmann::json::exception &) {
      std::clog << "fatal: nlohmann::json::parse() failed" << std::endl;
      exit(EXIT_FAILURE);
    }
    std::clog << "successfully parsed body as JSON" << std::endl;
    try {
      client.settings.hostname = json["fqdn"];
    } catch (const nlohmann::json::exception &) {
      std::clog << "fatal: cannot access JSON 'fqdn' field" << std::endl;
      exit(EXIT_FAILURE);
    }
    std::clog << "will use host: " << client.settings.hostname << std::endl;
  }

  bool rv = client.run();
  return (rv) ? EXIT_SUCCESS : EXIT_FAILURE;
}
