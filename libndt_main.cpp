#include "libndt.hpp"

#include <signal.h>

#include <iostream>

int main() {
  (void)signal(SIGPIPE, SIG_IGN);
  using namespace measurement_kit;
  libndt::Client client;
  //client.settings.hostname = "127.0.0.1";
  client.settings.hostname = "ndt.iupui.mlab2.trn01.measurement-lab.org";
  //client.settings.hostname = "neubot.mlab.mlab2.trn01.measurement-lab.org";
  client.settings.port = "3001";
  client.settings.test_suite = libndt::nettest_upload;
  //client.settings.test_suite = libndt::nettest_download|libndt::nettest_upload;
  //client.settings.test_suite = libndt::nettest_download_ext;
  client.settings.verbosity = libndt::verbosity_debug;
  auto rv = client.run();
  std::clog << std::boolalpha << rv << std::endl;
}
