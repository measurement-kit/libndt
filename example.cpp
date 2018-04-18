#include "ndt.hpp"

#include <signal.h>

#include <iostream>

int main() {
  (void)signal(SIGPIPE, SIG_IGN);
  using namespace measurement_kit;
  libndt::Ndt ndt;
  //ndt.settings.hostname = "127.0.0.1";
  ndt.settings.hostname = "ndt.iupui.mlab2.trn01.measurement-lab.org";
  //ndt.settings.hostname = "neubot.mlab.mlab2.trn01.measurement-lab.org";
  ndt.settings.port = "3001";
  ndt.settings.test_suite = libndt::nettest_download|libndt::nettest_upload;
  //ndt.settings.test_suite = libndt::nettest_download_ext;
  ndt.settings.verbosity = libndt::verbosity_debug;
  auto rv = ndt.run();
  std::clog << std::boolalpha << rv << std::endl;
}
