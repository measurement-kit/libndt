#include "ndt.hpp"

#include <iostream>

int main() {
  using namespace measurement_kit;
  libndt::Ndt ndt;
  //ndt.hostname = "127.0.0.1";
  ndt.hostname = "ndt.iupui.mlab2.trn01.measurement-lab.org";
  //ndt.hostname = "neubot.mlab.mlab2.trn01.measurement-lab.org";
  ndt.port = "3001";
  ndt.test_suite = libndt::nettest_download;
  //ndt.test_suite = libndt::nettest_download_ext;
  ndt.verbosity = libndt::verbosity_debug;
  auto rv = ndt.run();
  std::clog << std::boolalpha << rv << std::endl;
}
