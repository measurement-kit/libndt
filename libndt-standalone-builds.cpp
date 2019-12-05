// The purpose of this file is to make sure the standalone
// header is building. We're now using the individual headers
// elsewhere, and specifically "impl.hpp", such that it's
// significantly simpler to do development.
#include "json.hpp"
#include "libndt.hpp"
int main() {
  measurement_kit::libndt::Client client{
    measurement_kit::libndt::Settings{}
  };
  client.run();
}
