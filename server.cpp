#include <authentication-server.hpp>

namespace ndn {
namespace iot {

int
main()
{
  ndn::iot::AuthenticationServer as("/home/as");
  as.run();
  return 0;
}

} // namespace iot
} // namespace ndn

int main(int argc, char** argv) {
  return ndn::iot::main();
}