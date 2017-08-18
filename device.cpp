#include <device-controller.hpp>

int main(int argc, char** argv)
{
  ndn::iot::DeviceController controller("0123456789abcdef", "/home/dev1");
  controller.run();
  return 0;
}
