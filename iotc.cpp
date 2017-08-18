#include <command-tool.hpp>

int main(int argc, char** argv)
{
  ndn::iot::CommandTool cmdTool;

  cmdTool.issueCommand("/localhost/add-device",
			 ndn::iot::ControlParameters()
			   .setPinCode("0123456789abcdef"),
			 [] (const ndn::iot::ControlResponse& resp) {
			   std::cerr << resp << std::endl;
			 });
  cmdTool.run();
  
  return 0;
}
