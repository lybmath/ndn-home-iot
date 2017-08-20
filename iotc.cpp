#include <command-tool.hpp>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>

void
usage(std::ostream& os,
      const boost::program_options::options_description& desc,
      const char* programName)
{
  os << "Usage:\n"
     << "  " << programName << " --secret=<shared secret>\n"
     << "\n";
  os << desc;
}

int main(int argc, char** argv)
{
  namespace po = boost::program_options;
  po::options_description optionDesciption;

  std::string pinCode;
  optionDesciption.add_options()
      ("help,h", "produce help message")
      ("secret,s", po::value<std::string>(&pinCode),
       "the secret shared from some device to secure its bootstrap process")
      ("version,V", "show version and exit")
      ;

  po::variables_map options;
  try {
    po::store(po::command_line_parser(argc, argv).options(optionDesciption).run(), options);
    po::notify(options);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
    usage(std::cerr, optionDesciption, argv[0]);
    return 1;
  }

  if (options.count("help")) {
    usage(std::cout, optionDesciption, argv[0]);
    return 0;
  }

  if (options.count("version")) {
    std::cout << "1.0" << std::endl;
    return 0;
  }

  ndn::iot::CommandTool cmdTool;    
  cmdTool.issueCommand("/localhost/add-device",
			 ndn::iot::ControlParameters()
			   .setPinCode(pinCode),
			 [] (const ndn::iot::ControlResponse& resp) {
			   std::cerr << resp << std::endl;
			 });
  cmdTool.run();
  
  return 0;
}
