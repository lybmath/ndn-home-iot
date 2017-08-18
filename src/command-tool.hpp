#ifndef NDN_IOT_COMMAND_TOOL_HPP
#define NDN_IOT_COMMAND_TOOL_HPP

#include "hmac-helper.hpp"
#include "control-parameters.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/mgmt/control-response.hpp>
#include <boost/asio/io_service.hpp>
#include <ndn-cxx/security/command-interest-signer.hpp>

namespace ndn {
namespace iot {

using mgmt::ControlResponse;

class CommandTool : public security::CommandInterestSigner
{
public:
  CommandTool();

public:
  typedef std::function<void(const ControlResponse& resp)> ResponseCallback;
  
  CommandTool&
  issueCommand(const Name& prefix, const ControlParameters& params,
	       const ResponseCallback& onResponse = bind([] {}));

  void
  run();

private:
  Interest
  makeCommand(Name name, const ControlParameters& params);
  
private:
  boost::asio::io_service m_ioService;
  Face m_face;
  KeyChain m_keyChain;  
};

} // namespace iot
} // namespace ndn

#endif // NDN_IOT_COMMAND_TOOL_HPP
