#include "command-tool.hpp"

namespace ndn {
namespace iot {

CommandTool::CommandTool()
  : CommandInterestSigner(m_keyChain)
  , m_face(m_ioService)
{
}

void
CommandTool::run()
{
  m_face.processEvents();
}

CommandTool&
CommandTool::issueCommand(const Name& prefix, const ControlParameters& params,
			  const ResponseCallback& onResponse)
{
  m_face.expressInterest(makeCommand(prefix, params),
			 [onResponse] (const Interest&, const Data& data) {
			   ControlResponse resp; 
			   try {
			     resp.wireDecode(data.getContent().blockFromValue());
			   }
			   catch (const tlv::Error& e) {
			     resp = ControlResponse(0, "Parse Data error");
			   }
			   onResponse(resp);
			 },
			 [onResponse] (const Interest&, const lp::Nack& nack) {
			   onResponse(ControlResponse(0, "Nack"));
			 },
			 [onResponse] (const Interest&) {
			   onResponse(ControlResponse(0, "Timeout"));
			 }
			 );
}

Interest
CommandTool::makeCommand(Name name, const ControlParameters& params)
{
  return makeCommandInterest(name.append(params.wireEncode()));
}
  
} // namespace iot
} // namespace ndn
