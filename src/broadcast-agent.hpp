#ifndef NDN_IOT_BROADCAST_AGENT_HPP
#define NDN_IOT_BROADCAST_AGENT_HPP

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>
#include <ndn-cxx/mgmt/nfd/control-parameters.hpp>

#include <boost/function.hpp>
#include <unordered_map>

namespace ndn {
namespace iot {

class BroadcastAgent
{
public:
  typedef boost::function<void(uint32_t, const std::string&)> FailureCallback;
  
  BroadcastAgent(Face& face,
		 KeyChain& keyChain,
		 nfd::Controller& controller,
		 const FailureCallback& onFailure = bind([] {}));
  
  void
  registerTopPrefix(const Name& prefix,
		    const nfd::ControlParameters& params = nfd::ControlParameters());

  void
  broadcast(const Interest& interest,
	    const DataCallback& cbOnData);

private: 
  void
  registerPrefixToFaces(const nfd::ControlParameters& params,
			const std::vector<nfd::FaceStatus>& dataset);

  void
  afterPrefixRegistration(const Name& prefix);

  void
  setStrategy(const Name& prefix);
  
private:
  Face& m_face;
  KeyChain& m_keyChain;
  nfd::Controller& m_controller;
  const FailureCallback& m_onFailure;

  int m_nRegs = 0;
  int m_nRegSuccess = 0;
  int m_nRegFailure = 0;
};

} // namespace iot
} // namespace ndn

#endif // NDN_IOT_BROADCAST_AGENT_HPP
