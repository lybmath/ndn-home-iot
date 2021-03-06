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
  BroadcastAgent(Face& face,
		 KeyChain& keyChain,
		 nfd::Controller& controller);

  typedef std::function<void(void)> registerTopPrefixCallback;
  
  void
  registerTopPrefix(const Name& prefix,
		    const registerTopPrefixCallback& cbAfterRegistration = [] {});

  void
  broadcast(const Interest& interest,
	    const DataCallback& cbOnData,
	    const NackCallback& cbOnNack,
	    const TimeoutCallback& cbOnTimeout);

private: 
  void
  registerPrefixToFaces(const nfd::ControlParameters& params,
			const std::vector<nfd::FaceStatus>& dataset,
			const registerTopPrefixCallback& cbAfterRegistration);

  void
  afterPrefixRegistration(const Name& prefix,
			  const registerTopPrefixCallback& cbAfterRegistration);

  void
  setStrategy(const Name& prefix,
	      const registerTopPrefixCallback& cbAfterRegistration);
  
private:
  Face& m_face;
  KeyChain& m_keyChain;
  nfd::Controller& m_controller;

  int m_nRegs = 0;
  int m_nRegSuccess = 0;
  int m_nRegFailure = 0;
};

} // namespace iot
} // namespace ndn

#endif // NDN_IOT_BROADCAST_AGENT_HPP
