#include "broadcast-agent.hpp"
#include "logger.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>

namespace ndn {
namespace iot {

BroadcastAgent::BroadcastAgent(Face& face,
			       KeyChain& keyChain,
			       nfd::Controller& controller)
  : m_face(face)
  , m_keyChain(keyChain)
  , m_controller(controller)
{
}

void
BroadcastAgent::registerTopPrefix(const Name& prefix,
				  const registerTopPrefixCallback& cbAfterRegistration)
{
  // TODO check overlap
  nfd::FaceQueryFilter filter;
  filter.setLinkType(nfd::LINK_TYPE_MULTI_ACCESS);

  nfd::ControlParameters registerParameters = nfd::ControlParameters()
    .setName(prefix)
    .setCost(1)
    .setExpirationPeriod(time::milliseconds::max());
  
  m_controller.fetch<nfd::FaceQueryDataset>(
    filter,
    bind(&BroadcastAgent::registerPrefixToFaces, this,
	 registerParameters, _1, cbAfterRegistration),
    [] (uint32_t code, const std::string& reason) {
      LOG_FAILURE("broadcast", "Error " << code << "when fetching multicast faces: " << reason);
    });
}

void
BroadcastAgent::broadcast(const Interest& interest,
			  const DataCallback& cbOnData,
			  const NackCallback& cbOnNack,
			  const TimeoutCallback& cbOnTimeout)
{
  m_face.expressInterest(interest, cbOnData, cbOnNack, cbOnTimeout);
  LOG_INTEREST_OUT(interest);
}

void
BroadcastAgent::registerPrefixToFaces(const nfd::ControlParameters& params,
				      const std::vector<nfd::FaceStatus>& dataset,
				      const registerTopPrefixCallback& cbAfterRegistration)
{
  if (dataset.empty()) {
    LOG_FAILURE("broadcast", "No multi-access face available");
    return;
  }

  m_nRegs = dataset.size();
  m_nRegSuccess = 0;
  m_nRegFailure = 0;

  Name prefix = params.getName();  
  for (const auto& faceStatus : dataset) {
    auto registerParameters = params;
    
    m_controller.start<nfd::RibRegisterCommand>(
      registerParameters.setFaceId(faceStatus.getFaceId()),
      [this, prefix, cbAfterRegistration] (const nfd::ControlParameters&) {
	++m_nRegSuccess;
        afterPrefixRegistration(prefix, cbAfterRegistration);
      },
      [this, prefix, faceStatus, cbAfterRegistration] (const nfd::ControlResponse& resp) {
	LOG_FAILURE("broadcast", "Error " << resp.getCode() << " in registering route to ["
		    << faceStatus.getRemoteUri() << "]: " << resp.getText());
	++m_nRegFailure;
        afterPrefixRegistration(prefix, cbAfterRegistration);
      });
  }
}
  
void
BroadcastAgent::afterPrefixRegistration(const Name& prefix,
					const registerTopPrefixCallback& cbAfterRegistration)
{
  if (m_nRegSuccess + m_nRegFailure < m_nRegs) {
    return; // continue waiting
  }
  if (m_nRegSuccess > 0) {
    this->setStrategy(prefix, cbAfterRegistration);
  }
  else {
    LOG_FAILURE("broadcast", "Cannot register prefix on any multicast face");
  }  
}

void
BroadcastAgent::setStrategy(const Name& prefix,
			    const registerTopPrefixCallback& cbAfterRegistration)
{
  nfd::ControlParameters parameters;
  parameters
    .setName(prefix)
    .setStrategy("/localhost/nfd/strategy/multicast");
  
  m_controller.start<nfd::StrategyChoiceSetCommand>(
    parameters,
    bind([cbAfterRegistration] {
	LOG_INFO("Multicast faces are ready");
	cbAfterRegistration();
      }),
    [this] (const nfd::ControlResponse& resp) {
      LOG_FAILURE("broadcast", "Error " << resp.getCode() << "when setting multicast strategy: "
		  << resp.getText())
    });  
}

} // namespace iot
} // namespace ndn
