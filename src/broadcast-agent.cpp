#include "broadcast-agent.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>

namespace ndn {
namespace iot {

BroadcastAgent::BroadcastAgent(Face& face,
			       KeyChain& keyChain,
			       nfd::Controller& controller,
			       const FailureCallback& onFailure)
  : m_face(face)
  , m_keyChain(keyChain)
  , m_controller(controller)
  , m_onFailure(onFailure)
{
}

void
BroadcastAgent::registerTopPrefix(const Name& prefix,
				  const nfd::ControlParameters& params)
{
  // TODO check overlap
  nfd::FaceQueryFilter filter;
  filter.setLinkType(nfd::LINK_TYPE_MULTI_ACCESS);

  nfd::ControlParameters registerParameters = params;
  registerParameters
    .setName(prefix)
    .setCost(1)
    .setExpirationPeriod(time::milliseconds::max());
  
  m_controller.fetch<nfd::FaceQueryDataset>(
    filter,
    bind(&BroadcastAgent::registerPrefixToFaces, this, registerParameters, _1),
    m_onFailure);
}

void
BroadcastAgent::broadcast(const Interest& interest,
			  const DataCallback& cbOnData)
{
  auto onNack = [this] (const Interest& interest, const lp::Nack& nack) {
    std::cerr << interest.getName() << std::endl;
    std::cerr << "on nack broadcast: " << nack.getReason() << std::endl;
    m_onFailure(0, "on nack" + interest.getName().toUri());
  };
  auto onTimeout = [this] (const Interest& interest) {
    std::cerr << "on timeout for broadcast " << interest.getName() << std::endl;
    m_onFailure(0, "Time out when retrieving data by: " + interest.getName().toUri());
  };

  m_face.expressInterest(interest, cbOnData, onNack, onTimeout);
}

void
BroadcastAgent::registerPrefixToFaces(const nfd::ControlParameters& params,
				      const std::vector<nfd::FaceStatus>& dataset)
{
  if (dataset.empty()) {
    return m_onFailure(0, "No multi-access faces available");
  }

  m_nRegs = dataset.size();
  m_nRegSuccess = 0;
  m_nRegFailure = 0;

  Name prefix = params.getName();  
  for (const auto& faceStatus : dataset) {
    auto registerParameters = params;
    
    m_controller.start<nfd::RibRegisterCommand>(
      registerParameters.setFaceId(faceStatus.getFaceId()),
      [this, prefix] (const nfd::ControlParameters&) {
	++m_nRegSuccess;
        afterPrefixRegistration(prefix);
      },
      [this, prefix, faceStatus] (const nfd::ControlResponse& resp) {
	m_onFailure(resp.getCode(),
		  "fail in registering to " + faceStatus.getRemoteUri() + " " + resp.getText());
	++m_nRegFailure;
        afterPrefixRegistration(prefix);
      });
  }
}
  
void
BroadcastAgent::afterPrefixRegistration(const Name& prefix)
{
  if (m_nRegSuccess + m_nRegFailure < m_nRegs) {
    return; // continue waiting
  }
  if (m_nRegSuccess > 0) {
    this->setStrategy(prefix);
  }
  else {
    m_onFailure(0, "Cannot register prefix for any face");
  }  
}

void
BroadcastAgent::setStrategy(const Name& prefix)
{
  nfd::ControlParameters parameters;
  parameters
    .setName(prefix)
    .setStrategy("/localhost/nfd/strategy/multicast");
  
  m_controller.start<nfd::StrategyChoiceSetCommand>(
    parameters,
    bind([] {}),
    [this] (const nfd::ControlResponse& resp) {
      m_onFailure(resp.getCode(), " when setting multicast strategy: " + resp.getText());
    });  
}

} // namespace iot
} // namespace ndn
