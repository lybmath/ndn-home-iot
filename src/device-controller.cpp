#include "device-controller.hpp"
#include "logger.hpp"

#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/lp/tags.hpp>

namespace ndn {
namespace iot {

DeviceController::DeviceController(const std::string& pin, const Name& name)
  : Entity(name, true)
  , m_pin(pin)
  , m_faceMonitor(m_face)
{
  LOG_WELCOME("IoT Device Controller", m_name);
  registerCommandHandler("localhop", "probe-device",
			 bind(&DeviceController::handleProbe, this, _1, _2),
			 bind(&hmac::verifyInterest, _1, pin),
			 bind(&hmac::signData, _1, pin));
}

void
DeviceController::handleProbe(const ControlParameters& parameters,
			      const ReplyWithContent& done)
{
  if (!parameters.hasName()) {
    return done(ControlResponse(0, "prober name is missing").wireEncode());
  }
  
  auto filter = nfd::FaceQueryFilter()
    .setLinkType(nfd::LINK_TYPE_MULTI_ACCESS)
    .setFaceScope(nfd::FACE_SCOPE_NON_LOCAL);

  m_controller.fetch<nfd::FaceQueryDataset>(
    filter,
    bind(&DeviceController::makeProbeResponse, this, _1, done),
    [this, done] (uint32_t code, const std::string& reason) {
      done(ControlResponse(code, reason).wireEncode());
    });

  LOG_INFO("start monitor the face changes");
  m_faceMonitor.onNotification.connect(bind(&DeviceController::handleFaceCreation, this,
					    _1, parameters.getName()));
  m_faceMonitor.start();
}

void
DeviceController::handleFaceCreation(const nfd::FaceEventNotification& notification,
				     const Name& name)
{
  if (notification.getKind() == nfd::FACE_EVENT_CREATED &&
      notification.getFaceScope() != nfd::FACE_SCOPE_LOCAL &&
      notification.getFacePersistency() == nfd::FACE_PERSISTENCY_ON_DEMAND) {

      LOG_INFO("new notification of face creation: " << notification.getFaceId());
      m_createdFaces.push_back(notification.getFaceId());

      auto onFailure = [] (const nfd::ControlResponse& resp) {
	LOG_FAILURE("register route", "Error " << resp.getCode()
		    << " when registering rout to the created face: "
		    << resp.getText());
      };

      LOG_INFO("register " << name << "to face: " << notification.getFaceId());
      registerPrefixOnFace(name, notification.getFaceId(),
			   bind(&DeviceController::applyForCertificate, this,
				name, notification.getFaceId()),
			   onFailure);
    }  
}

void
DeviceController::applyForCertificate(const Name& name, uint64_t faceId)
{
  LOG_STEP(2, "apply certificate from " << name);
  
  security::Key key;
  try {
    key = m_identity.getDefaultKey();
  }
  catch (const security::Pib::Error&) {
    key = m_keyChain.createKey(m_identity);
  }

  auto prefix = Name(name).append("apply-cert").append(m_name);
  auto params = ControlParameters().setName(key.getName()).setKey(key.getPublicKey());

  issueCommand(makeCommand(prefix, params, bind(&hmac::signInterest, _1, m_pin)),
	       bind(&DeviceController::handleApplyResponse, this,
		    key.getName(), faceId, _1),
	       bind(&hmac::verifyData, _1, m_pin));
}

void
DeviceController::handleApplyResponse(const Name& keyName, uint64_t faceId,
				      const Block& content)
{
  try {
    security::v2::Certificate anchorCert(content.blockFromValue());
    LOG_INFO("receive the anchor cert: " << anchorCert.getName());

    registerPrefixOnFace(keyName, faceId,
			 bind(&DeviceController::requestCertificate, this,
			      keyName),
			 bind([] {
			     LOG_FAILURE("register route", "fail");
			   }));
 
  }
  catch (const tlv::Error& e) {
    LOG_FAILURE("cert", " fail to parse anchor " << e.what());
  }
}

void
DeviceController::requestCertificate(const Name& keyName)
{
  LOG_STEP(3, "request for AS signed certificate " << keyName);
  
  Interest interest(keyName);
  LOG_INTEREST_OUT(interest);
  
  m_face.expressInterest(interest,
			 [this, keyName] (const Interest&, const Data& data) {
			   auto key = m_identity.getKey(keyName);
			   security::v2::Certificate cert(data);
			   m_keyChain.setDefaultCertificate(key, cert);
			   LOG_INFO("new cert installed " << cert.getName());
			 },
			 [] (const Interest&, const lp::Nack& nack) {
			   std::cout << "install cert nack: "
				     << nack.getReason() << std::endl;
			 },
			 [] (const Interest&) {
			   std::cout << "intall cert timeout: " << std::endl;
			 });  
}

void
DeviceController::makeProbeResponse(const std::vector<nfd::FaceStatus>& dataset,
				    const ReplyWithContent& done)
{
  auto content = makeEmptyBlock(tlv::Content);
  content.push_back(m_name.wireEncode());
  content.push_back(packageAccessibleUris(dataset));

  content.encode();
  done(content);
}

Block
DeviceController::packageAccessibleUris(const std::vector<nfd::FaceStatus>& dataset)
{
  auto block = makeEmptyBlock(tlv::iot::DeviceUris);
  
  if (dataset.empty()) {
    this->fail("No faces available");
    return block;
  }

  for (const auto& faceStatus : dataset) {
    auto uri = faceStatus.getLocalUri();
    auto sub = uri.substr(0, uri.find_last_of(":"));
    if (sub != uri && sub.find(":") != std::string::npos) {
      uri = sub;
    }
    if (uri.find("udp") == 0) {
      uri.replace(0, 3, "tcp");
    }
    
    if (!sub.empty()) {
      block.push_back(makeStringBlock(tlv::iot::DeviceUri, uri));
    }
  }

  block.encode();
  return block;
}
  
void
DeviceController::onCertificateInterest(const Interest& interest)
{
  LOG_INTEREST_IN(interest);

  if (hmac::verifyInterest(interest, m_pin)) {
    LOG_FAILURE("cert", "can not verify interest with hmac " << interest.getName());
    return;
  }

  auto interestName = interest.getName();
  auto certBlock = interestName[m_name.size() + 2].blockFromValue();

  security::v2::Certificate cert(certBlock);
}

} // namespace iot
} // namespace ndn
