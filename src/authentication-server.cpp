#include "authentication-server.hpp"
#include "logger.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace iot {

static const Name PROBE_DEVICE_PREFIX("/localhop/probe-device");
static const time::nanoseconds FACEURI_CANONIZE_TIMEOUT = time::milliseconds(100);

AuthenticationServer::AuthenticationServer(const Name& name)
  : Entity(name, true)
{
  LOG_WELCOME("Authentication Server", m_name);
  
  m_agent.registerTopPrefix(PROBE_DEVICE_PREFIX);

  registerCommandHandler("localhost", "add-device",
			 bind(&AuthenticationServer::addDevice, this, _1, _2));
}

void
AuthenticationServer::addDevice(const ControlParameters& params,
				const ReplyWithContent& done)
{
  if (params.hasName() || !params.hasPinCode()) {
    LOG_FAILURE("invalid parameters", "NO PIN CODE or NAME IS PRESENT");
    return done(ControlResponse(0, "invalid parameters for add dev").wireEncode());
  }

  LOG_STEP(1, "Probing the device who owns the pin code " << params.getPinCode());

  auto probeParameters = params;
  probeParameters.setName(m_name).unsetPinCode();

  auto command = makeCommand(PROBE_DEVICE_PREFIX, probeParameters,
			     bind(&hmac::signInterest, _1, params.getPinCode()));

  broadcast(command,
	    bind(&AuthenticationServer::handleProbeResponse,
		 this, _1, done, params.getPinCode()),
	    bind(&hmac::verifyData, _1, params.getPinCode()),
	    [done] (const std::string& reason) {
	      done(ControlResponse(1, reason).wireEncode());
	    });
}

void
AuthenticationServer::handleProbeResponse(const Block& content,
					  const ReplyWithContent& done,
					  const std::string& pin)
{
  LOG_INFO("Get probe response");
  
  Name devName;
  try {
    devName.wireDecode(content.get(tlv::Name));
  }
  catch (const tlv::Error& e) {
    return done(ControlResponse(2, e.what()).wireEncode());
  }

  try {
    auto devUris = content.get(tlv::iot::DeviceUris);
    devUris.parse();
    
    std::vector<std::string> availableUris;
    for (const auto& ele : devUris.elements()) {
      availableUris.push_back(readString(ele));
    }

    auto cbDeviceConnected = bind(&AuthenticationServer::afterConnectToDevice, this,
				  _1, devName, done);

    LOG_INFO("Try to create face toward the device" << devName);
    connectToDevice(availableUris, cbDeviceConnected, done);  
  }
  catch (const tlv::Error& e) {
    return done(ControlResponse(3, e.what()).wireEncode());
  }

  LOG_INFO("Be ready to certificate application from " << devName);
    
  // ready for cert application
  registerCommandHandler(Name(m_name).append("apply-cert"), devName,
			 bind(&AuthenticationServer::issueCertificate, this, _1, _2),
			 bind(&hmac::verifyInterest, _1, pin),
			 bind(&hmac::signData, _1, pin));
}

void
AuthenticationServer::connectToDevice(std::vector<std::string> pendingUris,
				      const CommandSucceedCallback& cbDeviceConnected,
				      const ReplyWithContent& done)
{
  if (pendingUris.empty()) {
    LOG_FAILURE("create face", "all provided uris are not accessible");
    return done(ControlResponse(4, "none device uris can be connected to!").wireEncode());
  }

  FaceUri uri(pendingUris.back());
  pendingUris.pop_back();

  LOG_INFO("Try " << uri);
  uri.canonize(bind(&AuthenticationServer::createFaceTowardDevice, this,
		    _1, pendingUris, cbDeviceConnected, done),
	       bind(&AuthenticationServer::connectToDevice, this,
		    pendingUris, cbDeviceConnected, done),
	       m_ioService, FACEURI_CANONIZE_TIMEOUT);
}

void
AuthenticationServer::createFaceTowardDevice(const FaceUri& canonicalUri,
					     std::vector<std::string> pendingUris,
					     const CommandSucceedCallback& cbDeviceConnected,
					     const ReplyWithContent& done)
{
  m_controller.start<nfd::FaceCreateCommand>(
    nfd::ControlParameters().setUri(canonicalUri.toString()),
    cbDeviceConnected,
    bind(&AuthenticationServer::afterCreateFaceFailed, this,
	 _1, pendingUris, cbDeviceConnected, done));
}

void
AuthenticationServer::afterCreateFaceFailed(const nfd::ControlResponse& resp,
					    std::vector<std::string> pendingUris,
					    const CommandSucceedCallback& cbDeviceConnected,
					    const ReplyWithContent& done)
{
  if (resp.getCode() == 409) {
    LOG_INFO("face already exists");
    cbDeviceConnected(nfd::ControlParameters(resp.getBody()));
  }
  else {
    connectToDevice(pendingUris, cbDeviceConnected, done);
  }  
}

void
AuthenticationServer::afterConnectToDevice(const nfd::ControlParameters& params,
					   const Name& name,
					   const ReplyWithContent& done)
{
  LOG_INFO("register device name " << name << " on created face: "
	   << params.getUri() << " ( " << params.getFaceId() << " )");
  
  m_createdFaces.push_back(params.getFaceId());
  
  registerPrefixOnFace(name, params.getFaceId(),
		       [done] (const nfd::ControlParameters&) {
			 LOG_INFO("registration succeeds")
			 done(ControlResponse(200, "ok").wireEncode());
		       },
		       [done, params] (const nfd::ControlResponse& resp) {
			 LOG_FAILURE("register dev name", "Error "
				     << resp.getCode()
				     << "for face " << params.getFaceId()
				     << " (" << params.getUri()
				     << "): " << resp.getText());
			 done(resp.wireEncode());
		       });
}

void
AuthenticationServer::issueCertificate(const ControlParameters& params,
				       const ReplyWithContent& done)
{
  if (!params.hasName() || !params.hasKey()) {
    return done(ControlResponse(0, "invalid parameters for issueCert").wireEncode());
  }
  
  auto anchorCert = getDefaultCertificate();
  auto newCert = generateDeviceCertificate(params.getName(), params.getKey(), anchorCert);

  // std::cout << anchorCert << std::endl;
  // std::cout << newCert << std::endl;
  
  //publishCertificate(anchorCert);
  LOG_INFO("Publish certificate in local memory " << params.getName());
  publishCertificate(params.getName(), newCert);

  LOG_INFO("Reply anchor certificate to the device " << anchorCert.getName());
  done(anchorCert.wireEncode());
  
  //auto content = makeEmptyBlock(tlv::Content);
  //content.push_back(Block(tlv::iot::TrustAnchor, anchorCert.wireEncode()));
  //content.push_back(Block(tlv::iot::Certificate, newCert.wireEncode()));
}

security::v2::Certificate
AuthenticationServer::generateDeviceCertificate(const Name& keyName, const Block& pubKey,
						const security::v2::Certificate& anchor)
{
  LOG_INFO("Generate a certificate for " << keyName);
  Name certName = Name(keyName).append("NDNCERT").appendVersion();

  security::v2::Certificate newCert;
  newCert.setName(certName);

  try {
    auto content = makeBinaryBlock(tlv::Content, pubKey.value(), pubKey.value_size());  
    newCert.setContent(content);

    SignatureInfo signatureInfo;
    signatureInfo.setValidityPeriod(anchor.getValidityPeriod());
  
    auto signingInfo = security::signingByCertificate(anchor);
    signingInfo.setSignatureInfo(signatureInfo);
    
    m_keyChain.sign(newCert, signingInfo);
  }
  catch (const SignatureInfo::Error& e) {
    LOG_FAILURE("sig", e.what());
  }
  catch (const tlv::Error& e) {
    LOG_FAILURE("tlv", e.what());
  }

  return newCert;
}
  

} // namespace iot
} // namespace ndn
