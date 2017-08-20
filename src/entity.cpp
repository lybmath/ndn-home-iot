#include "entity.hpp"
#include "logger.hpp"
#include <ndn-cxx/lp/tags.hpp>
#include <algorithm>

namespace ndn {
namespace iot {

static const time::milliseconds COMMAND_INTEREST_LIFETIME = time::seconds(4);

Entity::Entity(const Name& name,
	       bool keepRunning)
  : m_face(m_ioService)
  , m_controller(m_face, m_keyChain)
  , m_agent(m_face, m_keyChain, m_controller)
  , m_storage(m_ioService, 10)
  , m_scheduler(m_ioService)
  , m_terminationSignalSet(m_ioService)
  , m_name(name)
{
  m_identity = m_keyChain.createIdentity(m_name);
  
  if (keepRunning) {
    m_terminationSignalSet.add(SIGINT);
    m_terminationSignalSet.add(SIGTERM);
    m_terminationSignalSet.async_wait(bind(&Entity::terminate, this, _1, _2));
  }

  m_handlerMaps.clear();
  if (!globalPacketFile.is_open()) {
    globalPacketFile.open("packet.out", std::ios::out | std::ios::binary);
  }
}

void
Entity::terminate(const boost::system::error_code& error, int signalNo)
{
  if (error)
    return;

  LOG_BYEBYE(m_name, "WITH " << ::strsignal(signalNo) << " CAUGHT");

  for (const auto& faceId : m_createdFaces) {
    auto params = nfd::ControlParameters();
    m_controller.start<nfd::FaceDestroyCommand>(params.setFaceId(faceId),
						bind([] {}), bind([] {}));  
  }

  if (globalPacketFile.is_open()) {
    globalPacketFile.close();
  }
  
  m_ioService.poll();
  m_ioService.stop();
}

Interest
Entity::makeCommand(Name name, const ControlParameters& params,
		    const InterestSigner& sign)
{
  auto interestName = prepareCommandInterestName(name.append(params.wireEncode()));
  auto interest = Interest(interestName);

  sign(interest, m_keyChain);

  interest.setInterestLifetime(COMMAND_INTEREST_LIFETIME);
  interest.setMustBeFresh(true);

  return interest;
}

void
Entity::issueCommand(const Interest& command,
		     const ResponseHandler& handler,
		     const Verification& verify)
{

  auto onFailure = [this] (const std::string& reason) {
    LOG_FAILURE("command", " faile with " << reason);
  };

  LOG_INTEREST_OUT(command);
  m_face.expressInterest(command,
			 bind(&Entity::verifyResponse, this, _1, _2,
			      verify, onFailure, handler),
			 [this] (const Interest&, const lp::Nack& nack) {
			   LOG_FAILURE("command", " nack " << nack.getReason());
			 },
			 [this] (const Interest&) {
			   LOG_FAILURE("command", " timeout ");
			 });     
}

void
Entity::registerCommandHandler(const Name& prefix, const Name& subPrefix,
			       const CommandHandler& handler,
			       SecurityOptions options)
{
  InterestCallback onInterest = bind(&Entity::authorizeRequester, this, _2,
				     handler, options);
  auto name = Name(prefix).append(subPrefix);

  if (!m_handlerMaps[prefix]) {
    m_handlerMaps[prefix] = true;
    m_face.registerPrefix(prefix,
			  bind([name] {}),
			  bind([name] { LOG_FAILURE("command", "fail to register " << name); }));
  }

  m_face.setInterestFilter(name, onInterest);
}

void
Entity::authorizeRequester(const Interest& interest,
			   const CommandHandler& handler,
			   SecurityOptions options)
{
  LOG_INTEREST_IN(interest);

  if (options.getVerificationOption() == SecurityOptions::NOT_SET) {
    return afterAuthorization(interest, handler, options);
  }

  if (options.getVerificationOption() & SecurityOptions::HMAC) {
    if (hmac::verifyInterest(interest, options.getPinCode())) {
      options.setVerificationType(SecurityOptions::HMAC);
      return afterAuthorization(interest, handler, options);
    }
  }

  verifyInterestByKey(interest, options,
		      bind(&Entity::afterAuthorization, this, interest, handler, _1));
}

void
Entity::verifyInterestByKey(const Interest& interest,
			    SecurityOptions options,
			    const AuthorizationCallback& cbAfterAuthorization)
{
  Name klName;
  if (!getKeyLocatorName(interest, klName)) {
    LOG_FAILURE("command", "can not get kl name " << klName);
    return;
  }

  if (m_certificates.empty()) {
    LOG_DBG("no trust anchor to verify this request");
    return;    
  }

  if (m_certificates.find(klName) != m_certificates.end()) {
    options.setVerificationType(SecurityOptions::IDENTITY);
    cbAfterAuthorization(options);
    return;
  }

  DataCallback onData = bind(&Entity::verifyDataByKey, this, _2, options, cbAfterAuthorization);
  NackCallback onNack = [klName] (const Interest&, const lp::Nack& nack) {
    LOG_FAILURE("verify by key", "Nack (" << nack.getReason() << ") on fetching cert " << klName);
  };
  TimeoutCallback onTimeout = [klName] (const Interest&) {
    LOG_FAILURE("verify by key", "Timeout on fetching cert " << klName);
  };
  
  m_face.expressInterest(Interest(klName), onData, onNack, onTimeout);
}

void
Entity::verifyDataByKey(const Data& data,
			SecurityOptions options,
			const AuthorizationCallback& cbAfterAuthorization)
{
  LOG_DATA_IN(data);

  Name klName;
  if (!getKeyLocatorName(data, klName)) {
    LOG_FAILURE("command", "can not get kl name " << klName);
    return;
  }

  if (m_certificates.empty()) {
    LOG_DBG("no trust anchor to verify this request");
    return;    
  }

  if (m_certificates.find(klName) != m_certificates.end()) {
    options.setVerificationType(SecurityOptions::IDENTITY);
    cbAfterAuthorization(options);
    return;
  }

  DataCallback onData = bind(&Entity::verifyDataByKey, this, _2, options, cbAfterAuthorization);
  NackCallback onNack = [klName] (const Interest&, const lp::Nack& nack) {
    LOG_FAILURE("verify by key", "Nack (" << nack.getReason() << ") on fetching cert " << klName);
  };
  TimeoutCallback onTimeout = [klName] (const Interest&) {
    LOG_FAILURE("verify by key", "Timeout on fetching cert " << klName);
  };
  
  m_face.expressInterest(Interest(klName), onData, onNack, onTimeout);
}

void
Entity::afterAuthorization(const Interest& interest,
			   const CommandHandler& handler,
			   SecurityOptions options)
{
  try {
    auto params = ControlParameters::fromCommandInterest(interest);
    handler(params, bind(&Entity::replyRequest, this, interest, options, _1), options);
  }
  catch (const ControlParameters::Error& e) {
    LOG_FAILURE("command", "can not parse the parameters: " << e.what());
  } 
}

void
Entity::replyRequest(const Interest& interest,
		     SecurityOptions options,
		     const Block& content)
{
  auto data = make_shared<Data>(Name(interest.getName()).appendVersion());
  try {
    data->setContent(content);
  }
  catch (const tlv::Error& e) {
    LOG_FAILURE("command", "can not set content for response: " << e.what());
  }

  if (options.getSigningOption() & SecurityOptions::HMAC) {
    hmac::signData(*data, options.getPinCode());
  }
  else if (options.getSigningOption() & SecurityOptions::IDENTITY) {
    m_keyChain.sign(*data);
  }
  else {
    m_keyChain.sign(*data);
  }

  lp::CachePolicy policy;
  policy.setPolicy(lp::CachePolicyType::NO_CACHE);
  data->setTag(make_shared<lp::CachePolicyTag>(policy));

  m_face.put(*data);
  LOG_DATA_OUT(*data);
}

void
Entity::broadcast(const Interest& interest,
		  const ResponseHandler& handler,
		  const Verification& verify,
		  const VerificationFailCallback& onFailure)
{
  m_agent.broadcast(interest,
		    bind(&Entity::verifyResponse, this, _1, _2, verify, onFailure, handler),
		    [] (const Interest&, const lp::Nack& nack) {
		      LOG_FAILURE("broadcast", "NACK: " << nack.getReason());
		    },
		    [] (const Interest&) {
		      LOG_FAILURE("broadcast", "TIMEOUT");
		    });
}

void
Entity::registerPrefixOnFace(const Name& name, uint64_t faceId,
			     const CommandSuccessCallback& onSuccess,
			     const CommandFailCallback& onFailure)
{
  nfd::ControlParameters ribParameters;
  ribParameters
    .setName(name)
    .setFaceId(faceId)
    .setCost(0)
    .setExpirationPeriod(time::milliseconds::max());

  m_controller.start<nfd::RibRegisterCommand>(ribParameters, onSuccess, onFailure);  
}

void
Entity::verifyResponse(const Interest& interest,
		       const Data& data,
		       const Verification& verify,
		       const VerificationFailCallback& onFailure,
		       const ResponseHandler& handler)
{
  LOG_DATA_IN(data);
  if (!interest.matchesData(data)) {
    return onFailure("interest and data do not match");
  }

  if (!verify(data)) {
    return onFailure("data can not be verified");
  }

  auto content = data.getContent();
  try {
    content.parse();
  }
  catch (const tlv::Error& e) {
    return onFailure("can not parse the data");
  }

  handler(content);
}


security::Key
Entity::getDefaultKey()
{
  try {
    return m_identity.getDefaultKey();
  }
  catch (const security::Pib::Error&) {
    return m_keyChain.createKey(m_identity);
  }
}

security::v2::Certificate
Entity::getDefaultCertificate()
{
  auto key = getDefaultKey();
  try {
    return key.getDefaultCertificate();
  }
  catch (const security::Pib::Error&) {
    return m_keyChain.createKey(m_identity).getDefaultCertificate();
  }  
}

void
Entity::publishCertificate(const Name& keyName, const security::v2::Certificate& certificate)
{
  try {
    //m_storage.insert(certificate);
  }
  catch (const InMemoryStorage::Error& e) {
    std::cout << "publish cert: " << e.what() << std::endl;
    return;
  }
  catch (const std::runtime_error& e) {
    std::cout << e.what() << std::endl;
  }

  m_certificates[certificate.getName()] = certificate;
  LOG_DBG("certificate " << keyName << " is published");
	   
  m_face.setInterestFilter(keyName,
			   bind(&Entity::fetchCertificate, this, _2),
			   bind([keyName] { LOG_DBG("listen to requests to this certificate"); }),
			   bind([keyName] { LOG_FAILURE("cert", "fail to listen" << keyName); }));
}

void
Entity::fetchCertificate(const Interest& interest)
{
  /*
  auto data = m_storage.find(interest);
  if (data != nullptr) {
    lp::CachePolicy policy;
    policy.setPolicy(lp::CachePolicyType::NO_CACHE);
    data->setTag(make_shared<lp::CachePolicyTag>(policy));
    m_face.put(*data);
  }
  else {
    std::cout << "can not find certificate" << interest.getName() << std::endl;
  }
  */

  LOG_STEP(3.2, "Fetch and supply certificate: " << interest.getName());

  LOG_INTEREST_IN(interest);
  for (const auto& entry : m_certificates) {
    if (interest.matchesData(entry.second)) {
      m_face.put(entry.second);
      LOG_DATA_OUT(entry.second);
      break;
    }
  }
}

bool
Entity::getKeyLocatorName(const SignatureInfo& si, Name& name)
{
  if (!si.hasKeyLocator()) {
    name = Name("missing keylocator");
    return false;
  }

  const KeyLocator& kl = si.getKeyLocator();
  if (kl.getType() != KeyLocator::KeyLocator_Name) {
    name = Name("not a name");
    return false;
  }

  name = kl.getName();
  return true;
}

bool
Entity::getKeyLocatorName(const Data& data, Name& name)
{
  return getKeyLocatorName(data.getSignature().getSignatureInfo(), name);
}

bool
Entity::getKeyLocatorName(const Interest& interest, Name& name)
{
  Name interestName = interest.getName();
  if (interestName.size() < signed_interest::MIN_SIZE) {
    name = Name("too short");
    return false;
  }

  SignatureInfo si;
  try {
    si.wireDecode(interestName.at(signed_interest::POS_SIG_INFO).blockFromValue());
  }
  catch (const tlv::Error& e) {
    name = Name(e.what());
    return false;
  }

  return getKeyLocatorName(si, name);
}

} // namespace iot
} // namespace ndn
