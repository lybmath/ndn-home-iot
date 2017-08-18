#include "entity.hpp"
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
  std::cout << "####################################################\n"
	    << "## A Entity with name: " << name << " is started!\n"
	    << "####################################################\n"
	    << std::endl;

  m_identity = m_keyChain.createIdentity(m_name);
  
  if (keepRunning) {
    m_terminationSignalSet.add(SIGINT);
    m_terminationSignalSet.add(SIGTERM);
    m_terminationSignalSet.async_wait(bind(&Entity::terminate, this, _1, _2));
  }

  m_handlerMaps.clear();
}

void
Entity::terminate(const boost::system::error_code& error, int signalNo)
{
  if (error)
    return;

  std::cout << "Caught signal '" << ::strsignal(signalNo) << "', exiting..." << std::endl;

  for (const auto& faceId : m_createdFaces) {
    auto params = nfd::ControlParameters();
    m_controller.start<nfd::FaceDestroyCommand>(params.setFaceId(faceId),
						bind([] {}), bind([] {}));  
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

  std::cout << "----------------------------------------\n" << interest.getName()
	    << "\n----------------------------------------" << std::endl;
  
  return interest;
}

void
Entity::issueCommand(const Interest& command,
		     const ResponseHandler& handler,
		     const Verification& verify)
{

  auto onFailure = [this] (const std::string& reason) {
    std::cout << "command fail: " << reason << std::endl;
    this->fail(reason);
  };
  m_face.expressInterest(command,
			 bind(&Entity::verifyResponse, this, _1, _2,
			      verify, onFailure, handler),
			 [this] (const Interest&, const lp::Nack& nack) {
			   std::cout << nack.getReason() << std::endl;
			   this->fail("NAC on command");
			 },
			 [this] (const Interest&) {
			   this->fail("Timeout when waiting for command");
			 });     
}

void
Entity::registerCommandHandler(const Name& prefix, const Name& subPrefix,
			       const CommandHandler& handler,
			       const Authorization& authorize,
			       const DataSigner& sign)
{
  InterestCallback onInterest = bind(&Entity::authorizeRequester, this, _2,
				     authorize, handler, sign);
  auto name = Name(prefix).append(subPrefix);
  
  if (!m_handlerMaps[prefix]) {
    m_handlerMaps[prefix] = true;
    m_face.registerPrefix(prefix,
			  bind([] { std::cout << "hehe yes" << std::endl; }),
			  bind([] { std::cout << "hehe no" << std::endl; }));
  }
  m_face.setInterestFilter(name, onInterest);
}

void
Entity::authorizeRequester(const Interest& interest,
			   const Authorization& authorize,
			   const CommandHandler& handler,
			   const DataSigner& sign)
{
  std::cout << "receive command: " << interest << std::endl;
  
  if (authorize && !authorize(interest)) {
    return this->fail("can not verify the requester");
  }

  try {
    auto params = ControlParameters::fromCommandInterest(interest);
    handler(params, bind(&Entity::replyRequest, this, interest, sign, _1));
  }
  catch (const ControlParameters::Error& e) {
    return this->fail(e.what());
  }  
}

void
Entity::replyRequest(const Interest& interest,
		     const DataSigner& sign,
		     const Block& content)
{
  auto data = make_shared<Data>(Name(interest.getName()).appendVersion());
  try {
    data->setContent(content);
  }
  catch (const tlv::Error& e) {
    std::cout << e.what() << std::endl;
  }

  sign(*data, m_keyChain);

  lp::CachePolicy policy;
  policy.setPolicy(lp::CachePolicyType::NO_CACHE);
  data->setTag(make_shared<lp::CachePolicyTag>(policy));

  m_face.put(*data);
}

void
Entity::broadcast(const Interest& interest,
		  const ResponseHandler& handler,
		  const Verification& verify,
		  const VerificationFailCallback& onFailure)
{
  m_agent.broadcast(interest,
		    bind(&Entity::verifyResponse, this, _1, _2, verify, onFailure, handler));
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
  m_face.setInterestFilter(keyName,
			   bind(&Entity::fetchCertificate, this, _2),
			   bind([] { std::cout << "published" << std::endl; }),
			   bind([] { std::cout << "not publish" << std::endl; }));
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

  for (const auto& entry : m_certificates) {
    if (interest.matchesData(entry.second)) {
      m_face.put(entry.second);
      break;
    }
  }
}

} // namespace iot
} // namespace ndn
