#ifndef NDN_IOT_ENTITY_HPP
#define NDN_IOT_ENTITY_HPP

#include "control-parameters.hpp"
#include "broadcast-agent.hpp"
#include "security-options.hpp"
#include "hmac-helper.hpp"

#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/mgmt/dispatcher.hpp>
#include <boost/asio/signal_set.hpp>
#include <ndn-cxx/mgmt/control-response.hpp>
#include <ndn-cxx/security/command-interest-signer.hpp>
#include <ndn-cxx/security/pib/identity.hpp>
#include <ndn-cxx/ims/in-memory-storage-fifo.hpp>
#include <ndn-cxx/security/v2/validator.hpp>

#include <fstream>

namespace ndn {
namespace iot {

using mgmt::ControlResponse;

class Entity : public security::CommandInterestPreparer
{
public:
  Entity(const Name& name,
	 bool keepRunning = false);

public:
  virtual void
  run()
  {
    m_face.processEvents();
  }

  void
  terminate(const boost::system::error_code& error, int signalNo);

public:
  Name
  getName() {
    return m_name;
  }

public: // command
  typedef boost::function<void(const Block& block)> ReplyWithContent;
  typedef boost::function<void(const ControlParameters& parameters,
			       const ReplyWithContent& done,
			       SecurityOptions options)> CommandHandler;
  typedef boost::function<bool(const Interest& interset)> Authorization;
  typedef boost::function<bool(const Data& data)> Verification;
  typedef boost::function<void(const std::string& reason)> VerificationFailCallback;
  typedef boost::function<void(Interest& interest, KeyChain& keyChain)> InterestSigner;
  typedef boost::function<void(Data& data, KeyChain& keyChain)> DataSigner;
  typedef boost::function<void(const Block& content)> ResponseHandler;

  static InterestSigner
  makeDefaultInterestSigner() {
    return [] (Interest& interest, KeyChain& keyChain) {
      keyChain.sign(interest);
    };
  }

  static DataSigner
  makeDefaultDataSigner() {
    return [] (Data& data, KeyChain& keyChain) {
      keyChain.sign(data);
    };
  }

  void
  registerCommandHandler(const Name& prefix, const Name& subPrefix,
			 const CommandHandler& handler,
			 SecurityOptions options = SecurityOptions());

  Interest
  makeCommand(Name name, const ControlParameters& params,
	      const InterestSigner& sign = Entity::makeDefaultInterestSigner());
  
  void
  issueCommand(const Interest& command,
	       const ResponseHandler& handler,
	       const Verification& verify = bind([] { return true; }));

public: // operation
  typedef boost::function<void(const nfd::ControlParameters& params)> CommandSuccessCallback;
  typedef boost::function<void(const nfd::ControlResponse& resp)> CommandFailCallback;
  
  void
  broadcast(const Interest& intest,
	    const ResponseHandler& handler,
	    const Verification& verify = bind([] { return true; }),
	    const VerificationFailCallback& onFailure = [] (const std::string& reason) {});

  void
  registerPrefixOnFace(const Name& name, uint64_t faceId,
		       const CommandSuccessCallback& onSuccess,
		       const CommandFailCallback& onFailure);

  security::Key
  getDefaultKey();

  security::v2::Certificate
  getDefaultCertificate();

  void
  publishCertificate(const Name& keyName, const security::v2::Certificate& certificate);

  void
  fetchCertificate(const Interest& interest);

private:
  typedef boost::function<void(SecurityOptions options)> AuthorizationCallback;
  
  void
  authorizeRequester(const Interest& interest,
		     const CommandHandler& handler,
		     SecurityOptions options);

  void
  verifyInterestByKey(const Interest& interset,
		      SecurityOptions options,
		      const AuthorizationCallback& cbAfterAuthorization);

  void
  verifyDataByKey(const Data& data,
		  SecurityOptions options,
		  const AuthorizationCallback& cbAfterAuthorization);

  void
  afterAuthorization(const Interest& interest,
		     const CommandHandler& handler,
		     SecurityOptions options);

  void
  verifyResponse(const Interest& interest,
		 const Data& data,
		 const Verification& verify,
		 const VerificationFailCallback& onFailure,
		 const ResponseHandler& handler);

  void
  replyRequest(const Interest& interest,
	       SecurityOptions options,
	       const Block& content);
  
public:
  void
  fail(uint32_t code, const std::string& msg)
  {
    std::cerr << "Entity " << this->getName() << " failed: " << msg << std::endl;
  }

  void
  fail(const std::string& msg)
  {
    std::cerr << "Entity " << this->getName() << " failed: " << msg << std::endl;
  }

private:
  bool
  getKeyLocatorName(const Data& data, Name& name);

  bool
  getKeyLocatorName(const Interest& interest, Name& name);

  bool
  getKeyLocatorName(const SignatureInfo& si, Name& name);
  
protected:
  boost::asio::io_service m_ioService;
  Face m_face;
  KeyChain m_keyChain;
  BroadcastAgent m_agent;
  nfd::Controller m_controller;
  InMemoryStorageFifo m_storage;
  Scheduler m_scheduler;
  boost::asio::signal_set m_terminationSignalSet;
  Name m_name;

  security::Identity m_identity;
  std::vector<uint64_t> m_createdFaces;
  std::unordered_map<Name, bool> m_handlerMaps;
  std::unordered_map<Name, security::v2::Certificate> m_certificates;
};

} // namespace iot
} // namespace ndn

#endif // NDN_IOT_ENTITY_HPP
