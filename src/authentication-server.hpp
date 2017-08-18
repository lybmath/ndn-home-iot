#ifndef NDN_IOT_AUTHENTICATION_SERVER_HPP
#define NDN_IOT_AUTHENTICATION_SERVER_HPP

#include "entity.hpp"
#include <ndn-cxx/mgmt/nfd/face-status.hpp>
#include <ndn-cxx/net/face-uri.hpp>
#include <ndn-cxx/mgmt/nfd/control-parameters.hpp>
#include <ndn-cxx/mgmt/nfd/control-response.hpp>
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace iot {

class AuthenticationServer : public Entity
{
public:
  AuthenticationServer(const Name& name = "/home/as");

public:
  void
  addDevice(const ControlParameters& params,
	    const ReplyWithContent& done);

  void
  issueCertificate(const ControlParameters& params,
		   const ReplyWithContent& done);
  
private: // probe
  void
  handleProbeResponse(const Block& content,
		      const ReplyWithContent& done,
		      const std::string& pin);

  typedef boost::function<void (const nfd::ControlParameters&)> CommandSucceedCallback;

  void
  connectToDevice(std::vector<std::string> pendingUris,
		  const CommandSucceedCallback& cbDeviceConnected,
		  const ReplyWithContent& done);
  
  void
  createFaceTowardDevice(const FaceUri& canonicalUri,
			 std::vector<std::string> pendingUris,
			 const CommandSucceedCallback& cbDeviceConnected,
			 const ReplyWithContent& done);

  void
  afterCreateFaceFailed(const nfd::ControlResponse& resp,
			std::vector<std::string> pendingUris,
			const CommandSucceedCallback& cbDeviceConnected,
			const ReplyWithContent& done);

  void
  afterConnectToDevice(const nfd::ControlParameters& params,
		       const Name& name,
		       const ReplyWithContent& done);

protected:
  security::v2::Certificate
  generateDeviceCertificate(const Name& keyName, const Block& pubKey,
			    const security::v2::Certificate& anchor);
};

} // namespace iot
} // namespace ndn

#endif // NDN_IOT_AUTHENTICATION_SERVER_HPP
