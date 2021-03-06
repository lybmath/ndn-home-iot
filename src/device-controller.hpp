#ifndef NDN_IOT_DEVICE_CONTROLLER_HPP
#define NDN_IOT_DEVICE_CONTROLLER_HPP

#include "entity.hpp"
#include <ndn-cxx/mgmt/nfd/face-status.hpp>
#include <ndn-cxx/mgmt/nfd/face-monitor.hpp>
#include <ndn-cxx/face.hpp>

namespace ndn {
namespace iot {

class DeviceController : public Entity
{
public:
  DeviceController(const std::string& pin,
		   const Name& name = "/home/controller");

public:
  void
  handleProbe(const ControlParameters& parameters,
	      const ReplyWithContent& done,
	      SecurityOptions options);

  void
  onCertificateInterest(const Interest& interest);

  void
  discovery();

  void
  onDiscoveredDevice(const Data& data);

private:
  void
  makeProbeResponse(const std::vector<nfd::FaceStatus>& dataset,
		    const ReplyWithContent& done);

  void
  handleFaceCreation(const nfd::FaceEventNotification& notification,
		     const Name& name);
  
  Block
  packageAccessibleUris(const std::vector<nfd::FaceStatus>& dataset);

  void
  applyForCertificate(const Name& name, uint64_t faceId);

  void
  handleApplyResponse(const Name& keyName, uint64_t faceId, const Block& content);

  void
  requestCertificate(const Name& name);
  
private:
  std::string m_pin;
  nfd::FaceMonitor m_faceMonitor;
  uint64_t m_asFaceId;
};

} // namespace iot
} // namespace ndn

#endif // NDN_IOT_DEVICE_CONTROLLER_HPP
