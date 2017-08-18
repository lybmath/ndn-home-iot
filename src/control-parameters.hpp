#ifndef NDN_IOT_CONTROL_PARAMETERS_HPP
#define NDN_IOT_CONTROL_PARAMETERS_HPP

#include <ndn-cxx/mgmt/control-parameters.hpp>

namespace ndn {
  class Interest;
  class Name;
}

namespace ndn {
namespace tlv {
namespace iot {

enum {
  HMACSignature = AppPrivateBlock1 + 1,
  ControlParameters,
  PinCode,
  DeviceUris,
  DeviceUri,
  KeyName,
  PublicKey,
  TrustAnchor,
  Certificate
};

}
}
}

namespace ndn {
namespace iot {
  
class ControlParameters : public mgmt::ControlParameters
{
public:
  class Error : public tlv::Error
  {
  public:
    explicit
    Error(const std::string& what)
      : tlv::Error(what)
    {
    }
  };

  ControlParameters();

  explicit
  ControlParameters(const Block& block);

  Block
  wireEncode() const final;

  void
  wireDecode(const Block& wire) final;

public: // static
  static ControlParameters
  fromCommandInterest(const Interest& interest);

public:
  bool
  hasName() const;

  Name
  getName() const;

  ControlParameters&
  setName(const Name& name);

  bool
  hasPinCode() const;

  std::string
  getPinCode() const;

  ControlParameters&
  setPinCode(const std::string& pin);

  ControlParameters&
  unsetPinCode();

  bool
  hasKey() const;

  Block
  getKey() const;

  ControlParameters&
  setKey(const Buffer& key);
  

protected:
  bool
  hasFiled(uint32_t type) const;

  const Block&
  getFiled(uint32_t type) const;

  std::string
  getStringFiled(uint32_t type) const;

  uint64_t
  getIntegerFiled(uint32_t type) const;

  ControlParameters&
  setFiled(const Block& block);

  ControlParameters&
  setFiled(uint32_t type, const std::string& value);
  
  ControlParameters&
  setFiled(uint32_t type, const uint64_t& value);

  ControlParameters&
  setFiled(uint32_t type, const Block& block);

  ControlParameters&
  setFiled(uint32_t type, const uint8_t* value, size_t length);

  ControlParameters&
  unsetFiled(uint32_t type);
    
private:
  mutable Block m_wire;
};

/** @brief Print URI representation of a control parameters
 *  @sa https://named-data.net/doc/ndn-tlv/name.html#ndn-uri-scheme
 */
std::ostream&
operator<<(std::ostream& os, const ControlParameters& params);

} // namespace iot
} // namespace ndn

#endif // NDN_IOT_CONTROL_PARAMETERS_HPP
