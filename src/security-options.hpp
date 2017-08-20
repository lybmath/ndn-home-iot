#ifndef NDN_IOT_SECURITY_OPTIONS_HPP
#define NDN_IOT_SECURITY_OPTIONS_HPP

#include <string>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/signature-info.hpp>

namespace ndn {

class Interest;
class Data;

}

namespace ndn {
namespace iot {

class SecurityOptions
{
public:
  enum {
    NOT_SET = 0,
    IDENTITY = 0x1, // 00000001
    HMAC = 0x2,     // 00000010
    NO_HMAC = 13,   // 11111101
    NO_DEFAULT = 14 // 11111110
  };

public:
  SecurityOptions();
  
  SecurityOptions(std::string pinCode);

public:
  SecurityOptions&
  addOption(std::string pinCode);
  
  SecurityOptions&
  setVerificationOption(std::string pinCode);

  SecurityOptions&
  setSigningOption(std::string pinCode);

public:
  int
  getVerificationOption() const;

  int
  getSigningOption() const;

  int
  getVerificationType() const;

  const std::string&
  getPinCode() const;

public:
  SecurityOptions&
  setVerificationType(int type);
  
private:
  int m_verificationOption;
  int m_signingOption;
  int m_verificationType;
  std::string m_pinCode;
};

} // namespace iot
} // namespace ndn

#endif // #define NDN_IOT_SECURITY_OPTIONS_HPP
