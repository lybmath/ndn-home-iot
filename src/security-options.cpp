#include "security-options.hpp"
#include "hmac-helper.hpp"
#include "logger.hpp"

namespace ndn {
namespace iot {

SecurityOptions::SecurityOptions()
  : m_verificationOption(NOT_SET)
  , m_signingOption(NOT_SET)
  , m_verificationType(NOT_SET)
{
}

SecurityOptions::SecurityOptions(std::string pinCode)
  : m_verificationOption(HMAC)
  , m_signingOption(HMAC)
  , m_verificationType(NOT_SET)
  , m_pinCode(pinCode)
{
}

SecurityOptions&
SecurityOptions::addOption(std::string pinCode)
{
  m_verificationOption |= HMAC;
  m_signingOption |= HMAC;
  m_pinCode = pinCode;
  return *this;
}

int
SecurityOptions::getVerificationOption() const
{
  return m_verificationOption;
}

int
SecurityOptions::getSigningOption() const
{
  return m_signingOption;
}

int
SecurityOptions::getVerificationType() const
{
  return m_verificationType;
}

const std::string&
SecurityOptions::getPinCode() const
{
  return m_pinCode;
}

SecurityOptions&
SecurityOptions::setVerificationType(int type)
{
  m_verificationType = type;
  return *this;
}

SecurityOptions&
SecurityOptions::setVerificationOption(std::string pinCode)
{
  m_verificationOption = HMAC;
  m_pinCode = pinCode;
  return *this;
}

SecurityOptions&
SecurityOptions::setSigningOption(std::string pinCode)
{
  m_signingOption = HMAC;
  m_pinCode = pinCode;
  return *this;
}

} // namespace iot
} // namespace ndn
