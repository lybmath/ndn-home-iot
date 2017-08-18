#include "control-parameters.hpp"
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/interest.hpp>

namespace ndn {
namespace iot {

ControlParameters::ControlParameters()
  : m_wire(makeEmptyBlock(tlv::iot::ControlParameters))
{
}

ControlParameters::ControlParameters(const Block& block)
{
  wireDecode(block);
}

Block
ControlParameters::wireEncode() const
{
  m_wire.encode();
  return m_wire;
}

void
ControlParameters::wireDecode(const Block& wire)
{
  if (wire.type() != tlv::iot::ControlParameters) {
    BOOST_THROW_EXCEPTION(Error("Expecting TLV-IOT-TYPE ControlParameters"));
  }
  m_wire = wire;
  m_wire.parse();
}

ControlParameters
ControlParameters::fromCommandInterest(const Interest& interest)
{
  const int POS_PARAMS_IN_COMMAND = -5;
  const int MIN_COMMAND_NAME_SIZE = 5;
  
  auto name = interest.getName();
  if (name.size() < MIN_COMMAND_NAME_SIZE) {
    BOOST_THROW_EXCEPTION(Error("Interest is too short"));
  }

  return ControlParameters(name.get(POS_PARAMS_IN_COMMAND).wireEncode().blockFromValue());
}

bool
ControlParameters::hasName() const
{
  return hasFiled(tlv::Name);
}

Name
ControlParameters::getName() const
{
  return Name(getFiled(tlv::Name));
}

ControlParameters&
ControlParameters::setName(const Name& name)
{
  return setFiled(name.wireEncode());
}

bool
ControlParameters::hasPinCode() const
{
  return hasFiled(tlv::iot::PinCode);
}

std::string
ControlParameters::getPinCode() const
{
  return getStringFiled(tlv::iot::PinCode);
}

ControlParameters&
ControlParameters::setPinCode(const std::string& pin)
{
  return setFiled(tlv::iot::PinCode, pin);
}

ControlParameters&
ControlParameters::unsetPinCode()
{
  return unsetFiled(tlv::iot::PinCode);
}

bool
ControlParameters::hasKey() const
{
  return hasFiled(tlv::iot::PublicKey);
}

Block
ControlParameters::getKey() const
{
  return getFiled(tlv::iot::PublicKey);
}

ControlParameters&
ControlParameters::setKey(const Buffer& key)
{
  return setFiled(tlv::iot::PublicKey, key.buf(), key.size());
}

bool
ControlParameters::hasFiled(uint32_t type) const
{
  return m_wire.find(type) != m_wire.elements_end();
}

const Block&
ControlParameters::getFiled(uint32_t type) const
{
  if (!this->hasFiled(type)) {
    BOOST_THROW_EXCEPTION(Error("do not has this type of filed"));
  }
  
  return m_wire.get(type);
}

std::string
ControlParameters::getStringFiled(uint32_t type) const
{
  return readString(getFiled(type));
}

uint64_t
ControlParameters::getIntegerFiled(uint32_t type) const
{
  return readNonNegativeInteger(getFiled(type));
}

ControlParameters&
ControlParameters::setFiled(const Block& block)
{
  BOOST_ASSERT(block.hasValue());
  m_wire.push_back(block);
  return *this;
}

ControlParameters&
ControlParameters::setFiled(uint32_t type, const std::string& value)
{
  return setFiled(type, reinterpret_cast<const uint8_t*>(value.data()), value.size());
}
  
ControlParameters&
ControlParameters::setFiled(uint32_t type, const uint64_t& value)
{
  m_wire.push_back(makeNonNegativeIntegerBlock(type, value));
  return *this;
}

ControlParameters&
ControlParameters::setFiled(uint32_t type, const Block& block)
{
  m_wire.push_back(Block(type, block));
  return *this;
}

ControlParameters&
ControlParameters::setFiled(uint32_t type, const uint8_t* value, size_t length)
{
  m_wire.push_back(makeBinaryBlock(type, value, length));
  return *this;
}

ControlParameters&
ControlParameters::unsetFiled(uint32_t type)
{
  m_wire.remove(type);
  return *this;
}

std::ostream&
operator<<(std::ostream& os, const ControlParameters& params)
{
  if (params.hasName()) {
    os << "Name: " << params.getName();
  }
  if (params.hasPinCode()) {
    os << "\nPinCode: " << params.getPinCode();
  }

  return os;
}

} // namespace iot
} // namespace ndn
