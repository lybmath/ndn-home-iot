#include "hmac-helper.hpp"
#include "control-parameters.hpp"

#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/security/security-common.hpp>
#include <ndn-cxx/security/transform/hmac-filter.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/signature.hpp>

namespace ndn {
namespace iot {
namespace hmac {

static Block
makeHMACSignatureInfo()
{
  auto info = makeEmptyBlock(tlv::SignatureInfo);
  info.push_back(makeNonNegativeIntegerBlock(tlv::SignatureType, tlv::iot::HMACSignature));
  
  info.encode();
  return info;
}

static Block
makeHMACSignatureValue(const uint8_t* buffer, size_t bufferLength,
			       const std::string& pin)
{
  OBufferStream os;
  
  security::transform::bufferSource(buffer, bufferLength)
    >> security::transform::hmacFilter(DigestAlgorithm::SHA256,
				       reinterpret_cast<const uint8_t*>(pin.data()),
				       pin.size())
    >> security::transform::streamSink(os);

  auto value = makeBinaryBlock(tlv::SignatureValue, os.buf()->buf(), os.buf()->size());
  
  value.encode();
  return value;
}

void
signInterest(Interest& interest, const std::string& pin)
{
  auto signedName = interest.getName();
  auto nameBlock = signedName.append(makeHMACSignatureInfo()).wireEncode();
  auto sigValue = makeHMACSignatureValue(nameBlock.value(), nameBlock.value_size(), pin);
 
  interest.setName(signedName.append(sigValue));
}
  
void
signData(Data& data, const std::string& pin)
{
  data.setSignature(Signature(makeHMACSignatureInfo()));
  
  EncodingBuffer encoder;
  data.wireEncode(encoder, true);
  
  auto sigValue = makeHMACSignatureValue(encoder.buf(), encoder.size(), pin);
  data.wireEncode(encoder, sigValue);
}

bool
verifyInterest(const Interest& interest, const std::string& pin)
{
  Name interestName = interest.getName();
  
  if (interestName.size() < signed_interest::MIN_SIZE) {
    std::cout << "too short" << std::endl;
    return false;
  }

  try {
    auto sigValue = interestName[signed_interest::POS_SIG_VALUE].blockFromValue();
    auto nameBlock = interestName.getPrefix(signed_interest::POS_SIG_VALUE).wireEncode();
    return makeHMACSignatureValue(nameBlock.value(), nameBlock.value_size(), pin) == sigValue;
  }
  catch (const tlv::Error& e) {
    std::cout << e.what() << std::endl;
    return false;
  }
}

bool
verifyData(const Data& data, const std::string& pin)
{
  try {
    const auto& signature = data.getSignature();
    return signature.getValue() ==
      makeHMACSignatureValue(data.wireEncode().value(),
			     data.wireEncode().value_size() - signature.getValue().size(),
			     pin);
  }
  catch (const tlv::Error& e) {
    std::cout << e.what() << std::endl;
    return false;
  }
}

} // namespace hmac
} // namespace iot
} // namespace ndn
