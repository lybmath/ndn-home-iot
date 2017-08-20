#include "logger.hpp"
#include "control-parameters.hpp"
#include <ndn-cxx/util/time.hpp>
#include <cinttypes>
#include <stdio.h>
#include <type_traits>
#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/signature-info.hpp>

namespace ndn {
namespace iot {

std::basic_ofstream<uint8_t> globalPacketFile;

static std::string
getKey(const SignatureInfo& info)
{
  std::string type = "";
  std::string key = "";
  switch(info.getSignatureType()) {
  case 129: key = "HMAC"; break;
  case 0: type = "DigestSha256"; break;
  case 1: type = "SignatureSha256WithRsa"; break;
  case 3: type = "SignatureSha256WithEcdsa"; break;
  default: type = "NOT DEFIEND"; break;
  }

  if (info.getSignatureType() != 129) {
    if (info.hasKeyLocator()) {
      const auto& kl = info.getKeyLocator();
      if (kl.getType() == KeyLocator::KeyLocator_Name) {
	key = kl.getName().toUri();
      }
    }
  }

  return key;
}

void
printInfoFromInterest(const std::string& msg, const Interest& interest)
{
  // std::cerr << "[" << LoggerTimestamp{} << "] " << msg << ":\n"
  // cout << "\033[1;31mbold red text\033[0m\n";
  Name name = interest.getName();
  if (name[0] == name::Component("localhost")) return;

  bool hasSignature = false;
  try {
    auto block = name.get(-2).blockFromValue();
    if (block.type() == tlv::SignatureInfo) {
      hasSignature = true;
    }
  }
  catch (const tlv::Error&) {
  }
  
  if (hasSignature) {
    SignatureInfo info(name.get(-2).blockFromValue());
    auto key = getKey(info);
    
    ControlParameters params;
    try {
      params.wireDecode(name.get(-5).blockFromValue());
      std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
		<< "\033[1;31m" << name.getPrefix(-5) << "\033[0m" << params << "\n"
		<< "SIGNED BY \033[1m " << key << "\033[0m" << std::endl;
    }
    catch (const tlv::Error&) {
      std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
		<< "\033[1;31m" << name.getPrefix(-4) << "\033[0m\n"
		<< "SIGNED BY \033[1m " << key << "\033[0m" << std::endl;
    }
  }
  else {
    std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
	      << "\033[31m" << name << "\033[0m" << std::endl;
  }
}

void printInfoFromData(const std::string& msg, const Data& data)
{
  Name name = data.getName();
  if (name[0] == name::Component("localhost")) return;
  
  bool hasSignature = false;
  try {
    auto block = name.get(-3).blockFromValue();
    if (block.type() == tlv::SignatureInfo) {
      hasSignature = true;
    }
  }
  catch (const tlv::Error&) {
  }

  if (!hasSignature) {
    std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
	      << name << std::endl;
    return;
  }

  SignatureInfo info(name.get(-3).blockFromValue());
  auto key = getKey(info);

  SignatureInfo dataSigInfo = data.getSignature().getSignatureInfo();
  auto dataKey = getKey(dataSigInfo);
  
  ControlParameters params;
  try {
    params.wireDecode(name.get(-6).blockFromValue());
    std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
	      << "\033[1;32m" << name.getPrefix(-6) << "\033[0m" << params
	      << "[SIG=" << key << "][V=" << name.get(-1).toVersion() << "]\n"
	      << "SIGNED BY \033[1m " << dataKey << "\033[0m" << std::endl;
  }
  catch (const tlv::Error&) {
    std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
	      << "\033[1;32m" << name.getPrefix(-5) << "\033[0m"
	      << "[SIG=" << key << "][V=" << name.get(-1).toVersion() << "]\n"
	      << "SIGNED BY \033[1m " << dataKey << "\033[0m" << std::endl;
  }  
}

void
writeToFile(const Block& block)
{					
  if (!globalPacketFile.is_open()) {				
      globalPacketFile.open("packet.out", std::ios::out | std::ios::binary); 
  }
  const uint8_t* buf = block.wire();
  size_t buf_size = block.size();

  // write the size first, so the reader can be aware of how many bytes to read next
  globalPacketFile.write(reinterpret_cast<uint8_t*>(&buf_size), sizeof(size_t));

  // write the whole buf into file in the binary format
  globalPacketFile.write(buf, buf_size);

  // flush to file rather than buffered the content
  globalPacketFile.flush();
}

std::ostream&
operator<<(std::ostream& os, const LoggerTimestamp&)
{
  using namespace ndn::time;

  static const microseconds::rep ONE_SECOND = 1000000;
  microseconds::rep microsecondsSinceEpoch = duration_cast<microseconds>(
    system_clock::now().time_since_epoch()).count();

  // 10 (whole seconds) + '.' + 6 (fraction) + '\0'
  char buffer[10 + 1 + 6 + 1];
  BOOST_ASSERT_MSG(microsecondsSinceEpoch / ONE_SECOND <= 9999999999L,
                   "whole seconds cannot fit in 10 characters");

  static_assert(std::is_same<microseconds::rep, int_least64_t>::value,
                "PRIdLEAST64 is incompatible with microseconds::rep");
  // - std::snprintf not found in some environments
  //   http://redmine.named-data.net/issues/2299 for more information
  snprintf(buffer, sizeof(buffer), "%" PRIdLEAST64 ".%06" PRIdLEAST64,
           microsecondsSinceEpoch / ONE_SECOND,
           microsecondsSinceEpoch % ONE_SECOND);

  return os << buffer;
}

} // namespace iot
} // namespace ndn
