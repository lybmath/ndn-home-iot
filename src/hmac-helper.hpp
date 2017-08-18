#ifndef NDN_IOT_HMAC_HELPER_HPP
#define NDN_IOT_HMAC_HELPER_HPP

#include <string>

namespace ndn {

class Interest;
class Data;

namespace iot {
namespace hmac {

void
signInterest(Interest& interest, const std::string& pin);
  
void
signData(Data& data, const std::string& pin);

bool
verifyInterest(const Interest& interest, const std::string& pin);

bool
verifyData(const Data& interest, const std::string& pin);

} // namespace hmac
} // namespace iot
} // namespace ndn

#endif // NDN_IOT_HMAC_HELPER_HPP
