#include "logger.hpp"
#include <ndn-cxx/util/time.hpp>
#include <cinttypes>
#include <stdio.h>
#include <type_traits>

namespace ndn {
namespace iot {

std::basic_ofstream<uint8_t> globalPacketFile;

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
