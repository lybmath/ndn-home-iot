#ifndef NDN_IOT_LOG_HPP
#define NDN_IOT_LOG_HPP

#include <boost/log/common.hpp>
#include <boost/log/sources/logger.hpp>
#include <ndn-cxx/encoding/block.hpp>
#include <fstream>

namespace ndn {
namespace iot {

struct LoggerTimestamp
{
};

extern std::basic_ofstream<uint8_t> globalPacketFile;

void
writeToFile(const Block& block);
  
std::ostream&
operator<<(std::ostream& os, const LoggerTimestamp&);

#define LOG_LINE(msg, expression) \
  LoggerTimestamp{} << " "#msg": " << expression;

#define LOG_WELCOME(role, name)						\
  std::cerr << "##########################################################\n" \
            << "# THE [" << role << "] NAMED [" << name << "] IS RUNNING " 		\
            << "\n##########################################################"	\
            << std::endl

#define LOG_BYEBYE(name, msg) \
  std::cerr << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n" \
            << "+ [" << name << "] IS GOING TO BE TERMINATED " << msg			\
            << "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"	\
            << std::endl

#define LOG_STEP(idx, msg) \
    std::cerr << "----------------------------------------------------------\n" \
              << "- [STEP " << idx << "]: " << msg					\
              << "\n----------------------------------------------------------"	\
              << std::endl

#define LOG_FAILURE(msg, expression)		\
  std::cerr << "[" << LoggerTimestamp{} << "] " << "[" << msg << "]: " << expression << std::endl;

#define LOG_INFO(expression) \
  std::cerr << "[" << LoggerTimestamp{} << "] " << expression << std::endl;

#define LOG_INTEREST_IN(interest) {					\
  std::cerr << "[" << LoggerTimestamp{} << "] " << "received an interest:\n"	\
            << interest << std::endl;					\
  writeToFile((interest).wireEncode());				\
}

#define LOG_INTEREST_OUT(interest) {					\
  std::cerr << "[" << LoggerTimestamp{} << "] " << "sent out an interest:\n" \
            << interest << std::endl;					\
  writeToFile((interest).wireEncode());				\
}

#define LOG_DATA_IN(data) {						\
  std::cerr << "[" << LoggerTimestamp{} << "] " << "received a data:\n"	\
            << data << std::endl;					\
  writeToFile((data).wireEncode());					\
}

#define LOG_DATA_OUT(data) {						\
  std::cerr << "[" << LoggerTimestamp{} << "] " << "sent out a data:\n" \
            << data << std::endl;					\
  writeToFile((data).wireEncode());					\
}
  
} // namespace iot
} // namespace ndn

#endif // NDN_IOT_LOG_HPP
