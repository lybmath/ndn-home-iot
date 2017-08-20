#ifndef NDN_IOT_LOG_HPP
#define NDN_IOT_LOG_HPP

#include <boost/log/common.hpp>
#include <boost/log/sources/logger.hpp>
#include <ndn-cxx/encoding/block.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <fstream>

/*
         foreground background
black        30         40
red          31         41
green        32         42
yellow       33         43
blue         34         44
magenta      35         45
cyan         36         46
white        37         47

reset             0  (everything back to normal)
bold/bright       1  (often a brighter shade of the same colour)
underline         4
inverse           7  (swap foreground and background colours)
bold/bright off  21
underline off    24
inverse off      27

cout << "\033[1;31m bold red text \033[0m\n";
*/
	 
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

#define LOG_DOT_LINE std::cerr << "------------------------------------------------------------------" << std::endl;

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

#define LOG_STEP(idx, msg) {						\
    LOG_DOT_LINE							\
    std::cerr << "- [STEP " << idx << "]: " << msg << std::endl;	\
    LOG_DOT_LINE							\
}

#define LOG_FAILURE(msg, expression)		\
  std::cerr << "[" << LoggerTimestamp{} << "] " << "[" << msg << "]: " << expression << std::endl; \
  LOG_DOT_LINE
  
#define LOG_INFO(expression) \
  std::cerr << "[" << LoggerTimestamp{} << "] " << expression << std::endl; \
  LOG_DOT_LINE

void printInfoFromInterest(const std::string& msg, const Interest& interest);
void printInfoFromData(const std::string& msg, const Data& data);
  
#define LOG_INTEREST(msg, interest) {					\
    printInfoFromInterest(msg, interest);				\
    LOG_DOT_LINE							\
}
#define LOG_DATA(msg, data) {					\
    printInfoFromData(msg, data);				\
    LOG_DOT_LINE						\
}

#define LOG_INTEREST_IN(interest)  LOG_INTEREST("Interest  IN", interest)
#define LOG_INTEREST_OUT(interest) LOG_INTEREST("Interest OUT", interest)
#define LOG_DATA_IN(data)  LOG_DATA("    Data  IN", data)
#define LOG_DATA_OUT(data) LOG_DATA("    Data OUT", data)

//#define DEBUG
#ifdef DEBUG
#define LOG_DBG LOG_INFO
#else
#define LOG_DBG(expression) {}
#endif

} // namespace iot
} // namespace ndn

#endif // NDN_IOT_LOG_HPP
