#include <ST_Scanner.h>

#include <AP_Selecter.h>


ST_Scanner::ST_Scanner(AP_info_tiny const &AP, char const * Iface)
  : m_Scanner(scanning, AP.bssid, AP.channel, Iface) {
    AP.Print();
}

void ST_Scanner::scanning(uint8_t const * BSSID, uint32_t Ch, char const * Iface) {
  return;
}

ST_Scanner::~ST_Scanner() {
  m_Scanner.join();
}