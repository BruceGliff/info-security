#pragma once

#include <thread>
#include <stdint.h>

class AP_info_tiny;

class ST_Scanner {

  std::thread m_Scanner;

  static void scanning(uint8_t const * BSSID, uint32_t Ch, char const * Iface);

public:
  ST_Scanner() = delete;
  ST_Scanner(ST_Scanner const &) = delete;
  ST_Scanner(ST_Scanner &&) = delete;
  ST_Scanner & operator=(ST_Scanner const &) = delete;
  ST_Scanner & operator=(ST_Scanner &&) = delete;
  
  ST_Scanner(AP_info_tiny const &AP, char const * Iface);
  ~ST_Scanner();

};