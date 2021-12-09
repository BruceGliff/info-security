#pragma once

#include <thread>
#include <mutex>
#include <vector>
#include <path.h>
#include <stdint.h>

struct AP_info_tiny;
struct ST_info_tiny {
  uint8_t stmac[6] {0};
  ST_info_tiny(uint8_t const * stmac_in);
  void Print() const;
};

struct ST_info;
struct AP_info;

struct local_options {
	AP_info *ap_1st{0},  *ap_end{0};
	ST_info *st_1st{0}, *st_end{0};

  int new_st{0};

  uint8_t f_bssid[6] {0};
	int channel{0};
	volatile int do_exit{0};
	char const * s_iface{nullptr};
	FILE * f_cap{nullptr};

  std::mutex m_data {};
};

struct Stations {
  std::vector<ST_info_tiny> m_st_vec;
  std::mutex m_data;

  typedef std::vector<ST_info_tiny>::iterator it;
  typedef std::vector<ST_info_tiny>::const_iterator c_it;

  it begin() { return m_st_vec.begin(); }
  it end() { return m_st_vec.end(); }
  c_it begin() const { return m_st_vec.begin(); }
  c_it end() const { return m_st_vec.end(); }
};


class ST_Scanner {

  local_options m_lopt;
  Stations m_Stations;

  std::thread m_Scanner;
  std::thread m_Deauth;

  static void scanning(uint8_t const * BSSID, uint32_t Ch, char const * Iface, local_options & lopt, path const & bin);
  static void deauthentacating(uint8_t const * BSSID, char const * iface, local_options & lopt, path const & bin);

public:
  ST_Scanner() = delete;
  ST_Scanner(ST_Scanner const &) = delete;
  ST_Scanner(ST_Scanner &&) = delete;
  ST_Scanner & operator=(ST_Scanner const &) = delete;
  ST_Scanner & operator=(ST_Scanner &&) = delete;
  
  ST_Scanner(path const & bin, AP_info_tiny const &AP, char const * Iface);
  ~ST_Scanner();
};
