#pragma once

#include <vector>

struct AP_info_tiny {
  unsigned char bssid[6] {0};
  unsigned char * essid {nullptr};
};

class AP_Selecter {

  std::vector<AP_info_tiny> m_AP_Chain;
  std::vector<AP_info_tiny>::const_iterator m_PreferedAP;

public:
  AP_Selecter(char const * Iface);
  AP_Selecter(AP_Selecter const &) = delete;
  AP_Selecter(AP_Selecter &&) = delete;
  AP_Selecter const & operator=(AP_Selecter const &) = delete;
  AP_Selecter const & operator=(AP_Selecter &&) = delete;

  ~AP_Selecter() = default;

  void ChooseAP();
};