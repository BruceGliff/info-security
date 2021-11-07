#pragma once

#include "ieee80211_def.h"

#include <vector>
#include <cstring>

struct AP_info_tiny {
  uint8_t bssid[6] {0};
  uint8_t essid[ESSID_LENGTH + 1] {0};
  AP_info_tiny(uint8_t * bssid_in, uint8_t * essid_in) {
    memcpy(bssid, bssid_in, sizeof(bssid));
    memcpy(essid, essid_in, ESSID_LENGTH + 1);
  }
};

// forward declaration
struct AP_info;

class AP_Selecter {

  std::vector<AP_info_tiny> m_AP_Chain;
  std::vector<AP_info_tiny>::const_iterator m_PreferedAP;

  void GetAPs(AP_info * AP_1st);

public:
  AP_Selecter(char const * Iface);
  AP_Selecter(AP_Selecter const &) = delete;
  AP_Selecter(AP_Selecter &&) = delete;
  AP_Selecter const & operator=(AP_Selecter const &) = delete;
  AP_Selecter const & operator=(AP_Selecter &&) = delete;

  ~AP_Selecter() = default;

  void ChooseAP();
};