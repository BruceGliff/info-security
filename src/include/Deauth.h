#pragma once

#include <inttypes.h>

struct wif;

class Deauth {

  uint8_t bssid[6] {0};
  char const * iface {nullptr};
  uint8_t h80211[4096] {0};

  uint8_t const *stmac {nullptr};

  // int do_attack_deauth(wif * wi);

public:
  Deauth(uint8_t const * bssid_in, char const * iface_in);
  int SendPacket(uint8_t const *stmac);
};


void sendP(char const * iface, uint8_t const * bssid_in, uint8_t const * stmac_in);