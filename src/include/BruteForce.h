#pragma once

#include <path.h>

#include <stdint.h>
#include <string>
#include <fstream>
#include <unordered_map>
#include <cstring>

struct AP_info;
struct ST_info;
struct pcap_pkthdr;

namespace std {
  template <>
  struct hash<uint8_t*> {
    std::size_t operator()(const uint8_t* k) const {
      std::string vec {"123456"};
      memcpy(&vec[0], k, 6);
      return std::hash<std::string>()(vec);
    }
  };
}

class BruteForce {
  uint8_t m_BSSID[6];
  uint8_t m_pke[800];
  std::ifstream m_WordlistFile {};
  std::ifstream m_CapFile {};

  std::unordered_map<uint8_t*, ST_info*> m_Stations;
  AP_info * m_CurrAp {nullptr};

  void GetAPInfo();
  void DoWPAHack();
  void CalcPKE();
  bool CheckKey(std::string const &);
  bool GetNextKey(std::string &);
  void ProcessPacket(uint8_t * h80211, pcap_pkthdr const &);
  void Update_APInfo(uint8_t * h80211, pcap_pkthdr const &);

public:
  BruteForce(path const & bin, uint8_t const * bssid);


};
