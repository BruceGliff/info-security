#include <iostream>

#include <Monitoring.h>
#include <AP_Selecter.h>
#include <ST_Scanner.h>
#include <BruteForce.h>
#include <path.h>

int main(int argc, char *argv[]) {
  path bin_path = path{argv[0]}.errase_filename();
  
  // uint8_t essid[] = "MY_ESSID";
  // uint8_t bssid[] = {0xc4, 0x71, 0x54, 0xb5, 0x3a, 0x4a};
  // AP_info_tiny ap { bssid, essid , 11};
  // ST_Scanner st{bin_path, ap, "wlan0mon"};

  Monitor m{};
  AP_Selecter ap{m.GetIface()};
  ST_Scanner st{bin_path, ap.ChooseAP().GetPreferedAP(), m.GetIface()};
  BruteForce bf{bin_path, ap.GetPreferedAP().bssid};
  // BruteForce bf{bin_path, bssid};

  return 0;
}
