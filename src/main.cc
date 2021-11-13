#include <iostream>

#include <Monitoring.h>
#include <AP_Selecter.h>
#include <ST_Scanner.h>

int main(int argc, char *argv[]) {

  // Monitor m{};
  // AP_Selecter ap{m.GetIface()};
  // ST_Scanner st{ap.ChooseAP().GetPreferedAP(), m.GetIface()};
  uint8_t essid[] = "MY_ESSID";
  uint8_t bssid[] = {0xc4, 0x71, 0x54, 0xb5, 0x3a, 0x4a};
  AP_info_tiny ap { bssid, essid , 11};
  ST_Scanner st{ap, "wlan0mon"};

  return 0;
}
