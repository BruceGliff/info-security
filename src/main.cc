#include <iostream>

#include <Monitoring.h>
#include <AP_Selecter.h>
#include <ST_Scanner.h>
#include <path.h>

int main(int argc, char *argv[]) {
  path bin_path = path{argv[0]}.errase_filename();

  Monitor m{};
  AP_Selecter ap{m.GetIface()};
  ST_Scanner st{bin_path, ap.ChooseAP().GetPreferedAP(), m.GetIface()};
  // BruteForce bf{ap.GetPreferedAP().bssid};
  

  return 0;
}
