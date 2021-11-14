#include <iostream>

#include <Monitoring.h>
#include <AP_Selecter.h>
#include <ST_Scanner.h>
#include <path.h>

int main(int argc, char *argv[]) {

  path bin_path = path{argv[0]}.errase_filename();

  Monitor m{};
  AP_Selecter ap{m.GetIface()};
  AP_info_tiny apt {ap.ChooseAP().GetPreferedAP()};
  apt.channel = 11;
  ST_Scanner st{bin_path, apt, m.GetIface()};

  return 0;
}
