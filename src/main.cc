#include <iostream>

#include <Monitoring.h>
#include <AP_Selecter.h>
#include <ST_Scanner.h>

int main(int argc, char *argv[]) {

  Monitor m{};
  AP_Selecter ap{m.GetIface()};
  ST_Scanner st{ap.ChooseAP().GetPreferedAP(), m.GetIface()};
  

  return 0;
}
