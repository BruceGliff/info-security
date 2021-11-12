#include <iostream>

#include <Monitoring.h>
#include <AP_Selecter.h>

int main(int argc, char *argv[]) {

  Monitor m{};
  AP_Selecter ap{m.GetIface()};
  ap.ChooseAP();

  return 0;
}
