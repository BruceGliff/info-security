#include <iostream>

#include <monitoring.h>
#include <scanner.h>

int main(int argc, char *arhv[]) {

  monitor m{};

  scanner s{m.GetIface()};

  return 0;
}
