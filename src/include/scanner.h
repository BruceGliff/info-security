#pragma once

#include "card_info.h"

class scanner {
  wif *wi;

  void launch();

public:
  static wif *open(char const *);
  scanner(char const *);
};