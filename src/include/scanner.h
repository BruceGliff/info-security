#pragma once

#include "card_info.h"

class scanner {
  wif *wi;

  static wif *open(char const *);

public:
  scanner(char const *);
};