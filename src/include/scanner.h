#pragma once

#include "card_info.h"

class scanner {
  wif *wi;

  static wif *open(char const *);

  void launch();

public:
  scanner(char const *);
};