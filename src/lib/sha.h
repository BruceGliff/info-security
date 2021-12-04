#pragma once

#include <stdint.h>

void calc_pmk(uint8_t const * key, uint8_t const * essid_pre, uint32_t essid_pre_len, uint8_t pmk[40]);
