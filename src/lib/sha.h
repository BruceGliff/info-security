#pragma once

#include <stdint.h>

void calc_pmk(uint8_t const * key, uint8_t const * essid_pre, uint32_t essid_pre_len, uint8_t pmk[40]);
void calc_ptk(uint8_t * pmk, uint8_t * pke, uint8_t * ptk);
void calc_mic(uint8_t * eapol, uint32_t eapol_size, uint8_t keyver, uint8_t * mic, uint8_t * ptk);