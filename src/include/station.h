#pragma once

#include <inttypes.h>

#define ESSID_LENGTH 32

struct AP_info
{
	struct AP_info * prev;
	struct AP_info * next;

	int channel;
	int ssid_length;

	uint8_t bssid[6];
	uint8_t essid[ESSID_LENGTH + 1];
};
