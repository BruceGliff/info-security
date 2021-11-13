#pragma once

#include <inttypes.h>

#define ESSID_LENGTH 32

struct AP_info {
	struct AP_info * prev; /* prev. AP in list         */
	struct AP_info * next; /* next  AP in list         */

	int channel;
	int ssid_length;
	int EAP_detected;
	uint8_t bssid[6]; /* access point MAC address     */
	uint8_t essid[ESSID_LENGTH + 1]; /* access point identifier      */

};

struct ST_info {
	struct ST_info * prev; /* the prev client in list   */
	struct ST_info * next; /* the next client in list   */
	struct AP_info * base; /* AP this client belongs to */
	uint8_t stmac[6]; /* the client's MAC address  */
	uint8_t essid[ESSID_LENGTH + 1]; /* last associated essid     */
	int essid_length; /* essid length of last asso */
	int state;

	int channel; /* Channel station is seen   */
};
