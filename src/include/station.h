#pragma once

#include <inttypes.h>

#define ESSID_LENGTH 32

struct WPA_hdsk {
	uint8_t stmac[6]; /* supplicant MAC           */
	uint8_t snonce[32]; /* supplicant nonce         */
	uint8_t anonce[32]; /* authenticator nonce      */
	uint8_t pmkid[16]; /* eapol frame PMKID RSN    */
	uint8_t keymic[16]; /* eapol frame MIC          */
	uint8_t eapol[256]; /* eapol frame contents     */
	uint32_t eapol_size; /* eapol frame size         */
	uint8_t keyver; /* key version (TKIP / AES) */
	uint8_t state; /* handshake completion     */
	uint8_t found;
	uint8_t eapol_source;
	uint64_t replay;
	uint64_t timestamp_start_us;
	uint64_t timestamp_last_us;
};

struct AP_info {
	AP_info * prev; /* prev. AP in list         */
	AP_info * next; /* next  AP in list         */

	int channel;
	int ssid_length;
	int EAP_detected;
	uint8_t bssid[6]; /* access point MAC address     */
	uint8_t essid[ESSID_LENGTH + 1]; /* access point identifier      */
	WPA_hdsk wpa; /* WPA handshake data        */

};

struct ST_info {
	ST_info * prev; /* the prev client in list   */
	ST_info * next; /* the next client in list   */
	AP_info * base; /* AP this client belongs to */
	uint8_t stmac[6]; /* the client's MAC address  */
	uint8_t essid[ESSID_LENGTH + 1]; /* last associated essid     */
	int essid_length; /* essid length of last asso */
	int state;
	int eapol;
	WPA_hdsk wpa; /* WPA handshake data        */

	int channel; /* Channel station is seen   */
};
