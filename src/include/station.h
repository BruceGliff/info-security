#pragma once

#include <inttypes.h>

#define ESSID_LENGTH 32

struct AP_info
{
	struct AP_info * prev; /* prev. AP in list         */
	struct AP_info * next; /* next  AP in list         */

	// time_t tinit, tlast; /* first and last time seen */

	int channel; /* AP radio channel         */
	// enum channel_width_enum channel_width; /* Channel width            */
	// char standard[3]; /* 802.11 standard: n or ac */
	// struct n_channel_info n_channel; /* 802.11n channel info     */
	// struct ac_channel_info ac_channel; /* 802.11ac channel info    */
	// int max_speed; /* AP maximum speed in Mb/s */
	// int avg_power; /* averaged signal power    */
	// int best_power; /* best signal power    */
	// int power_index; /* index in power ring buf. */
	// int power_lvl[NB_PWR]; /* signal power ring buffer */
	// int preamble; /* 0 = long, 1 = short      */
	// unsigned int security; /* ENC_*, AUTH_*, STD_*     */
	// int beacon_logged; /* We need 1 beacon per AP  */
	// int dict_started; /* 1 if dict attack started */
	int ssid_length; /* length of ssid           */
	// float gps_loc_min[5]; /* min gps coordinates      */
	// float gps_loc_max[5]; /* max gps coordinates      */
	// float gps_loc_best[5]; /* best gps coordinates     */

	// unsigned long nb_bcn; /* total number of beacons  */
	// unsigned long nb_pkt; /* total number of packets  */
	// unsigned long nb_data; /* number of  data packets  */
	// unsigned long nb_data_old; /* number of data packets/sec*/
	// int nb_dataps; /* number of data packets/sec*/
	// struct timeval tv; /* time for data per second */
	// char * manuf; /* the access point's manufacturer */
	// unsigned long long timestamp; /* Timestamp to calculate uptime   */

	uint8_t bssid[6]; /* access point MAC address     */
	uint8_t essid[ESSID_LENGTH + 1]; /* access point identifier      */
	// uint8_t lanip[4]; /* IP address if unencrypted    */
	// uint8_t * ivbuf; /* table holding WEP IV data    */
	// uint8_t ** uiv_root; /* IV uniqueness root struct    */
	// long ivbuf_size; /* IV buffer allocated size     */
	// long nb_ivs; /* total number of unique IVs   */
	// long nb_ivs_clean; /* total number of unique IVs   */
	// long nb_ivs_vague; /* total number of unique IVs   */
	// unsigned int crypt; /* encryption algorithm         */
	// int eapol; /* set if EAPOL is present      */
	// int target; /* flag set if AP is a target   */
	// struct ST_info * st_1st; /* DEPRECATED: linked list of stations */
	// c_avl_tree_t * stations; /* AVL tree of stations keyed on MAC*/
	// struct WPA_hdsk wpa; /* valid WPA handshake data     */
	// PTW_attackstate * ptw_clean;
	// PTW_attackstate * ptw_vague;

	// int wpa_stored; /* wpa stored in ivs file?   */
	// int essid_stored; /* essid stored in ivs file? */

	// int rx_quality; /* percent of captured beacons */
	// int fcapt; /* amount of captured frames   */
	// int fmiss; /* amount of missed frames     */
	// unsigned int last_seq; /* last sequence number        */
	// struct timeval ftimef; /* time of first frame         */
	// struct timeval ftimel; /* time of last frame          */
	// struct timeval ftimer; /* time of restart             */

	// char * key; /* if wep-key found by dict */

	// char decloak_detect; /* run decloak detection? */
	// struct pkt_buf * packets; /* list of captured packets (last few seconds) */
	// char is_decloak; /* detected decloak */

	// This feature eats 48Mb per AP
	// int EAP_detected;
	// uint8_t * data_root; /* first 2 bytes of data if */
	/* WEP network; used for    */
	/* detecting WEP cloak	  */
	/* + one byte to indicate   */
	/* (in)existence of the IV  */

	// int marked;
	// int marked_color;
	// struct WPS_info wps;
};