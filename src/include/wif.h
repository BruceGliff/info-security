#pragma once

struct priv_linux;

#define MAX_IFACE_NAME 64
struct wif {
	int (*wi_read)(struct wif * wi,
				   struct timespec * ts,
				   int * dlt,
				   unsigned char * h80211,
				   int len,
				   struct rx_info * ri);
	int (*wi_write)(struct wif * wi,
					struct timespec * ts,
					int dlt,
					unsigned char * h80211,
					int len,
					struct tx_info * ti);
	int (*wi_set_channel)(struct wif * wi, int chan);
	void (*wi_close)(struct wif * wi);
	int (*wi_fd)(struct wif * wi);

	void * wi_priv;
	char wi_interface[MAX_IFACE_NAME];
};

/* Routines to be used by client code */
struct wif * wi_open(char const * iface);
int wi_read(struct wif * wi,
				   struct timespec * ts,
				   int * dlt,
				   unsigned char * h80211,
				   int len,
				   struct rx_info * ri);
int wi_set_channel(struct wif * wi, int chan);
void wi_close(struct wif * wi);
char const * wi_get_ifname(struct wif * wi);
