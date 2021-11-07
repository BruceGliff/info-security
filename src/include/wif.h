#pragma once

#define MAX_IFACE_NAME 64
struct wif {
  int read(unsigned char * h80211,
				   int len,
				   struct rx_info * ri);
  int set_channel(int chan);
  int close();
  int fd();

	void * wi_priv;
	char wi_interface[MAX_IFACE_NAME];

  wif(char const * iface);

private:
  int do_linux_open(char const * iface);
};


