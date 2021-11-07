#pragma once

struct priv_linux;

#define MAX_IFACE_NAME 64
struct wif {
  int read(unsigned char * h80211, int len, struct rx_info * ri);
  int set_channel(int chan);
  int fd();
  int reopen();
  wif(char const * iface);
  ~wif();
  priv_linux * wi_priv();
  char const * wi_get_iface();
private:
  int do_linux_open(char const * iface);
  int open(char const *);
  void close();

	void * priv;
	char interface[MAX_IFACE_NAME];
};



