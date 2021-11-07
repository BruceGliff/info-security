#include <wif.h>

#include <ieee80211_def.h>
#include "radiotap_iter.h"

#include <cassert>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <errno.h>

//from library
#include <linux/nl80211.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/genetlink.h>

// To resolve net/if.h and linux/if.h conflict
extern "C" unsigned int if_nametoindex(const char * __ifname) throw();
struct priv_linux
{
	int fd_in, arptype_in;
	int fd_out, arptype_out;
	int fd_main;
	int fd_rtc;
	int sysfs_inject;
	int channel;
	int freq;
	int rate;
	int tx_power;
	char * wlanctlng; /* XXX never set */
	char * iwpriv;
	char * iwconfig;
	char * ifconfig;
	char * wl;
	char * main_if;
	unsigned char pl_mac[6];
	int inject_wlanng;
};

struct nl80211_state
{
	struct nl_sock * nl_sock;
	struct nl_cache * nl_cache;
	struct genl_family * nl80211;
} state;

static int chan;
static int openraw(char const * iface, int fd, int * arptype);
static int linux_nl80211_init(struct nl80211_state * state);
static void do_free(wif * wi);

wif::wif(char const * Iface) {	
  assert(Iface && Iface[0] && "iface is NULL");
  open(Iface);
}

priv_linux * wif::wi_priv() {
  return static_cast<priv_linux*>(priv);
};
char const * wif::wi_get_iface() {
  return interface;
}

static void nl80211_cleanup(struct nl80211_state * state) {
	genl_family_put(state->nl80211);
	nl_cache_free(state->nl_cache);
	nl_socket_free(state->nl_sock);
}

int wif::open(char const * Iface) {
  priv = malloc(sizeof(priv_linux));
  linux_nl80211_init(&state);
  int const status = do_linux_open(Iface);
  if (interface != Iface)
	  strncpy(interface, Iface, sizeof(interface) - 1);
	interface[sizeof(interface) - 1] = 0;
  return status;
}

wif::~wif() {
  close();
}

int wif::reopen() {
  close();
  return open(interface);
}

void wif::close() {
	priv_linux * pl = wi_priv();
	nl80211_cleanup(&state);

	if (pl->fd_in) ::close(pl->fd_in);
	if (pl->fd_out) ::close(pl->fd_out);

	do_free(this);
}

static void do_free(wif * wi) {
	priv_linux * pl = wi->wi_priv();

	if (pl->wlanctlng) free(pl->wlanctlng);
	if (pl->iwpriv) free(pl->iwpriv);
	if (pl->iwconfig) free(pl->iwconfig);
	if (pl->ifconfig) free(pl->ifconfig);
	if (pl->wl) free(pl->wl);
	if (pl->main_if) free(pl->main_if);

	free(pl);
}

int wif::do_linux_open(char const * iface) {
	priv_linux * dev = wi_priv();
	/* open raw socks */
	if ((dev->fd_in = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket(PF_PACKET) failed");
		if (getuid() != 0)
			fprintf(stderr, "This program requires root privileges.\n");
		return (1);
	}

	if ((dev->fd_main = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket(PF_PACKET) failed");
		if (getuid() != 0)
			fprintf(stderr, "This program requires root privileges.\n");
		return (1);
	}

	if ((dev->fd_out = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket(PF_PACKET) failed");
		goto close_in;
	}

	if (!openraw(iface, dev->fd_out, &dev->arptype_out))
		goto close_out;

  ::close(dev->fd_in);
  dev->fd_in = dev->fd_out;
	dev->arptype_in = dev->arptype_out;
	return 0;
close_out:
	::close(dev->fd_out);

close_in:
	::close(dev->fd_in);
	return 1;
}

static int linux_nl80211_init(struct nl80211_state * state) {
	int err{0};

	state->nl_sock = nl_socket_alloc();

	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	if (genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache)) {
		fprintf(stderr, "Failed to allocate generic netlink cache.\n");
		err = -ENOMEM;
		goto out_handle_destroy;
	}

	state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
	if (!state->nl80211) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_cache_free;
	}

	return 0;

out_cache_free:
	nl_cache_free(state->nl_cache);
out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

static int openraw(char const * iface, int fd, int * arptype) {
  assert(iface && arptype);

	struct ifreq ifr;
	struct packet_mreq mr;
	struct sockaddr_ll sll;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		printf("Interface %s: \n", iface);
		perror("ioctl(SIOCGIFINDEX) failed");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol = htons(ETH_P_ALL);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("Interface %s: \n", iface);
		perror("ioctl(SIOCGIFHWADDR) failed");
		return -1;
	}

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
		printf("Interface %s: \n", iface);
		perror("bind(ETH_P_ALL) failed");
		return -1;
	}

	/* lookup the hardware type */
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("Interface %s: \n", iface);
		perror("ioctl(SIOCGIFHWADDR) failed");
		return -1;
	}
	*arptype = ifr.ifr_hwaddr.sa_family;

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = sll.sll_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;

	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		perror("setsockopt(PACKET_MR_PROMISC) failed");
		return -1;
	}

	return 0;
}

int wif::read(unsigned char * buf, int count, rx_info * ri) {
	priv_linux * dev = wi_priv();
	unsigned char tmpbuf[4096] __attribute__((aligned(8)));

	int caplen, n, got_signal, got_noise, got_channel, fcs_removed;

	n = got_signal = got_noise = got_channel = fcs_removed = 0;

	if ((unsigned) count > sizeof(tmpbuf)) return (-1);

	caplen = ::read(dev->fd_in, tmpbuf, count);
	if (caplen < 0 && errno == EAGAIN)
		return (-1);
	else if (caplen < 0) {
		perror("read failed");
		return (-1);
	}

  struct ieee80211_radiotap_iterator iterator;
  struct ieee80211_radiotap_header * rthdr;

  rthdr = (struct ieee80211_radiotap_header *) tmpbuf; //-V1032

  if (ieee80211_radiotap_iterator_init(&iterator, rthdr, caplen, NULL)
    < 0)
    return (0);

  while (ri && (ieee80211_radiotap_iterator_next(&iterator) >= 0)) {
    switch (iterator.this_arg_index) {
      case IEEE80211_RADIOTAP_TSFT:
        break;

      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
      case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
        if (!got_signal)
        {
          if (*iterator.this_arg < 127)
            ri->ri_power = *iterator.this_arg;
          else
            ri->ri_power = *iterator.this_arg - 255;

          got_signal = 1;
        }
        break;

      case IEEE80211_RADIOTAP_DBM_ANTNOISE:
      case IEEE80211_RADIOTAP_DB_ANTNOISE:
        if (!got_noise) {
          if (*iterator.this_arg < 127)
            ri->ri_noise = *iterator.this_arg;
          else
            ri->ri_noise = *iterator.this_arg - 255;

          got_noise = 1;
        }
        break;

      case IEEE80211_RADIOTAP_ANTENNA:
        ri->ri_antenna = *iterator.this_arg;
        break;

      case IEEE80211_RADIOTAP_CHANNEL:
        break;

      case IEEE80211_RADIOTAP_RATE:
        ri->ri_rate = (*iterator.this_arg) * 500000;
        break;

      case IEEE80211_RADIOTAP_FLAGS:
        /* is the CRC visible at the end?
        * remove
        */
        if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FCS) {
          fcs_removed = 1;
          caplen -= 4;
        }

        if (*iterator.this_arg & IEEE80211_RADIOTAP_F_BADFCS)
          return (0);

        break;
    }
  }

  n = le16_to_cpu(rthdr->it_len);

  if (n <= 0 || n >= caplen) return (0);

	caplen -= n;

	memcpy(buf, tmpbuf + n, caplen);

	return (caplen);
}

int wif::fd() {
	priv_linux * pl = wi_priv();
	return pl->fd_in;
}

static int ieee80211_channel_to_frequency(int channel) {
	if (channel < 14) return 2407 + channel * 5;
	if (channel == 14) return 2484;
	return (channel + 1000) * 5;
}

int wif::set_channel(int channel) {
	priv_linux * dev = wi_priv();
	char s[32];

	unsigned int devid;
	struct nl_msg * msg;
	unsigned int freq;

	memset(s, 0, sizeof(s));
	chan = channel;

	devid = if_nametoindex(interface);
	freq = ieee80211_channel_to_frequency(channel);
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return -1;
	}

	genlmsg_put(msg,
				0,
				0,
				genl_family_get_id(state.nl80211),
				0,
				0,
				NL80211_CMD_SET_WIPHY,
				0);
        
	unsigned ht = NL80211_CHAN_NO_HT;
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devid);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, ht);

	nl_send_auto_complete(state.nl_sock, msg);
	nlmsg_free(msg);

	dev->channel = channel;

	return (0);
nla_put_failure:
	return -ENOBUFS;
}