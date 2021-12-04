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
static struct wif * linux_open(char const * iface);
static int openraw(struct priv_linux * dev, char const * iface, int fd, int * arptype, unsigned char * mac);
static int do_linux_open(struct wif * wi, char const * iface);
static int linux_read(struct wif * wi, struct timespec * ts, int * dlt, unsigned char * buf, int count, struct rx_info * ri);
static int linux_write(struct wif * wi, struct timespec * ts, int dlt, unsigned char * buf, int count, struct tx_info * ti);
static int linux_nl80211_init(struct nl80211_state * state);
static int linux_set_channel(struct wif * wi, int channel);
static void linux_close_nl80211(struct wif * wi);
static void do_free(struct wif * wi);
static int linux_fd(struct wif * wi);
static void nl80211_cleanup(struct nl80211_state * state);
static struct wif * wi_alloc(int sz);

struct priv_linux {
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
static priv_linux * wi_priv(struct wif * wi) { return (priv_linux*) wi->wi_priv; }
char const * wi_get_ifname(struct wif * wi) { return wi->wi_interface; }
void wi_close(wif * wi) { wi->wi_close(wi); }
int wi_read(struct wif * wi, struct timespec * ts, int * dlt, unsigned char * h80211, int len, struct rx_info * ri) {
	assert(wi->wi_read);
	return wi->wi_read(wi, ts, dlt, h80211, len, ri);
}
struct nl80211_state {
	struct nl_sock * nl_sock;
	struct nl_cache * nl_cache;
	struct genl_family * nl80211;
} state;

static int chan;

struct wif * wi_open(char const * iface) {
  return linux_open(iface);
}
static struct wif * linux_open(char const * iface) {
  assert(iface);
	struct wif * wi;
	struct priv_linux * pl;

	if (iface == NULL || strlen(iface) >= IFNAMSIZ)
	{
		return NULL;
	}

	wi = wi_alloc(sizeof(*pl));
	if (!wi) return NULL;
	wi->wi_read = linux_read;
	wi->wi_write = linux_write;
	linux_nl80211_init(&state);
	wi->wi_set_channel = linux_set_channel;
	wi->wi_close = linux_close_nl80211;
	wi->wi_fd = linux_fd;

	if (do_linux_open(wi, iface)) {
		do_free(wi);
		return NULL;
	}
  strncpy(wi->wi_interface, iface, MAX_IFACE_NAME);
  wi->wi_interface[MAX_IFACE_NAME - 1] = 0;
	return wi;
}

static void do_free(struct wif * wi) {
	struct priv_linux * pl = wi_priv(wi);

	if (pl->wlanctlng) free(pl->wlanctlng);

	if (pl->iwpriv) free(pl->iwpriv);

	if (pl->iwconfig) free(pl->iwconfig);

	if (pl->ifconfig) free(pl->ifconfig);

	if (pl->wl) free(pl->wl);

	if (pl->main_if) free(pl->main_if);

	free(pl);
	free(wi);
}

static int linux_fd(struct wif * wi) {
	struct priv_linux * pl = wi_priv(wi);
	return pl->fd_in;
}

static void nl80211_cleanup(struct nl80211_state * state) {
	genl_family_put(state->nl80211);
	nl_cache_free(state->nl_cache);
	nl_socket_free(state->nl_sock);
}

static void linux_close_nl80211(struct wif * wi) {
	struct priv_linux * pl = wi_priv(wi);
	nl80211_cleanup(&state);

	if (pl->fd_in) close(pl->fd_in);
	if (pl->fd_out) close(pl->fd_out);

	do_free(wi);
}
static int ieee80211_channel_to_frequency(int chan) {
	if (chan < 14) return 2407 + chan * 5;
	if (chan == 14) return 2484;
	return (chan + 1000) * 5;
}

static int linux_set_channel(struct wif * wi, int channel) {
	struct priv_linux * dev = wi_priv(wi);
	char s[32];

	unsigned int devid;
	struct nl_msg * msg;
	unsigned int freq;

	memset(s, 0, sizeof(s));

	chan = channel;

	devid = if_nametoindex(wi->wi_interface);
	freq = ieee80211_channel_to_frequency(channel);
	msg = nlmsg_alloc();
	if (!msg)
	{
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
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

static int linux_nl80211_init(struct nl80211_state * state) {
	int err;

	state->nl_sock = nl_socket_alloc();

	if (!state->nl_sock)
	{
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_sock))
	{
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	if (genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache))
	{
		fprintf(stderr, "Failed to allocate generic netlink cache.\n");
		err = -ENOMEM;
		goto out_handle_destroy;
	}

	state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
	if (!state->nl80211)
	{
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

static int linux_read(struct wif * wi, struct timespec * ts, int * dlt, unsigned char * buf, int count, struct rx_info * ri) {
	struct priv_linux * dev = wi_priv(wi);
	unsigned char tmpbuf[4096] __attribute__((aligned(8)));

	int caplen, n, got_signal, got_noise, got_channel, fcs_removed;

	n = got_signal = got_noise = got_channel = fcs_removed = 0;

	if ((unsigned) count > sizeof(tmpbuf)) return (-1);

	caplen = read(dev->fd_in, tmpbuf, count);
	if (caplen < 0 && errno == EAGAIN)
		return (-1);
	else if (caplen < 0)
	{
		perror("read failed");
		return (-1);
	}

  struct ieee80211_radiotap_iterator iterator;
  struct ieee80211_radiotap_header * rthdr;

  rthdr = (struct ieee80211_radiotap_header *) tmpbuf; //-V1032

  if (ieee80211_radiotap_iterator_init(&iterator, rthdr, caplen, NULL)
    < 0)
    return (0);

  while (ri && (ieee80211_radiotap_iterator_next(&iterator) >= 0))
  {

    switch (iterator.this_arg_index)
    {

      case IEEE80211_RADIOTAP_TSFT:
      // 	ri->ri_mactime
      // 		= le64_to_cpu(*((uint64_t *) iterator.this_arg));
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
        if (!got_noise)
        {
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
        ri->ri_channel = getChannelFromFrequency(
        	le16toh(*(uint16_t *) iterator.this_arg));
        got_channel = 1;
        break;

      case IEEE80211_RADIOTAP_RATE:
        ri->ri_rate = (*iterator.this_arg) * 500000;
        break;

      case IEEE80211_RADIOTAP_FLAGS:
        /* is the CRC visible at the end?
        * remove
        */
        if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FCS)
        {
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

static struct wif * wi_alloc(int sz) {
	struct wif * wi;
	void * priv;

	/* Allocate wif & private state */
	wi = (wif*) malloc(sizeof(*wi));
	if (!wi) return NULL;
	memset(wi, 0, sizeof(*wi));

	priv = malloc(sz);
	if (!priv) {
		free(wi);
		return NULL;
	}
	memset(priv, 0, sz);
	wi->wi_priv = priv;
	return wi;
}

static int do_linux_open(struct wif * wi, char const * iface) {
	struct priv_linux * dev = wi_priv(wi);

	if (iface == NULL || strlen(iface) >= IFNAMSIZ) {
		return (1);
	}

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
	if (openraw(dev, iface, dev->fd_out, &dev->arptype_out, dev->pl_mac) != 0) {
		goto close_out;
	}

  close(dev->fd_in);
  dev->fd_in = dev->fd_out;
	dev->arptype_in = dev->arptype_out;

	return 0;
close_out:
	close(dev->fd_out);
close_in:
	close(dev->fd_in);
	return 1;
}

static int openraw(struct priv_linux * dev, char const * iface, int fd, int * arptype, unsigned char * mac) {
	assert(iface);

	struct ifreq ifr;
	struct packet_mreq mr;
	struct sockaddr_ll sll;

	if (strlen(iface) >= sizeof(ifr.ifr_name))
	{
		printf("Interface name too long: %s\n", iface);
		return (1);
	}

	/* find the interface index */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		printf("Interface %s: \n", iface);
		perror("ioctl(SIOCGIFINDEX) failed");
		return (1);
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol = htons(ETH_P_ALL);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("Interface %s: \n", iface);
		perror("ioctl(SIOCGIFHWADDR) failed");
		return (1);
	}

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
		printf("Interface %s: \n", iface);
		perror("bind(ETH_P_ALL) failed");
		return (1);
	}

	/* lookup the hardware type */

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("Interface %s: \n", iface);
		perror("ioctl(SIOCGIFHWADDR) failed");
		return (1);
	}
	*arptype = ifr.ifr_hwaddr.sa_family;

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = sll.sll_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;

	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		perror("setsockopt(PACKET_MR_PROMISC) failed");
		return (1);
	}

	return (0);
}

static int linux_write(struct wif * wi, struct timespec * ts, int dlt, unsigned char * buf, int count, struct tx_info * ti)
{
	struct priv_linux * dev = wi_priv(wi);
	unsigned char tmpbuf[4096];
	unsigned char rate;

	unsigned char u8aRadiotap[] __attribute__((aligned(8))) = {
		0x00,
		0x00, // <-- radiotap version
		0x0c,
		0x00, // <- radiotap header length
		0x04,
		0x80,
		0x00,
		0x00, // <-- bitmap
		0x00, // <-- rate
		0x00, // <-- padding for natural alignment
		0x18,
		0x00, // <-- TX flags
	};

	/* Pointer to the radiotap header length field for later use. */

	if ((unsigned) count > sizeof(tmpbuf) - 22) return -1;

	/* XXX honor ti */
	if (ti)
	{
	}

	(void) ts;
	(void) dlt;

	rate = dev->rate;

	u8aRadiotap[8] = rate;

	memcpy(tmpbuf, u8aRadiotap, sizeof(u8aRadiotap));
	memcpy(tmpbuf + sizeof(u8aRadiotap), buf, count);
	count += sizeof(u8aRadiotap);

	buf = tmpbuf;

	int ret = write(dev->fd_out, buf, count);

	if (ret < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS
			|| errno == ENOMEM)
		{
			usleep(10000);
			return (0);
		}

		perror("write failed");
		return (-1);
	}
	return (ret);
}