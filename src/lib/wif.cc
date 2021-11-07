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

struct priv_linux
{
	int fd_in, arptype_in;
	int fd_out, arptype_out;
	int fd_main;
	int fd_rtc;

	// DRIVER_TYPE drivertype; /* inited to DT_UNKNOWN on allocation by wi_alloc */

	// FILE * f_cap_in;

	// struct pcap_file_header pfh_in;

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

wif::wif(char const * iface) {	
  assert(iface && iface[0] && "iface is NULL");

  wi_priv = malloc(sizeof(priv_linux));
  linux_nl80211_init(&state);
	wi->wi_set_channel = linux_set_channel_nl80211;
	wi->wi_close = linux_close_nl80211;
  do_linux_open(iface);

	strncpy(wi_interface, iface, sizeof(wi_interface) - 1);
	wi_interface[sizeof(wi_interface) - 1] = 0;
}

static priv_linux * wi_priv(wif * wi) {
  return static_cast<priv_linux*>(wi->wi_priv);
};


int wif::do_linux_open(char const * iface) {
	priv_linux * dev = ::wi_priv(this);
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

static int openraw(
				   char const * iface,
				   int fd,
				   int * arptype)
{
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

int wif::read(unsigned char * buf,
					    int count,
					    struct rx_info * ri)
{
	struct priv_linux * dev = ::wi_priv(this);
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

int wif::fd() {
	struct priv_linux * pl = ::wi_priv(this);
	return pl->fd_in;
}

static int ieee80211_channel_to_frequency(int chan)
{
	if (chan < 14) return 2407 + chan * 5;

	if (chan == 14) return 2484;

	/* FIXME: dot11ChannelStartingFactor (802.11-2007 17.3.8.3.2) */
	return (chan + 1000) * 5;
}

static int
linux_set_ht_channel_nl80211(struct wif * wi, int channel)
{
	struct priv_linux * dev = wi_priv(wi);
	char s[32];
	// int pid, status;

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

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devid);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);

	unsigned ht = NL80211_CHAN_NO_HT;
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, ht);

	nl_send_auto_complete(state.nl_sock, msg);
	nlmsg_free(msg);

	dev->channel = channel;

	return (0);
nla_put_failure:
	return -ENOBUFS;
}