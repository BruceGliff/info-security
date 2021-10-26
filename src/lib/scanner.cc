#include <scanner.h>

#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// it is from library
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

scanner::scanner(char const *iface) : wi{open(iface)} {}

struct nl80211_state {
  // #if !defined(CONFIG_LIBNL30) && !defined(CONFIG_LIBNL20)
  // 	struct nl_handle * nl_sock;
  // #else
  struct nl_sock *nl_sock;
  //#endif
  struct nl_cache *nl_cache;
  struct genl_family *nl80211;
} state;
static int linux_nl80211_init(struct nl80211_state *state) {
  int err;

  state->nl_sock = nl_socket_alloc();

  if (!state->nl_sock) {
    fprintf(stderr, "Failed to allocate netlink socket.\n");
    return -1;
  }

  if (genl_connect(state->nl_sock)) {
    fprintf(stderr, "Failed to connect to generic netlink.\n");
    err = -1;
    goto out_handle_destroy;
  }

  if (genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache)) {
    fprintf(stderr, "Failed to allocate generic netlink cache.\n");
    err = -1;
    goto out_handle_destroy;
  }

  state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
  if (!state->nl80211) {
    fprintf(stderr, "nl80211 not found.\n");
    err = -1;
    goto out_cache_free;
  }

  return 0;

out_cache_free:
  nl_cache_free(state->nl_cache);
out_handle_destroy:
  nl_socket_free(state->nl_sock);
  return err;
}

typedef enum {
  DT_NULL = 0,
  DT_WLANNG,
  DT_HOSTAP,
  DT_MADWIFI,
  DT_MADWIFING,
  DT_BCM43XX,
  DT_ORINOCO,
  DT_ZD1211RW,
  DT_ACX,
  DT_MAC80211_RT,
  DT_AT76USB,
  DT_IPW2200
} DRIVER_TYPE;

struct priv_linux {
  int fd_in, arptype_in;
  int fd_out, arptype_out;
  int fd_main;
  int fd_rtc;

  DRIVER_TYPE drivertype; /* inited to DT_UNKNOWN on allocation by wi_alloc */

  FILE *f_cap_in;

  // struct pcap_file_header pfh_in;

  int sysfs_inject;
  int channel;
  int freq;
  int rate;
  int tx_power;
  char *wlanctlng; /* XXX never set */
  char *iwpriv;
  char *iwconfig;
  char *ifconfig;
  char *wl;
  char *main_if;
  unsigned char pl_mac[6];
  int inject_wlanng;
};

wif *wi_alloc(uint32_t sz) {
  wif *wi;
  void *priv;
  wi = (wif *)malloc(sizeof(*wi));
  if (!wi)
    return NULL;
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

static int linux_read(struct wif *wi, struct timespec *ts, int *dlt,
                      unsigned char *buf, int count, struct rx_info *ri) {
  printf("placeholder linux_read\n");
  return 0;
}
static int linux_write(struct wif *wi, struct timespec *ts, int dlt,
                       unsigned char *buf, int count, struct tx_info *ti) {
  printf("placeholder linux_write\n");
  return 0;
}
static int linux_set_channel_nl80211(struct wif *wi, int channel) {
  printf("placeholder linux_set_channel_nl80211\n");
  return 0;
}
static int linux_set_ht_channel_nl80211(struct wif *wi, int channel,
                                        unsigned int htval) {
  printf("placeholder linux_set_ht_channel_nl80211\n");
  return 0;
}
static int linux_get_channel(struct wif *wi) {
  printf("placeholder linux_get_channel\n");
  return 0;
}
static int linux_set_freq(struct wif *wi, int freq) {
  printf("placeholder linux_set_freq\n");
  return 0;
}
static int linux_get_freq(struct wif *wi) {
  printf("placeholder linux_get_freq\n");
  return 0;
}
static void linux_close_nl80211(struct wif *wi) {
  printf("placeholder linux_close_nl80211\n");
}
static int linux_fd(struct wif *wi) {
  printf("placeholder linux_close_nl80211\n");
  return 0;
}
static int linux_get_mac(struct wif *wi, unsigned char *mac) {
  printf("placeholder linux_get_mac\n");
  return 0;
}
static int linux_set_mac(struct wif *wi, unsigned char *mac) {
  printf("placeholder linux_get_mac\n");
  return 0;
}
static int linux_get_monitor(struct wif *wi) {
  printf("placeholder linux_get_monitor\n");
  return 0;
}
static int linux_get_rate(struct wif *wi) {
  printf("placeholder linux_get_rate\n");
  return 0;
}
static int linux_set_rate(struct wif *wi, int rate) {
  printf("placeholder linux_set_rate\n");
  return 0;
}
static int linux_get_mtu(struct wif *wi) {
  printf("placeholder linux_get_mtu\n");
  return 0;
}
static int linux_set_mtu(struct wif *wi, int mtu) {
  printf("placeholder linux_set_mtu\n");
  return 0;
}
static char *searchInside(const char *dir, const char *filename) {
  char *ret;
  char *curfile;
  struct stat sb;
  int len, lentot;
  DIR *dp;
  struct dirent *ep;

  dp = opendir(dir);
  if (dp == NULL) {
    return NULL;
  }

  len = strlen(filename);
  lentot = strlen(dir) + 256 + 2;
  curfile = (char *)calloc(1, lentot);
  if (curfile == NULL) {
    (void)closedir(dp);
    return (NULL);
  }

  while ((ep = readdir(dp)) != NULL) {

    memset(curfile, 0, lentot);
    sprintf(curfile, "%s/%s", dir, ep->d_name);

    // Checking if it's the good file
    if ((int)strlen(ep->d_name) == len && !strcmp(ep->d_name, filename)) {
      (void)closedir(dp);
      return curfile;
    }

    // If it's a directory and not a link, try to go inside to search
    if (lstat(curfile, &sb) == 0 && S_ISDIR(sb.st_mode) &&
        !S_ISLNK(sb.st_mode)) {
      // Check if the directory isn't "." or ".."
      if (strcmp(".", ep->d_name) && strcmp("..", ep->d_name)) {
        // Recursive call
        ret = searchInside(curfile, filename);
        if (ret != NULL) {
          (void)closedir(dp);
          free(curfile);
          return ret;
        }
      }
    }
  }
  (void)closedir(dp);
  free(curfile);
  return NULL;
}
static char *wiToolsPath(const char *tool) {
  char *path /*, *found, *env */;
  int i, nbelems;
  static const char *paths[] = {"/sbin", "/usr/sbin", "/usr/local/sbin",
                                "/bin",  "/usr/bin",  "/usr/local/bin",
                                "/tmp"};

  // Also search in other known location just in case we haven't found it yet
  nbelems = sizeof(paths) / sizeof(char *);
  for (i = 0; i < nbelems; i++) {
    path = searchInside(paths[i], tool);
    if (path != NULL)
      return path;
  }

  return NULL;
}
static int openraw(struct priv_linux *dev, char const *iface, int fd,
                   int *arptype, unsigned char *mac) {
  struct ifreq ifr;
  struct iwreq wrq;
  struct packet_mreq mr;
  struct sockaddr_ll sll;

  if (strlen(iface) >= sizeof(ifr.ifr_name)) {
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

  /* lookup the hardware type */

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
    printf("Interface %s: \n", iface);
    perror("ioctl(SIOCGIFHWADDR) failed");
    return (1);
  }

  /* lookup iw mode */
  memset(&wrq, 0, sizeof(struct iwreq));
  strncpy(wrq.ifr_name, iface, IFNAMSIZ);
  wrq.ifr_name[IFNAMSIZ - 1] = 0;

  if (ioctl(fd, SIOCGIWMODE, &wrq) < 0) {
    /* most probably not supported (ie for rtap ipw interface) *
     * so just assume its correctly set...                     */
    wrq.u.mode = IW_MODE_MONITOR;
  }

  /* Is interface st to up, broadcast & running ? */
  if ((ifr.ifr_flags | IFF_UP | IFF_BROADCAST | IFF_RUNNING) != ifr.ifr_flags) {
    /* Bring interface up*/
    ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
      perror("ioctl(SIOCSIFFLAGS) failed");
      return (1);
    }
  }
  /* bind the raw socket to the interface */

  if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) //-V641
  {
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

  memcpy(mac, (unsigned char *)ifr.ifr_hwaddr.sa_data, 6); //-V512

  *arptype = ifr.ifr_hwaddr.sa_family;

  /* enable promiscuous mode */

  memset(&mr, 0, sizeof(mr));
  mr.mr_ifindex = sll.sll_ifindex;
  mr.mr_type = PACKET_MR_PROMISC;

  if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
    perror("setsockopt(PACKET_MR_PROMISC) failed");
    return (1);
  }

  return (0);
}
static int do_linux_open(struct wif *wi, char const *iface) {
  struct priv_linux *dev = (priv_linux *)wi->wi_priv;
  char strbuf[512];

  dev->inject_wlanng = 1;
  dev->rate = 2; /* default to 1Mbps if nothing is set */

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

  dev->iwpriv = wiToolsPath("iwpriv");
  dev->iwconfig = wiToolsPath("iwconfig");
  dev->ifconfig = wiToolsPath("ifconfig");

  if (!(dev->iwpriv)) {
    fprintf(stderr, "Required wireless tools when compiled without libnl "
                    "could not be found, exiting.\n");
    goto close_in;
  }

  if ((dev->fd_out = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket(PF_PACKET) failed");
    goto close_in;
  }
  /* figure out device type */

  /* mac80211 radiotap injection
   * detected based on interface called mon...
   * since mac80211 allows multiple virtual interfaces
   *
   * note though that the virtual interfaces are ultimately using a
   * single physical radio: that means for example they must all
   * operate on the same channel
   */

  /* mac80211 stack detection */
  memset(strbuf, 0, sizeof(strbuf));
  snprintf(strbuf, sizeof(strbuf) - 1,
           "ls /sys/class/net/%s/phy80211/subsystem >/dev/null 2>/dev/null",
           iface);

  if (system(strbuf) == 0)
    dev->drivertype = DT_MAC80211_RT;
  else
    assert(0 && "Only MAC80211_RT");

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

static void do_free(struct wif *wi) {
  struct priv_linux *pl = (priv_linux *)wi->wi_priv;

  if (pl->wlanctlng)
    free(pl->wlanctlng);

  if (pl->iwpriv)
    free(pl->iwpriv);

  if (pl->iwconfig)
    free(pl->iwconfig);

  if (pl->ifconfig)
    free(pl->ifconfig);

  if (pl->wl)
    free(pl->wl);

  if (pl->main_if)
    free(pl->main_if);

  free(pl);
  free(wi);
}

// static
wif *scanner::open(char const *iface) {
  assert(iface && "empty iface");

  wif *wi;
  priv_linux *pl;
  wi = wi_alloc(sizeof(*pl));

  wi->wi_read = linux_read;
  wi->wi_write = linux_write;

  linux_nl80211_init(&state);
  wi->wi_set_ht_channel = linux_set_ht_channel_nl80211;
  wi->wi_set_channel = linux_set_channel_nl80211;

  wi->wi_get_channel = linux_get_channel;
  wi->wi_set_freq = linux_set_freq;
  wi->wi_get_freq = linux_get_freq;
  wi->wi_close = linux_close_nl80211;
  wi->wi_fd = linux_fd;
  wi->wi_get_mac = linux_get_mac;
  wi->wi_set_mac = linux_set_mac;
  wi->wi_get_monitor = linux_get_monitor;
  wi->wi_get_rate = linux_get_rate;
  wi->wi_set_rate = linux_set_rate;
  wi->wi_get_mtu = linux_get_mtu;
  wi->wi_set_mtu = linux_set_mtu;

  if (do_linux_open(wi, iface)) {
    do_free(wi);
    return NULL;
  }

  return wi;
}
