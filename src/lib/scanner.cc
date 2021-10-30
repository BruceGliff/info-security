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
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

// it is from library
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

#define MAX_CARDS 8

static int bg_chans[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0};
static struct local_options
{
	//struct AP_info *ap_1st, *ap_end;
	//struct ST_info *st_1st, *st_end;
	//struct NA_info * na_1st;
	//struct oui * manufList;

	unsigned char prev_bssid[6];
	char ** f_essid;
	int f_essid_count;
//#ifdef HAVE_PCRE
//	pcre * f_essid_regex;
//#endif
	char * dump_prefix;
	char * keyout;

	char * batt; /* Battery string       */
	int channel[MAX_CARDS]; /* current channel #    */
	int frequency[MAX_CARDS]; /* current frequency #    */
	int ch_pipe[2]; /* current channel pipe */
	int cd_pipe[2]; /* current card pipe    */
	int gc_pipe[2]; /* gps coordinates pipe */
	float gps_loc[8]; /* gps coordinates      */
	int save_gps; /* keep gps file flag   */
	int gps_valid_interval; /* how many seconds until we consider the GPS data invalid if we dont get new data */

	int * channels;
	int singlechan; /* channel hopping set 1*/
	int singlefreq; /* frequency hopping: 1 */
	int chswitch; /* switching method     */
	unsigned int f_encrypt; /* encryption filter    */
	int update_s; /* update delay in sec  */

	volatile int do_exit; /* interrupt flag       */
	//struct winsize ws; /* console window size  */

	char * elapsed_time; /* capture time			*/

	int one_beacon; /* Record only 1 beacon?*/

	int * own_channels; /* custom channel list  */
	int * own_frequencies; /* custom frequency list  */

	int asso_client; /* only show associated clients */

	unsigned char wpa_bssid[6]; /* the wpa handshake bssid   */
	char message[512];
	char decloak;

	char is_berlin; /* is the switch --berlin set? */
	int numaps; /* number of APs on the current list */
	int maxnumaps; /* maximum nubers of APs on the list */
	int maxaps; /* number of all APs found */
	int berlin; /* number of seconds it takes in berlin to fill the whole screen
				   with APs*/
	/*
	 * The name for this option may look quite strange, here is the story behind
	 * it:
	 * During the CCC2007, 10 august 2007, we (hirte, Mister_X) went to visit
	 * Berlin
	 * and couldn't resist to turn on airodump-ng to see how much access point
	 * we can
	 * get during the trip from Finowfurt to Berlin. When we were in Berlin, the
	 * number
	 * of AP increase really fast, so fast that it couldn't fit in a screen,
	 * even rotated;
	 * the list was really huge (we have a picture of that). The 2 minutes
	 * timeout
	 * (if the last packet seen is higher than 2 minutes, the AP isn't shown
	 * anymore)
	 * wasn't enough, so we decided to create a new option to change that
	 * timeout.
	 * We implemented this option in the highest tower (TV Tower) of Berlin,
	 * eating an ice.
	 */

	int show_ap;
	int show_sta;
	int show_ack;
	int hide_known;

	int hopfreq;

	char * s_iface; /* source interface to read from */
	FILE * f_cap_in;
	//struct pcap_file_header pfh_in;
	int detect_anomaly; /* Detect WIPS protecting WEP in action */

	char * freqstring;
	int freqoption;
	int chanoption;
	int active_scan_sim; /* simulates an active scan, sending probe requests */

	/* Airodump-ng start time: for kismet netxml file */
	char * airodump_start_time;

	pthread_t input_tid;
	pthread_t gps_tid;
	int sort_by;
	int sort_inv;
	int start_print_ap;
	int start_print_sta;
	//struct AP_info * p_selected_ap;
	enum
	{
		selection_direction_down,
		selection_direction_up,
		selection_direction_no
	} en_selection_direction;
	int mark_cur_ap;
	int num_cards;
	int do_pause;
	int do_sort_always;

	pthread_mutex_t mx_print; /* lock write access to ap LL   */
	pthread_mutex_t mx_sort; /* lock write access to ap LL   */

	unsigned char selected_bssid[6]; /* bssid that is selected */

	u_int maxsize_essid_seen;
	int show_manufacturer;
	int show_uptime;
	int file_write_interval;
	u_int maxsize_wps_seen;
	int show_wps;
	//struct tm gps_time; /* the timestamp from the gps data */
//#ifdef CONFIG_LIBNL
	unsigned int htval;
//#endif
	int background_mode;

	unsigned long min_pkts;

	int relative_time; /* read PCAP in psuedo-real-time */
} lopt;


void do_free(struct wif *wi);
void set_lopt();
static int getchancount(int valid)
{
	int i = 0, chan_count = 0;

	while (lopt.channels[i])
	{
		i++;
		if (lopt.channels[i] != -1) chan_count++;
	}

	if (valid) return (chan_count);
	return (i);
}

scanner::scanner(char const *iface)
  : wi{open(iface)} {
    set_lopt();
    launch();
}
void erase_display(int n)
{
	char command[13];

	snprintf(command, sizeof(command), "%c[%dJ", 0x1B, n);
	fprintf(stdout, "%s", command);
	fflush(stdout);
}
static void sighandler(int signum)
{
	int card = 0;

	if (signum == SIGUSR1)
	{
		ssize_t unused = read(lopt.cd_pipe[0], &card, sizeof(int));
		if (unused < 0)
		{
			// error occurred
			perror("read");
			return;
		}
		else if (unused == 0)
		{
			// EOF
			perror("EOF encountered read(opt.cd_pipe[0])");
			return;
		}
    read(lopt.ch_pipe[0], &(lopt.channel[card]), sizeof(int));
	}

	if (signum == SIGUSR2)
		read(lopt.gc_pipe[0], &lopt.gps_loc, sizeof(lopt.gps_loc));

	if (signum == SIGINT || signum == SIGTERM)
	{
		lopt.do_exit = 1;
		// show_cursor();
		// reset_term();
		fprintf(stdout, "Quitting...\n");
	}

	if (signum == SIGSEGV)
	{
		fprintf(stderr,
				"Caught signal 11 (SIGSEGV). Please"
				" contact the author!\n\n");
		//show_cursor();
		fflush(stdout);
		exit(1);
	}

	if (signum == SIGALRM)
	{
		fprintf(stdout,
				"Caught signal 14 (SIGALRM). Please"
				" contact the author!\n\n");
		//show_cursor();
		exit(1);
	}

	if (signum == SIGCHLD) wait(NULL);

	if (signum == SIGWINCH)
	{
		erase_display(0);
		fflush(stdout);
	}
}
#define PROBE_REQ "\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC" "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"
#define RATES "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"
#define LINKTYPE_IEEE802_11 105//DLT_IEEE802_11
static inline uint8_t rand_u8(void)
{
	// coverity[dont_call]
	return (uint8_t)(
		rand()
		& 0xFFU); // NOLINT(cert-msc30-c,cert-msc50-cpp,hicpp-signed-bitwise)
}
static int send_probe_request(struct wif * wi)
{
	int len;
	uint8_t p[4096], r_smac[6];

	memcpy(p, PROBE_REQ, 24);

	len = 24;

	p[24] = 0x00; // ESSID Tag Number
	p[25] = 0x00; // ESSID Tag Length

	len += 2;

	memcpy(p + len, RATES, 16);

	len += 16;

	r_smac[0] = 0x00;
	r_smac[1] = rand_u8();
	r_smac[2] = rand_u8();
	r_smac[3] = rand_u8();
	r_smac[4] = rand_u8();
	r_smac[5] = rand_u8();

	memcpy(p + 10, r_smac, 6);

	if (wi->wi_write(wi, NULL, LINKTYPE_IEEE802_11, p, len, NULL) == -1)
	{
		switch (errno)
		{
			case EAGAIN:
			case ENOBUFS:
				usleep(10000);
				return (0); /* XXX not sure I like this... -sorbo */
			default:
				break;
		}

		perror("wi_write()");
		return (-1);
	}

	return (0);
}
static void
channel_hopper(struct wif * wi, int if_num, int chan_count, pid_t parent)
{
  printf("hopper\n");
	int ch, ch_idx = 0, card = 0, chi = 0, cai = 0, j = 0, k = 0, first = 1,
			again;
	int dropped = 0;

	while (0 == kill(parent, 0))
	{
    printf("ASD\n");
		for (j = 0; j < if_num; j++)
		{
			again = 1;

			ch_idx = chi % chan_count;

			card = cai % if_num;

			++chi;
			++cai;

			if (lopt.chswitch == 2 && !first)
			{
				j = if_num - 1;
				card = if_num - 1;

				if (getchancount(1) > if_num)
				{
					while (again)
					{
						again = 0;
						for (k = 0; k < (if_num - 1); k++)
						{
							if (lopt.channels[ch_idx] == lopt.channel[k])
							{
								again = 1;
								ch_idx = chi % chan_count;
								chi++;
							}
						}
					}
				}
			}

			if (lopt.channels[ch_idx] == -1)
			{
				j--;
				cai--;
				dropped++;
				if (dropped >= chan_count)
				{
          assert(card == 0); // it is because i have only wi
					//ch = wi_get_channel(wi[card]);
          ch = wi->wi_get_channel(wi);
					lopt.channel[card] = ch;
					write(lopt.cd_pipe[1], &card, sizeof(int));
					write(lopt.ch_pipe[1], &ch, sizeof(int));
					kill(parent, SIGUSR1);
					usleep(1000);
				}
				continue;
			}

			dropped = 0;

			ch = lopt.channels[ch_idx];

//#ifdef CONFIG_LIBNL
			//if (wi_set_ht_channel(wi[card], ch, lopt.htval) == 0)
      if (wi->wi_set_ht_channel(wi, ch, lopt.htval) == 0)
//#else

			{
				lopt.channel[card] = ch;
				write(lopt.cd_pipe[1], &card, sizeof(int));
				write(lopt.ch_pipe[1], &ch, sizeof(int));
				if (lopt.active_scan_sim > 0) /*send_probe_request(wi[card])*/send_probe_request(wi);
				kill(parent, SIGUSR1);
				usleep(1000);
			}
			else
			{
				lopt.channels[ch_idx] = -1; /* remove invalid channel */
				j--;
				cai--;
				continue;
			}
		}

		if (lopt.chswitch == 0)
		{
			chi = chi - (if_num - 1);
		}

		if (first)
		{
			first = 0;
		}

		usleep((useconds_t)(lopt.hopfreq * 1000));
	}

	exit(0);
}


void scanner::launch() {
  int fd_raw = wi->wi_fd(wi);
  int fdh = fd_raw > 0 ? fd_raw : 0;
  int chan_count = getchancount(0);

  pid_t main_pid = getpid();

	pipe(lopt.ch_pipe);
	pipe(lopt.cd_pipe);

  struct sigaction action;
  action.sa_flags = 0;
  action.sa_handler = &sighandler;
  sigemptyset(&action.sa_mask);

  if (sigaction(SIGUSR1, &action, NULL) == -1)
    perror("sigaction(SIGUSR1)");

  if (!fork())
  {
    /* reopen cards.  This way parent & child don't share
    * resources for
    * accessing the card (e.g. file descriptors) which may cause
    * problems.  -sorbo
    */
    char ifnam[64];
    strncpy(ifnam, wi->wi_interface, sizeof(ifnam));

    wi->wi_close(wi);
    wi = open(ifnam);
    if (!wi)
    {
      printf("Can't reopen %s\n", ifnam);
      exit(EXIT_FAILURE);
    }

    /* Drop privileges */
    if (setuid(getuid()) == -1)
    {
      perror("setuid");
    }

    channel_hopper(wi, lopt.num_cards, chan_count, main_pid);
    exit(EXIT_FAILURE);
  }
  // printf("parent");

}






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
static void nl80211_cleanup(struct nl80211_state * state)
{
	genl_family_put(state->nl80211);
	nl_cache_free(state->nl_cache);
	nl_socket_free(state->nl_sock);
}
static void linux_close_nl80211(struct wif *wi) {
	struct priv_linux * pl = (priv_linux *)wi->wi_priv;
	nl80211_cleanup(&state);

	if (pl->fd_in) close(pl->fd_in);
	if (pl->fd_out) close(pl->fd_out);

	do_free(wi);
}

static int linux_fd(struct wif *wi) {
  struct priv_linux * pl = (priv_linux* )wi->wi_priv;
	return pl->fd_in;
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

void do_free(struct wif *wi) {
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
    printf("Do not opened\n");
    do_free(wi);
    return NULL;
  }
  strncpy(wi->wi_interface, iface, sizeof(wi->wi_interface) - 1);
	wi->wi_interface[sizeof(wi->wi_interface) - 1] = 0;
  return wi;
}


void set_lopt() {
  lopt.chanoption = 0;
	lopt.freqoption = 0;
	lopt.num_cards = 0;
//	fdh = 0;
//	time_slept = 0;
	lopt.batt = NULL;
	lopt.chswitch = 0;
//	opt.usegpsd = 0;
	lopt.channels = (int *) bg_chans;
	lopt.one_beacon = 1;
	lopt.singlechan = 0;
	lopt.singlefreq = 0;
	lopt.dump_prefix = NULL;
	
	lopt.keyout = NULL;
	
	lopt.f_encrypt = 0;
	lopt.asso_client = 0;
	lopt.f_essid = NULL;
	lopt.f_essid_count = 0;
	lopt.active_scan_sim = 0;
	lopt.update_s = 0;
	lopt.decloak = 1;
	lopt.is_berlin = 0;
	lopt.numaps = 0;
	lopt.maxnumaps = 0;
	lopt.berlin = 120;
	lopt.show_ap = 1;
	lopt.show_sta = 1;
	lopt.show_ack = 0;
	lopt.hide_known = 0;
	lopt.maxsize_essid_seen = 5; // Initial value: length of "ESSID"
	lopt.show_manufacturer = 0;
	lopt.show_uptime = 0;
//	lopt.hopfreq = DEFAULT_HOPFREQ;

	lopt.s_iface = NULL;
	lopt.f_cap_in = NULL;
	lopt.detect_anomaly = 0;
	lopt.airodump_start_time = NULL;
//	lopt.manufList = NULL;

	lopt.gps_valid_interval
		= 5; // If we dont get a new GPS update in 5 seconds - invalidate it
	lopt.file_write_interval = 5; // Write file every 5 seconds by default
	lopt.maxsize_wps_seen = 6;
	lopt.show_wps = 0;
	lopt.background_mode = -1;
	lopt.do_exit = 0;
	lopt.min_pkts = 2;
	lopt.relative_time = 0;
//#ifdef CONFIG_LIBNL
//	lopt.htval = CHANNEL_NO_HT;
//#endif
//#ifdef HAVE_PCRE
//	lopt.f_essid_regex = NULL;
//#endif
}