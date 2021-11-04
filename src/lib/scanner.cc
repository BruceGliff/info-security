#include <scanner.h>

#include <station.h>
#include <uniqueiv.h>
#include <pcap_local.h>

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
#include <ctype.h>
#include <pthread.h>

// it is from library
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

#define MAX_CARDS 8

#define MIN(x,y) ((x) > (y) ? (y) : (x))

static int bg_chans[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0};
struct oui
{
	char id[9]; /* TODO: Don't use ASCII chars to compare, use unsigned char[3]
				   (later) with the value (hex ascii will have to be converted)
				   */
	char
		manuf[128]; /* TODO: Switch to a char * later to improve memory usage */
	struct oui * next;
};
static struct local_options
{
	struct AP_info *ap_1st, *ap_end;
	struct ST_info *st_1st, *st_end;
	struct NA_info * na_1st;
	struct oui * manufList;

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
float get_80211n_rate(const int width,
					  const int is_short_GI,
					  const int mcs_index);
float get_80211ac_rate(const int width,
					   const int is_short_GI,
					   const int mcs_idx,
					   const int amount_ss);
void set_lopt();
void printAT_ST();
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
#define NULL_MAC (unsigned char *) "\x00\x00\x00\x00\x00\x00"
#define BROADCAST (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF"
#define SPANTREE (unsigned char *) "\x01\x80\xC2\x00\x00\x00"
#define CDP_VTP (unsigned char *) "\x01\x00\x0C\xCC\xCC\xCC"

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

char * get_manufacturer_from_string(char * buffer)
{
	char * manuf = NULL;
	char * buffer_manuf;
	if (buffer != NULL && strlen(buffer) > 0)
	{
		buffer_manuf = strstr(buffer, "(hex)");
		if (buffer_manuf != NULL)
		{
			buffer_manuf += 6; // skip '(hex)' and one more character (there's
			// at least one 'space' character after that
			// string)
			while (*buffer_manuf == '\t' || *buffer_manuf == ' ')
			{
				++buffer_manuf;
			}

			// Did we stop at the manufacturer
			if (*buffer_manuf != '\0')
			{
				const int buffer_manuf_len_minus_1 = strlen(buffer_manuf);

				// First make sure there's no end of line
				if (buffer_manuf[buffer_manuf_len_minus_1] == '\n'
					|| buffer_manuf[buffer_manuf_len_minus_1] == '\r')
				{
					buffer_manuf[buffer_manuf_len_minus_1] = '\0';
					if (buffer_manuf_len_minus_1 >= 1
						&& (buffer_manuf[buffer_manuf_len_minus_1 - 1] == '\n'
							|| buffer[buffer_manuf_len_minus_1 - 1] == '\r'))
					{
						buffer_manuf[buffer_manuf_len_minus_1 - 1] = '\0';
					}
				}
				if (*buffer_manuf != '\0')
				{
					if ((manuf = (char *) malloc((strlen(buffer_manuf) + 1)
												 * sizeof(char)))
						== NULL)
					{
						perror("malloc failed");
						return (NULL);
					}
					snprintf(
						manuf, strlen(buffer_manuf) + 1, "%s", buffer_manuf);
				}
			}
		}
	}

	return (manuf);
}

static inline void ltrim(char * str)
{
	size_t i;
	size_t begin = 0u;
	size_t end = strlen(str) - 1u;

	while (isspace((int) str[begin])) begin++;

	// Shift all characters back to the start of the string array.
	for (i = begin; i <= end; i++) str[i - begin] = str[i];

	// Ensure the string is null terminated.
	str[i - begin] = '\0';
}

/// Return \a str with all trailing whitespace removed.
static inline void rtrim(char * str)
{
	size_t end = strlen(str) - 1u;

	while ((end != 0) && isspace((int) str[end])) end--;

	// Ensure the string is null terminated.
	str[end + 1] = '\0';
}

/// Return \a str with all leading and trailing whitespace removed.
static inline void trim(char * str)
{
	ltrim(str);
	rtrim(str);
}

static struct oui * load_oui_file(void)
{
	FILE * fp;
	char * manuf;
	char buffer[BUFSIZ];
	unsigned char a[2];
	unsigned char b[2];
	unsigned char c[2];
	struct oui *oui_ptr = NULL, *oui_head = NULL;

	fp = fopen("/var/lib/ieee-data/oui.txt", "r");
	if (!fp)
	{
    perror("file oui.txt");
		return (NULL);
	}

	memset(buffer, 0x00, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer), fp) != NULL)
	{
		if (!(strstr(buffer, "(hex)"))) continue;

		memset(a, 0x00, sizeof(a));
		memset(b, 0x00, sizeof(b));
		memset(c, 0x00, sizeof(c));
		// Remove leading/trailing whitespaces.
		trim(buffer);
		if (sscanf(buffer, "%2c-%2c-%2c", (char *) a, (char *) b, (char *) c)
			== 3)
		{
			if (oui_ptr == NULL)
			{
				if (!(oui_ptr = (struct oui *) malloc(sizeof(struct oui))))
				{
					fclose(fp);
					perror("malloc failed");
					return (NULL);
				}
			}
			else
			{
				if (!(oui_ptr->next
					  = (struct oui *) malloc(sizeof(struct oui))))
				{
					fclose(fp);
					perror("malloc failed");

					while (oui_head != NULL)
					{
						oui_ptr = oui_head->next;
						free(oui_head);
						oui_head = oui_ptr;
					}
					return (NULL);
				}
				oui_ptr = oui_ptr->next;
			}
			memset(oui_ptr->id, 0x00, sizeof(oui_ptr->id));
			memset(oui_ptr->manuf, 0x00, sizeof(oui_ptr->manuf));
			snprintf(oui_ptr->id,
					 sizeof(oui_ptr->id),
					 "%c%c:%c%c:%c%c",
					 a[0],
					 a[1],
					 b[0],
					 b[1],
					 c[0],
					 c[1]);
			manuf = get_manufacturer_from_string(buffer);
			if (manuf != NULL)
			{
				snprintf(oui_ptr->manuf, sizeof(oui_ptr->manuf), "%s", manuf);
				free(manuf);
			}
			else
			{
				snprintf(oui_ptr->manuf, sizeof(oui_ptr->manuf), "Unknown");
			}
			if (oui_head == NULL) oui_head = oui_ptr;
			oui_ptr->next = NULL;
		}
	}

	fclose(fp);
	return (oui_head);
}

int is_background(void)
{
	pid_t grp = tcgetpgrp(STDIN_FILENO);
	if (grp == -1)
	{
		// Piped
		return 0;
	}

	if (grp == getpgrp())
	{
		// Foreground
		return 0;
	}

	// Background
	return 1;
}

static int check_monitor(struct wif * wi, int * fd_raw, int * fdh, int cards)
{
	int i, monitor;
	char ifname[64];

	for (i = 0; i < cards; i++)
	{
		monitor = wi->wi_get_monitor(wi);
		if (monitor != 0)
		{
			memset(lopt.message, '\x00', sizeof(lopt.message));
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ %s reset to monitor mode",
					 wi->wi_interface);
			// reopen in monitor mode

			strncpy(ifname, wi->wi_interface, sizeof(ifname));

      wi->wi_close(wi);
      wi = scanner::open(wi->wi_interface);
      printf("reopening\n");
			if (wi)
			{
				printf("Can't reopen %s\n", ifname);
				exit(1);
			}

      fd_raw[i] = wi->wi_fd(wi);
			if (fd_raw[i] > *fdh) *fdh = fd_raw[i];
		}
	}
	return (0);
}

#define	IEEE80211_ADDR_LEN	6		/* size of 802.11 address */
/* is 802.11 address multicast/broadcast? */
#define	IEEE80211_IS_MULTICAST(_a)	(*(_a) & 0x01)
#define	IEEE80211_FC0_VERSION_MASK		0x03
#define	IEEE80211_FC0_VERSION_SHIFT		0
#define	IEEE80211_FC0_VERSION_0			0x00
#define	IEEE80211_FC0_TYPE_MASK			0x0c
#define	IEEE80211_FC0_TYPE_SHIFT		2
#define	IEEE80211_FC0_TYPE_MGT			0x00
#define	IEEE80211_FC0_TYPE_CTL			0x04
#define	IEEE80211_FC0_TYPE_DATA			0x08
#define	IEEE80211_FC1_DIR_MASK			0x03
#define	IEEE80211_FC1_DIR_NODS			0x00	/* STA->STA */
#define	IEEE80211_FC1_DIR_TODS			0x01	/* STA->AP  */
#define	IEEE80211_FC1_DIR_FROMDS		0x02	/* AP ->STA */
#define	IEEE80211_FC1_DIR_DSTODS		0x03	/* AP ->AP  */
#define	IEEE80211_FC0_SUBTYPE_ASSOC_REQ		0x00
#define	IEEE80211_FC0_SUBTYPE_ASSOC_RESP	0x10
#define	IEEE80211_FC0_SUBTYPE_REASSOC_REQ	0x20
#define	IEEE80211_FC0_SUBTYPE_REASSOC_RESP	0x30
#define	IEEE80211_FC0_SUBTYPE_PROBE_REQ		0x40
#define	IEEE80211_FC0_SUBTYPE_PROBE_RESP	0x50
#define	IEEE80211_FC0_SUBTYPE_BEACON		0x80
#define	IEEE80211_FC0_SUBTYPE_ATIM		0x90
#define	IEEE80211_FC0_SUBTYPE_DISASSOC		0xa0
#define	IEEE80211_FC0_SUBTYPE_AUTH		0xb0
#define	IEEE80211_FC0_SUBTYPE_DEAUTH		0xc0

#define HIGHEST_CHANNEL 220
#define STD_OPN 0x0001u
#define STD_WEP 0x0002u
#define STD_WPA 0x0004u
#define STD_WPA2 0x0008u

#define STD_FIELD (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)

#define ENC_WEP 0x0010u
#define ENC_TKIP 0x0020u
#define ENC_WRAP 0x0040u
#define ENC_CCMP 0x0080u
#define ENC_WEP40 0x1000u
#define ENC_WEP104 0x0100u
#define ENC_GCMP 0x4000u
#define ENC_GMAC 0x8000u

#define ENC_FIELD                                                              \
	(ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP40 | ENC_WEP104         \
	 | ENC_GCMP                                                                \
	 | ENC_GMAC)

#define AUTH_OPN 0x0200u
#define AUTH_PSK 0x0400u
#define AUTH_MGT 0x0800u
#define AUTH_CMAC 0x10000u
#define AUTH_SAE 0x20000u
#define AUTH_OWE 0x40000u

#define AUTH_FIELD                                                             \
	(AUTH_OPN | AUTH_PSK | AUTH_CMAC | AUTH_MGT | AUTH_SAE | AUTH_OWE)

#define STD_QOS 0x2000u

struct ieee80211_frame {
	u_int8_t	i_fc[2];
	u_int8_t	i_dur[2];
	u_int8_t	i_addr1[IEEE80211_ADDR_LEN];
	u_int8_t	i_addr2[IEEE80211_ADDR_LEN];
	u_int8_t	i_addr3[IEEE80211_ADDR_LEN];
	u_int8_t	i_seq[2];
};


static int remove_namac(unsigned char * mac)
{
	struct NA_info * na_cur = NULL;
	struct NA_info * na_prv = NULL;

	if (mac == NULL) return (-1);

	na_cur = lopt.na_1st;
	na_prv = NULL;

	while (na_cur != NULL)
	{
		if (!memcmp(na_cur->namac, mac, 6)) break;

		na_prv = na_cur;
		na_cur = na_cur->next;
	}

	/* if it's known, remove it */
	if (na_cur != NULL)
	{
		/* first in linked list */
		if (na_cur == lopt.na_1st)
		{
			lopt.na_1st = na_cur->next;
		}
		else
		{
			na_prv->next = na_cur->next;
		}
		free(na_cur);
	}

	return (0);
}

#define OUI_STR_SIZE 8
#define MANUF_SIZE 128
static char *
get_manufacturer(unsigned char mac0, unsigned char mac1, unsigned char mac2)
{
	char oui[OUI_STR_SIZE + 1];
	char *manuf, *rmanuf;
	char * manuf_str;
	struct oui * ptr;
	FILE * fp;
	char buffer[BUFSIZ];
	char temp[OUI_STR_SIZE + 1];
	unsigned char a[2];
	unsigned char b[2];
	unsigned char c[2];
	int found = 0;
	size_t oui_len;

	if ((manuf = (char *) calloc(1, MANUF_SIZE * sizeof(char))) == NULL)
	{
		perror("calloc failed");
		return (NULL);
	}

	snprintf(oui, sizeof(oui), "%02X:%02X:%02X", mac0, mac1, mac2);
	oui_len = strlen(oui);

	if (lopt.manufList != NULL)
	{
		// Search in the list
		ptr = lopt.manufList;
		while (ptr != NULL)
		{
			found = !strncasecmp(ptr->id, oui, OUI_STR_SIZE);
			if (found)
			{
				memcpy(manuf, ptr->manuf, MANUF_SIZE);
				break;
			}
			ptr = ptr->next;
		}
	}
	else
	{
		// If the file exist, then query it each time we need to get a
		// manufacturer.
		fp = fopen("/var/lib/ieee-data/oui.txt", "r");

		if (fp != NULL)
		{

			memset(buffer, 0x00, sizeof(buffer));
			while (fgets(buffer, sizeof(buffer), fp) != NULL)
			{
				if (strstr(buffer, "(hex)") == NULL)
				{
					continue;
				}

				memset(a, 0x00, sizeof(a));
				memset(b, 0x00, sizeof(b));
				memset(c, 0x00, sizeof(c));
				if (sscanf(buffer,
						   "%2c-%2c-%2c",
						   (char *) a,
						   (char *) b,
						   (char *) c)
					== 3)
				{
					snprintf(temp,
							 sizeof(temp),
							 "%c%c:%c%c:%c%c",
							 a[0],
							 a[1],
							 b[0],
							 b[1],
							 c[0],
							 c[1]);
					found = !memcmp(temp, oui, oui_len);
					if (found)
					{
						manuf_str = get_manufacturer_from_string(buffer);
						if (manuf_str != NULL)
						{
							snprintf(manuf, MANUF_SIZE, "%s", manuf_str);
							free(manuf_str);
						}

						break;
					}
				}
				memset(buffer, 0x00, sizeof(buffer));
			}

			fclose(fp);
		}
	}

	// Not found, use "Unknown".
	if (!found || *manuf == '\0')
	{
		memcpy(manuf, "Unknown", 7);
		manuf[7] = '\0';
	}

	// Going in a smaller buffer
	rmanuf = (char *) realloc(manuf, (strlen(manuf) + 1) * sizeof(char));
	return (rmanuf);
}
#undef OUI_STR_SIZE
#undef MANUF_SIZE

static inline uintptr_t adds_uptr(uintptr_t a, uintptr_t b)
{
	uintptr_t c = a + b;
	if (c < a) /* can only happen due to overflow */
		c = -1;
	return (c);
}

static int dump_add_packet(unsigned char * h80211,
						   int caplen,
						   struct rx_info * ri,
						   int cardnum)
{
	int seq, msd, offset, clen, o;
	size_t i;
	size_t n;
	size_t dlen;
	unsigned z;
	int type, length, numuni = 0;
	size_t numauth = 0;
	struct pcap_pkthdr pkh;
	struct timeval tv;
	struct ivs2_pkthdr ivs2;
	unsigned char *p, *org_p, c;
	unsigned char bssid[6];
	unsigned char stmac[6];
	unsigned char namac[6];
	unsigned char clear[2048];
	int weight[16];
	int num_xor = 0;

	struct AP_info * ap_cur = NULL;
	struct ST_info * st_cur = NULL;
	struct NA_info * na_cur = NULL;
	struct AP_info * ap_prv = NULL;
	struct ST_info * st_prv = NULL;
	struct NA_info * na_prv = NULL;

	/* skip all non probe response frames in active scanning simulation mode */
	if (lopt.active_scan_sim > 0 && h80211[0] != 0x50) {
		return (0);
	}
	/* skip packets smaller than a 802.11 header */

	if (caplen < (int) sizeof(struct ieee80211_frame)) {
		goto write_packet;
	}
	/* skip (uninteresting) control frames */

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL) {
		goto write_packet;
	}
	/* grab the sequence number */
	seq = ((h80211[22] >> 4) + (h80211[23] << 4));

	/* locate the access point's MAC address */

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
	{
		case IEEE80211_FC1_DIR_NODS:
			memcpy(bssid, h80211 + 16, 6); //-V525
			// if AP
			break; // Adhoc
		case IEEE80211_FC1_DIR_TODS:
			memcpy(bssid, h80211 + 4, 6);
			// if ST
			break; // ToDS
		case IEEE80211_FC1_DIR_FROMDS:
		case IEEE80211_FC1_DIR_DSTODS:
			memcpy(bssid, h80211 + 10, 6);
			break; // WDS -> Transmitter taken as BSSID
		default:
			abort();
	}

	// if (memcmp(opt.f_bssid, NULL_MAC, 6) != 0)
	// {
	// 	if (memcmp(opt.f_netmask, NULL_MAC, 6) != 0)
	// 	{
	// 		if (is_filtered_netmask(bssid)) {
	// 			FlD("skip is_filtered_netmask")	
	// 			return (1);
	// 		}
	// 	}
	// 	else
	// 	{
	// 		if (memcmp(opt.f_bssid, bssid, 6) != 0) {
	// 			FlD("skip alreay occurs")
	// 			return (1);
	// 		}
	// 	}
	// }

	/* update our chained list of access points */

	ap_cur = lopt.ap_1st;
	ap_prv = NULL;

	while (ap_cur != NULL)
	{
		if (!memcmp(ap_cur->bssid, bssid, 6)) break;

		ap_prv = ap_cur;
		ap_cur = ap_cur->next;
	}

	/* if it's a new access point, add it */

	if (ap_cur == NULL)
	{
		if (!(ap_cur = (struct AP_info *) calloc(1, sizeof(struct AP_info))))
		{
			perror("calloc failed");
			return (1);
		}

		/* if mac is listed as unknown, remove it */
    // TODO do we need this?
		remove_namac(bssid);

		if (lopt.ap_1st == NULL)
			lopt.ap_1st = ap_cur;
		else if (ap_prv != NULL)
			ap_prv->next = ap_cur;

		memcpy(ap_cur->bssid, bssid, 6);
		if (ap_cur->manuf == NULL)
		{
      // TODO do we need this?
			ap_cur->manuf = get_manufacturer(
				ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2]);
		}

		ap_cur->nb_pkt = 0;
		ap_cur->prev = ap_prv;

		// ap_cur->tinit = time(NULL);
		// ap_cur->tlast = time(NULL);

		ap_cur->avg_power = -1;
		ap_cur->best_power = -1;
		ap_cur->power_index = -1;

		for (i = 0; i < NB_PWR; i++) ap_cur->power_lvl[i] = -1;

		ap_cur->channel = -1;
		ap_cur->max_speed = -1;
		ap_cur->security = 0;

		ap_cur->ivbuf = NULL;
		ap_cur->ivbuf_size = 0;
		ap_cur->uiv_root = uniqueiv_init();

		ap_cur->nb_data = 0;
		ap_cur->nb_dataps = 0;
		ap_cur->nb_data_old = 0;
		//gettimeofday(&(ap_cur->tv), NULL);

		ap_cur->dict_started = 0;

		ap_cur->key = NULL;

		lopt.ap_end = ap_cur;

		ap_cur->nb_bcn = 0;

		ap_cur->rx_quality = 0;
		ap_cur->fcapt = 0;
		ap_cur->fmiss = 0;
		ap_cur->last_seq = 0;
		// gettimeofday(&(ap_cur->ftimef), NULL);
		// gettimeofday(&(ap_cur->ftimel), NULL);
		// gettimeofday(&(ap_cur->ftimer), NULL);

		ap_cur->ssid_length = 0;
		ap_cur->essid_stored = 0;
		memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
		ap_cur->timestamp = 0;

		ap_cur->decloak_detect = lopt.decloak;
		ap_cur->is_decloak = 0;
		ap_cur->packets = NULL;

		ap_cur->marked = 0;
		ap_cur->marked_color = 1;

		ap_cur->data_root = NULL;
		ap_cur->EAP_detected = 0;
		memcpy(ap_cur->gps_loc_min, lopt.gps_loc, sizeof(float) * 5); //-V512
		memcpy(ap_cur->gps_loc_max, lopt.gps_loc, sizeof(float) * 5); //-V512
		memcpy(ap_cur->gps_loc_best, lopt.gps_loc, sizeof(float) * 5); //-V512

		/* 802.11n and ac */
		ap_cur->channel_width = CHANNEL_22MHZ; // 20MHz by default
		memset(ap_cur->standard, 0, 3);

		ap_cur->n_channel.sec_channel = -1;
		ap_cur->n_channel.short_gi_20 = 0;
		ap_cur->n_channel.short_gi_40 = 0;
		ap_cur->n_channel.any_chan_width = 0;
		ap_cur->n_channel.mcs_index = -1;

		ap_cur->ac_channel.center_sgmt[0] = 0;
		ap_cur->ac_channel.center_sgmt[1] = 0;
		ap_cur->ac_channel.mu_mimo = 0;
		ap_cur->ac_channel.short_gi_80 = 0;
		ap_cur->ac_channel.short_gi_160 = 0;
		ap_cur->ac_channel.split_chan = 0;
		ap_cur->ac_channel.mhz_160_chan = 0;
		ap_cur->ac_channel.wave_2 = 0;
		memset(ap_cur->ac_channel.mcs_index, 0, MAX_AC_MCS_INDEX);
	}

	/* update the last time seen */
	// FlD("last ap");
	// ap_cur->tlast = time(NULL);

	/* only update power if packets comes from
	 * the AP: either type == mgmt and SA == BSSID,
	 * or FromDS == 1 and ToDS == 0 */

	if (((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_NODS
		 && memcmp(h80211 + 10, bssid, 6) == 0)
		|| ((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_FROMDS))
	{
		ap_cur->power_index = (ap_cur->power_index + 1) % NB_PWR;
		ap_cur->power_lvl[ap_cur->power_index] = ri->ri_power;

		// Moving exponential average
		// ma_new = alpha * new_sample + (1-alpha) * ma_old;
		ap_cur->avg_power
			= (int) (0.99f * ri->ri_power + (1.f - 0.99f) * ap_cur->avg_power);

		if (ap_cur->avg_power > ap_cur->best_power)
		{
			ap_cur->best_power = ap_cur->avg_power;
			memcpy(ap_cur->gps_loc_best, //-V512
				   lopt.gps_loc,
				   sizeof(float) * 5);
		}

		/* every packet in here comes from the AP */

		if (lopt.gps_loc[0] > ap_cur->gps_loc_max[0])
			ap_cur->gps_loc_max[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] > ap_cur->gps_loc_max[1])
			ap_cur->gps_loc_max[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] > ap_cur->gps_loc_max[2])
			ap_cur->gps_loc_max[2] = lopt.gps_loc[2];

		if (lopt.gps_loc[0] < ap_cur->gps_loc_min[0])
			ap_cur->gps_loc_min[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] < ap_cur->gps_loc_min[1])
			ap_cur->gps_loc_min[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] < ap_cur->gps_loc_min[2])
			ap_cur->gps_loc_min[2] = lopt.gps_loc[2];
		//        printf("seqnum: %i\n", seq);

		// if (ap_cur->fcapt == 0 && ->fmiss == 0)
		// 	gettimeofday(&(ap_cur->ftimef), NULL);
		if (ap_cur->last_seq != 0)
			ap_cur->fmiss += (seq - ap_cur->last_seq - 1);
		ap_cur->last_seq = (uint16_t) seq;
		ap_cur->fcapt++;
		//gettimeofday(&(ap_cur->ftimel)ap_cur, NULL);

		/* if we are writing to a file and want to make a continuous rolling log save the data here */
		// if (opt.record_data && opt.output_format_log_csv)
		// {
		// 	/* Write out our rolling log every time we see data from an AP */
		// 	FlD("dump strange log");
		// 	dump_write_airodump_ng_logcsv_add_ap(
		// 		ap_cur, ri->ri_power, &lopt.gps_time, lopt.gps_loc);
		// }

		//         if(ap_cur->fcapt >= QLT_COUNT) update_rx_quality();
	}

	switch (h80211[0])
	{
		case IEEE80211_FC0_SUBTYPE_BEACON:
			ap_cur->nb_bcn++;
			break;

		case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
			/* reset the WPS state */
			ap_cur->wps.state = 0xFF;
			ap_cur->wps.ap_setup_locked = 0;
			break;

		default:
			break;
	}

	ap_cur->nb_pkt++;

	/* locate the station MAC in the 802.11 header */

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
	{
		case IEEE80211_FC1_DIR_NODS:
			/* if management, check that SA != BSSID */

			if (memcmp(h80211 + 10, bssid, 6) == 0) {
				goto skip_station;
			}
			memcpy(stmac, h80211 + 10, 6);
			break;

		case IEEE80211_FC1_DIR_TODS:
			/* ToDS packet, must come from a client */

			memcpy(stmac, h80211 + 10, 6);
			break;

		// case IEEE80211_FC1_DIR_FROMDS:

		// 	/* FromDS packet, reject broadcast MACs */
		// 	FlD("IEEE80211_FC1_DIR_FROMDS");
		// 	if ((h80211[4] % 2) != 0) {
		// 		FlD("skip_station");
		// 		goto skip_station;
		// 	}
		// 	memcpy(stmac, h80211 + 4, 6);
		// 	break;

		// case IEEE80211_FC1_DIR_DSTODS:
		// 	FlD("skip_station");
		// 	goto skip_station;

		default:
			abort();
	}

	/* update our chained list of wireless stations */
	st_cur = lopt.st_1st;
	st_prv = NULL;

	while (st_cur != NULL)
	{
		if (!memcmp(st_cur->stmac, stmac, 6)) break;

		st_prv = st_cur;
		st_cur = st_cur->next;
	}

	/* if it's a new client, add it */

	if (st_cur == NULL)
	{
		if (!(st_cur = (struct ST_info *) calloc(1, sizeof(struct ST_info))))
		{
			perror("calloc failed");
			return (1);
		}
		/* if mac is listed as unknown, remove it */
		remove_namac(stmac);

		memset(st_cur, 0, sizeof(struct ST_info));

		if (lopt.st_1st == NULL)
			lopt.st_1st = st_cur;
		else
			st_prv->next = st_cur;

		memcpy(st_cur->stmac, stmac, 6);

		if (st_cur->manuf == NULL)
		{
			st_cur->manuf = get_manufacturer(
				st_cur->stmac[0], st_cur->stmac[1], st_cur->stmac[2]);
		}

		st_cur->nb_pkt = 0;

		st_cur->prev = st_prv;

		st_cur->power = -1;
		st_cur->best_power = -1;
		st_cur->rate_to = -1;
		st_cur->rate_from = -1;

		st_cur->probe_index = -1;
		st_cur->missed = 0;
		st_cur->lastseq = 0;
		st_cur->qos_fr_ds = 0;
		st_cur->qos_to_ds = 0;
		st_cur->channel = 0;

		memcpy(st_cur->gps_loc_min, //-V512
			   lopt.gps_loc,
			   sizeof(st_cur->gps_loc_min));
		memcpy(st_cur->gps_loc_max, //-V512
			   lopt.gps_loc,
			   sizeof(st_cur->gps_loc_max));
		memcpy( //-V512
			st_cur->gps_loc_best,
			lopt.gps_loc,
			sizeof(st_cur->gps_loc_best));

		for (i = 0; i < NB_PRB; i++)
		{
			memset(st_cur->probes[i], 0, sizeof(st_cur->probes[i]));
			st_cur->ssid_length[i] = 0;
		}

		lopt.st_end = st_cur;
	}

	if (st_cur->base == NULL || memcmp(ap_cur->bssid, BROADCAST, 6) != 0) {
		st_cur->base = ap_cur;
	}

	// update bitrate to station
	if ((h80211[1] & 3) == 2) st_cur->rate_to = ri->ri_rate;

	/* update the last time seen */

	/* only update power if packets comes from the
	 * client: either type == Mgmt and SA != BSSID,
	 * or FromDS == 0 and ToDS == 1 */

	if (((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_NODS
		 && memcmp(h80211 + 10, bssid, 6) != 0)
		|| ((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_TODS))
	{
    // TODO maybe unused
		st_cur->power = ri->ri_power;
		if (ri->ri_power > st_cur->best_power)
		{
			st_cur->best_power = ri->ri_power;
			memcpy(ap_cur->gps_loc_best, //-V512
				   lopt.gps_loc,
				   sizeof(st_cur->gps_loc_best));
		}

		st_cur->rate_from = ri->ri_rate;
		if (ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
			st_cur->channel = ri->ri_channel;
		else
			st_cur->channel = lopt.channel[cardnum];

		if (lopt.gps_loc[0] > st_cur->gps_loc_max[0])
			st_cur->gps_loc_max[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] > st_cur->gps_loc_max[1])
			st_cur->gps_loc_max[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] > st_cur->gps_loc_max[2])
			st_cur->gps_loc_max[2] = lopt.gps_loc[2];

		if (lopt.gps_loc[0] < st_cur->gps_loc_min[0])
			st_cur->gps_loc_min[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] < st_cur->gps_loc_min[1])
			st_cur->gps_loc_min[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] < st_cur->gps_loc_min[2])
			st_cur->gps_loc_min[2] = lopt.gps_loc[2];

		if (st_cur->lastseq != 0)
		{
			msd = seq - st_cur->lastseq - 1;
			if (msd > 0 && msd < 1000) st_cur->missed += msd;
		}
		st_cur->lastseq = (uint16_t) seq;
	}

	st_cur->nb_pkt++;

skip_station:

	/* packet parsing: Beacon or Probe Response */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_BEACON
		|| h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
	{
		if (!(ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)))
		{
			if ((h80211[34] & 0x10) >> 4)
				ap_cur->security |= STD_WEP | ENC_WEP;
			else
				ap_cur->security |= STD_OPN;
		}

		ap_cur->preamble = (h80211[34] & 0x20) >> 5;

		p = h80211 + 36;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			// only update the essid length if the new length is > the old one
			if (p[0] == 0x00 && (ap_cur->ssid_length < p[1]))
				ap_cur->ssid_length = p[1];

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				/* found a non-cloaked ESSID */
				n = MIN(ESSID_LENGTH, p[1]);

				memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
				memcpy(ap_cur->essid, p + 2, n);

				// if (opt.f_ivs != NULL && !ap_cur->essid_stored)
				// {
				// 	memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
				// 	ivs2.flags |= IVS2_ESSID;
				// 	ivs2.len += ap_cur->ssid_length;

				// 	if (memcmp(lopt.prev_bssid, ap_cur->bssid, 6) != 0)
				// 	{
				// 		ivs2.flags |= IVS2_BSSID;
				// 		ivs2.len += 6;
				// 		memcpy(lopt.prev_bssid, ap_cur->bssid, 6);
				// 	}

				// 	/* write header */
				// 	if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), opt.f_ivs)
				// 		!= (size_t) sizeof(struct ivs2_pkthdr))
				// 	{
				// 		perror("fwrite(IV header) failed");
				// 		return (1);
				// 	}

				// 	/* write BSSID */
				// 	if (ivs2.flags & IVS2_BSSID)
				// 	{
				// 		if (fwrite(ap_cur->bssid, 1, 6, opt.f_ivs)
				// 			!= (size_t) 6)
				// 		{
				// 			perror("fwrite(IV bssid) failed");
				// 			return (1);
				// 		}
				// 	}

				// 	/* write essid */
				// 	if (fwrite(ap_cur->essid,
				// 			   1,
				// 			   (size_t) ap_cur->ssid_length,
				// 			   opt.f_ivs)
				// 		!= (size_t) ap_cur->ssid_length)
				// 	{
				// 		perror("fwrite(IV essid) failed");
				// 		return (1);
				// 	}

				// 	ap_cur->essid_stored = 1;
				// }

				// if (verifyssid(ap_cur->essid) == 0)
				// 	for (i = 0; i < n; i++)
				// 		if (ap_cur->essid[i] < 32) ap_cur->essid[i] = '.';
			}

			/* get the maximum speed in Mb and the AP's channel */

			if (p[0] == 0x01 || p[0] == 0x32)
			{
				if (ap_cur->max_speed < (p[1 + p[1]] & 0x7F) / 2)
					ap_cur->max_speed = (p[1 + p[1]] & 0x7F) / 2;
			}

			if (p[0] == 0x03)
			{
				ap_cur->channel = p[2];
			}
			else if (p[0] == 0x3d)
			{
				if (ap_cur->standard[0] == '\0')
				{
					ap_cur->standard[0] = 'n';
				}

				/* also get the channel from ht information->primary channel */
				ap_cur->channel = p[2];

				// Get channel width and secondary channel
				switch (p[3] % 4)
				{
					case 0:
						// 20MHz
						ap_cur->channel_width = CHANNEL_20MHZ;
						break;
					case 1:
						// Above
						ap_cur->n_channel.sec_channel = 1;
						switch (ap_cur->channel_width)
						{
							case CHANNEL_UNKNOWN_WIDTH:
							case CHANNEL_3MHZ:
							case CHANNEL_5MHZ:
							case CHANNEL_10MHZ:
							case CHANNEL_20MHZ:
							case CHANNEL_22MHZ:
							case CHANNEL_30MHZ:
							case CHANNEL_20_OR_40MHZ:
								ap_cur->channel_width = CHANNEL_40MHZ;
								break;
							default:
								break;
						}
						break;
					case 2:
						// Reserved
						break;
					case 3:
						// Below
						ap_cur->n_channel.sec_channel = -1;
						switch (ap_cur->channel_width)
						{
							case CHANNEL_UNKNOWN_WIDTH:
							case CHANNEL_3MHZ:
							case CHANNEL_5MHZ:
							case CHANNEL_10MHZ:
							case CHANNEL_20MHZ:
							case CHANNEL_22MHZ:
							case CHANNEL_30MHZ:
							case CHANNEL_20_OR_40MHZ:
								ap_cur->channel_width = CHANNEL_40MHZ;
								break;
							default:
								break;
						}
						break;
					default:
						break;
				}

				ap_cur->n_channel.any_chan_width = (uint8_t)((p[3] / 4) % 2);
			}

			// HT capabilities
			if (p[0] == 0x2d && p[1] > 18)
			{
				if (ap_cur->standard[0] == '\0')
				{
					ap_cur->standard[0] = 'n';
				}

				// Short GI for 20/40MHz
				ap_cur->n_channel.short_gi_20 = (uint8_t)((p[3] / 32) % 2);
				ap_cur->n_channel.short_gi_40 = (uint8_t)((p[3] / 64) % 2);

				// Parse MCS rate
				/*
				 * XXX: Sometimes TX and RX spatial stream # differ and none of
				 * the beacon
				 * have that. If someone happens to have such AP, open an issue
				 * with it.
				 * Ref:
				 * https://www.wireshark.org/lists/wireshark-bugs/201307/msg00098.html
				 * See IEEE standard 802.11-2012 table 8.126
				 *
				 * For now, just figure out the highest MCS rate.
				 */
				if ((unsigned char) ap_cur->n_channel.mcs_index == 0xff)
				{
					uint32_t rx_mcs_bitmask = 0;
					memcpy(&rx_mcs_bitmask, p + 5, sizeof(uint32_t));
					while (rx_mcs_bitmask)
					{
						++(ap_cur->n_channel.mcs_index);
						rx_mcs_bitmask /= 2;
					}
				}
			}

			// VHT Capabilities
			if (p[0] == 0xbf && p[1] >= 12)
			{
				// Standard is AC
				strcpy(ap_cur->standard, "ac");

				ap_cur->ac_channel.split_chan = (uint8_t)((p[3] / 4) % 4);

				ap_cur->ac_channel.short_gi_80 = (uint8_t)((p[3] / 32) % 2);
				ap_cur->ac_channel.short_gi_160 = (uint8_t)((p[3] / 64) % 2);

				ap_cur->ac_channel.mu_mimo = (uint8_t)((p[4] & 0x18) % 2);

				// A few things indicate Wave 2: MU-MIMO, 80+80 Channels
				ap_cur->ac_channel.wave_2
					= (uint8_t)((ap_cur->ac_channel.mu_mimo
								 || ap_cur->ac_channel.split_chan)
								% 2);

				// Maximum rates (16 bit)
				uint16_t tx_mcs = 0;
				memcpy(&tx_mcs, p + 10, sizeof(uint16_t));

				// Maximum of 8 SS, each uses 2 bits
				for (uint8_t stream_idx = 0; stream_idx < MAX_AC_MCS_INDEX;
					 ++stream_idx)
				{
					uint8_t mcs = (uint8_t)(tx_mcs % 4);

					// Unsupported -> No more spatial stream
					if (mcs == 3)
					{
						break;
					}
					switch (mcs)
					{
						case 0:
							// support of MCS 0-7
							ap_cur->ac_channel.mcs_index[stream_idx] = 7;
							break;
						case 1:
							// support of MCS 0-8
							ap_cur->ac_channel.mcs_index[stream_idx] = 8;
							break;
						case 2:
							// support of MCS 0-9
							ap_cur->ac_channel.mcs_index[stream_idx] = 9;
							break;
						default:
							break;
					}

					// Next spatial stream
					tx_mcs /= 4;
				}
			}

			// VHT Operations
			if (p[0] == 0xc0 && p[1] >= 3)
			{
				// Standard is AC
				strcpy(ap_cur->standard, "ac");

				// Channel width
				switch (p[2])
				{
					case 0:
						// 20 or 40MHz
						ap_cur->channel_width = CHANNEL_20_OR_40MHZ;
						break;
					case 1:
						ap_cur->channel_width = CHANNEL_80MHZ;
						break;
					case 2:
						ap_cur->channel_width = CHANNEL_160MHZ;
						break;
					case 3:
						// 80+80MHz
						ap_cur->channel_width = CHANNEL_80_80MHZ;
						ap_cur->ac_channel.split_chan = 1;
						break;
					default:
						break;
				}

				// 802.11ac channel center segments
				ap_cur->ac_channel.center_sgmt[0] = p[3];
				ap_cur->ac_channel.center_sgmt[1] = p[4];
			}

			// Next
			p += 2 + p[1];
		}

		// Now get max rate
		if (ap_cur->standard[0] == 'n' || strcmp(ap_cur->standard, "ac") == 0)
		{
			int sgi = 0;
			int width = 0;

			switch (ap_cur->channel_width)
			{
				case CHANNEL_20MHZ:
					width = 20;
					sgi = ap_cur->n_channel.short_gi_20;
					break;
				case CHANNEL_20_OR_40MHZ:
				case CHANNEL_40MHZ:
					width = 40;
					sgi = ap_cur->n_channel.short_gi_40;
					break;
				case CHANNEL_80MHZ:
					width = 80;
					sgi = ap_cur->ac_channel.short_gi_80;
					break;
				case CHANNEL_80_80MHZ:
				case CHANNEL_160MHZ:
					width = 160;
					sgi = ap_cur->ac_channel.short_gi_160;
					break;
				default:
					break;
			}

			if (width != 0)
			{
				// In case of ac, get the amount of spatial streams
				int amount_ss = 1;
				if (ap_cur->standard[0] != 'n')
				{
					for (amount_ss = 0;
						 amount_ss < MAX_AC_MCS_INDEX
						 && ap_cur->ac_channel.mcs_index[amount_ss] != 0;
						 ++amount_ss)
						;
				}

				// Get rate
				float max_rate
					= (ap_cur->standard[0] == 'n')
						  ? get_80211n_rate(
								width, sgi, ap_cur->n_channel.mcs_index)
						  : get_80211ac_rate(
								width,
								sgi,
								ap_cur->ac_channel.mcs_index[amount_ss - 1],
								amount_ss);

				// If no error, update rate
				if (max_rate > 0)
				{
					ap_cur->max_speed = (int) max_rate;
				}
			}
		}
	}

	/* packet parsing: Beacon & Probe response */
	/* TODO: Merge this if and the one above */
	if ((h80211[0] == IEEE80211_FC0_SUBTYPE_BEACON
		 || h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
		&& caplen > 38)
	{
		p = h80211 + 36; // ignore hdr + fixed params

		while (p < h80211 + caplen)
		{
			type = p[0];
			length = p[1];
			if (p + 2 + length > h80211 + caplen)
			{
				/*                printf("error parsing tags! %p vs. %p (tag:
				%i, length: %i,position: %i)\n", (p+2+length), (h80211+caplen),
				type, length, (p-h80211));
				exit(1);*/
				break;
			}

			// Find WPA and RSN tags
			if ((type == 0xDD && (length >= 8)
				 && (memcmp(p + 2, "\x00\x50\xF2\x01\x01\x00", 6) == 0))
				|| (type == 0x30))
			{
				ap_cur->security &= ~(STD_WEP | ENC_WEP | STD_WPA);

				org_p = p;
				offset = 0;

				if (type == 0xDD)
				{
					// WPA defined in vendor specific tag -> WPA1 support
					ap_cur->security |= STD_WPA;
					offset = 4;
				}

				// RSN => WPA2
				if (type == 0x30)
				{
					ap_cur->security |= STD_WPA2;
					offset = 0;
				}

				if (length < (18 + offset))
				{
					p += length + 2;
					continue;
				}

				// Number of pairwise cipher suites
				if (p + 9 + offset > h80211 + caplen) break;
				numuni = p[8 + offset] + (p[9 + offset] << 8);

				// Number of Authentication Key Managament suites
				if (p + (11 + offset) + 4 * numuni > h80211 + caplen) break;
				numauth = p[(10 + offset) + 4 * numuni]
						  + (p[(11 + offset) + 4 * numuni] << 8);

				p += (10 + offset);

				if (type != 0x30)
				{
					if (p + (4 * numuni) + (2 + 4 * numauth) > h80211 + caplen)
						break;
				}
				else
				{
					if (p + (4 * numuni) + (2 + 4 * numauth) + 2
						> h80211 + caplen)
						break;
				}

				// Get the list of cipher suites
				for (i = 0; i < (size_t) numuni; i++)
				{
					switch (p[i * 4 + 3])
					{
						case 0x01:
							ap_cur->security |= ENC_WEP;
							break;
						case 0x02:
							ap_cur->security |= ENC_TKIP;
							break;
						case 0x03:
							ap_cur->security |= ENC_WRAP;
							break;
						case 0x0A:
						case 0x04:
							ap_cur->security |= ENC_CCMP;
							ap_cur->security |= STD_WPA2;
							break;
						case 0x05:
							ap_cur->security |= ENC_WEP104;
							break;
						case 0x08:
						case 0x09:
							ap_cur->security |= ENC_GCMP;
							ap_cur->security |= STD_WPA2;
							break;
						case 0x0B:
						case 0x0C:
							ap_cur->security |= ENC_GMAC;
							ap_cur->security |= STD_WPA2;
							break;
						default:
							break;
					}
				}

				p += 2 + 4 * numuni;

				// Get the AKM suites
				for (i = 0; i < numauth; i++)
				{
					switch (p[i * 4 + 3])
					{
						case 0x01:
							ap_cur->security |= AUTH_MGT;
							break;
						case 0x02:
							ap_cur->security |= AUTH_PSK;
							break;
						case 0x06:
						case 0x0d:
							ap_cur->security |= AUTH_CMAC;
							break;
						case 0x08:
							ap_cur->security |= AUTH_SAE;
							break;
						case 0x12:
							ap_cur->security |= AUTH_OWE;
							break;
						default:
							break;
					}
				}

				p = org_p + length + 2;
			}
			else if ((type == 0xDD && (length >= 8)
					  && (memcmp(p + 2, "\x00\x50\xF2\x02\x01\x01", 6) == 0)))
			{
				// QoS IE
				ap_cur->security |= STD_QOS;
				p += length + 2;
			}
			else if ((type == 0xDD && (length >= 4)
					  && (memcmp(p + 2, "\x00\x50\xF2\x04", 4) == 0)))
			{
				// WPS IE
				org_p = p;
				p += 6;
				int len = length, subtype = 0, sublen = 0;
				while (len >= 4)
				{
					subtype = (p[0] << 8) + p[1];
					sublen = (p[2] << 8) + p[3];
					if (sublen > len) break;
					switch (subtype)
					{
						case 0x104a: // WPS Version
							ap_cur->wps.version = p[4];
							break;
						case 0x1011: // Device Name
						case 0x1012: // Device Password ID
						case 0x1021: // Manufacturer
						case 0x1023: // Model
						case 0x1024: // Model Number
						case 0x103b: // Response Type
						case 0x103c: // RF Bands
						case 0x1041: // Selected Registrar
						case 0x1042: // Serial Number
							break;
						case 0x1044: // WPS State
							ap_cur->wps.state = p[4];
							break;
						case 0x1047: // UUID Enrollee
						case 0x1049: // Vendor Extension
							if (memcmp(&p[4], "\x00\x37\x2A", 3) == 0)
							{
								unsigned char * pwfa = &p[7];
								int wfa_len = ntohs(*((short *) &p[2]));
								while (wfa_len > 0)
								{
									if (*pwfa == 0)
									{ // Version2
										ap_cur->wps.version = pwfa[2];
										break;
									}
									wfa_len -= pwfa[1] + 2;
									pwfa += pwfa[1] + 2;
								}
							}
							break;
						case 0x1054: // Primary Device Type
							break;
						case 0x1057: // AP Setup Locked
							ap_cur->wps.ap_setup_locked = p[4];
							break;
						case 0x1008: // Config Methods
						case 0x1053: // Selected Registrar Config Methods
							ap_cur->wps.meth = (p[4] << 8) + p[5];
							break;
						default: // Unknown type-length-value
							break;
					}
					p += sublen + 4;
					len -= sublen + 4;
				}
				p = org_p + length + 2;
			}
			else
				p += length + 2;
		}
	}

	/* packet parsing: Authentication Response */

	// if (h80211[0] == IEEE80211_FC0_SUBTYPE_AUTH && caplen >= 30)
	// {
	// 	if (ap_cur->security & STD_WEP)
	// 	{
	// 		FlD("Authentication response");
	// 		// successful step 2 or 4 (coming from the AP)
	// 		if (memcmp(h80211 + 28, "\x00\x00", 2) == 0
	// 			&& (h80211[26] == 0x02 || h80211[26] == 0x04))
	// 		{
	// 			ap_cur->security &= ~(AUTH_OPN | AUTH_PSK | AUTH_MGT);
	// 			if (h80211[24] == 0x00) ap_cur->security |= AUTH_OPN;
	// 			if (h80211[24] == 0x01) ap_cur->security |= AUTH_PSK;
	// 		}
	// 	}
	// }

	/* packet parsing: Association Request */

	// if (h80211[0] == IEEE80211_FC0_SUBTYPE_ASSOC_REQ && caplen > 28)
	// {
	// 	FlD("Association Request");
	// 	p = h80211 + 28;

	// 	while (p < h80211 + caplen)
	// 	{
	// 		if (p + 2 + p[1] > h80211 + caplen) break;

	// 		if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
	// 			&& (p[1] > 1 || p[2] != ' '))
	// 		{
	// 			/* found a non-cloaked ESSID */
	// 			n = MIN(ESSID_LENGTH, p[1]);

	// 			memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
	// 			memcpy(ap_cur->essid, p + 2, n);
	// 			ap_cur->ssid_length = (int) n;

	// 			if (opt.f_ivs != NULL && !ap_cur->essid_stored)
	// 			{
	// 				memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
	// 				ivs2.flags |= IVS2_ESSID;
	// 				ivs2.len += ap_cur->ssid_length;

	// 				if (memcmp(lopt.prev_bssid, ap_cur->bssid, 6) != 0)
	// 				{
	// 					ivs2.flags |= IVS2_BSSID;
	// 					ivs2.len += 6;
	// 					memcpy(lopt.prev_bssid, ap_cur->bssid, 6);
	// 				}

	// 				/* write header */
	// 				if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), opt.f_ivs)
	// 					!= (size_t) sizeof(struct ivs2_pkthdr))
	// 				{
	// 					perror("fwrite(IV header) failed");
	// 					return (1);
	// 				}

	// 				/* write BSSID */
	// 				if (ivs2.flags & IVS2_BSSID)
	// 				{
	// 					if (fwrite(ap_cur->bssid, 1, 6, opt.f_ivs)
	// 						!= (size_t) 6)
	// 					{
	// 						perror("fwrite(IV bssid) failed");
	// 						return (1);
	// 					}
	// 				}

	// 				/* write essid */
	// 				if (fwrite(ap_cur->essid,
	// 						   1,
	// 						   (size_t) ap_cur->ssid_length,
	// 						   opt.f_ivs)
	// 					!= (size_t) ap_cur->ssid_length)
	// 				{
	// 					perror("fwrite(IV essid) failed");
	// 					return (1);
	// 				}

	// 				ap_cur->essid_stored = 1;
	// 			}

	// 			if (verifyssid(ap_cur->essid) == 0)
	// 				for (i = 0; i < n; i++)
	// 					if (ap_cur->essid[i] < 32) ap_cur->essid[i] = '.';
	// 		}

	// 		p += 2 + p[1];
	// 	}
	// 	if (st_cur != NULL) st_cur->wpa.state = 0;
	// }

	/* packet parsing: some data */

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA)
	{
		/* update the channel if we didn't get any beacon */
		if (ap_cur->channel == -1)
		{
			if (ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
				ap_cur->channel = ri->ri_channel;
			else
				ap_cur->channel = lopt.channel[cardnum];
		}

		/* check the SNAP header to see if data is encrypted */
		z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
				? 24
				: 30;

		/* Check if 802.11e (QoS) */
		if ((h80211[0] & 0x80) == 0x80)
		{
			z += 2;
			if (st_cur != NULL)
			{
				if ((h80211[1] & 3) == 1) // ToDS
					st_cur->qos_to_ds = 1;
				else
					st_cur->qos_fr_ds = 1;
			}
		}
		else
		{
			if (st_cur != NULL)
			{
				if ((h80211[1] & 3) == 1) // ToDS
					st_cur->qos_to_ds = 0;
				else
					st_cur->qos_fr_ds = 0;
			}
		}

		if (z == 24)
		{
			assert(0 && "not suppose to happen");
		}

		if (z + 26 > (unsigned) caplen) {	
			goto write_packet;
		}
		if (h80211[z] == h80211[z + 1] && h80211[z + 2] == 0x03)
		{
			//            if( ap_cur->encryption < 0 )
			//                ap_cur->encryption = 0;

			/* if ethertype == IPv4, find the LAN address */

			if (h80211[z + 6] == 0x08 && h80211[z + 7] == 0x00
				&& (h80211[1] & 3) == 0x01)
				memcpy(ap_cur->lanip, &h80211[z + 20], 4);

			if (h80211[z + 6] == 0x08 && h80211[z + 7] == 0x06)
				memcpy(ap_cur->lanip, &h80211[z + 22], 4);
		}
		//        else
		//            ap_cur->encryption = 2 + ( ( h80211[z + 3] & 0x20 ) >> 5
		//            );

		// if (ap_cur->security == 0 || (ap_cur->security & STD_WEP))
		// {
		// 	FlD("Smth scary..");
		// 	if ((h80211[1] & 0x40) != 0x40)
		// 	{
		// 		ap_cur->security |= STD_OPN;
		// 	}
		// 	else
		// 	{
		// 		if ((h80211[z + 3] & 0x20) == 0x20)
		// 		{
		// 			ap_cur->security |= STD_WPA;
		// 		}
		// 		else
		// 		{
		// 			ap_cur->security |= STD_WEP;
		// 			if ((h80211[z + 3] & 0xC0) != 0x00)
		// 			{
		// 				ap_cur->security |= ENC_WEP40;
		// 			}
		// 			else
		// 			{
		// 				ap_cur->security &= ~ENC_WEP40;
		// 				ap_cur->security |= ENC_WEP;
		// 			}
		// 		}
		// 	}
		// }

		if (z + 10 > (unsigned) caplen) goto write_packet;

		// if (ap_cur->security & STD_WEP)
		// {
		// 	/* WEP: check if we've already seen this IV */
		// 	FlD("if we already seen this IV");
		// 	if (!uniqueiv_check(ap_cur->uiv_root, &h80211[z]))
		// 	{
		// 		/* first time seen IVs */
		// 		FlD("first time seen IVs ");
		// 		if (opt.f_ivs != NULL)
		// 		{
		// 			memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
		// 			ivs2.flags = 0;
		// 			ivs2.len = 0;

		// 			/* datalen = caplen - (header+iv+ivs) */
		// 			dlen = caplen - z - 4 - 4; // original data len
		// 			if (dlen > 2048) dlen = 2048;
		// 			// get cleartext + len + 4(iv+idx)
		// 			num_xor = known_clear(clear, &clen, weight, h80211, dlen);
		// 			if (num_xor == 1)
		// 			{
		// 				ivs2.flags |= IVS2_XOR;
		// 				ivs2.len += clen + 4;
		// 				/* reveal keystream (plain^encrypted) */
		// 				for (n = 0; n < (size_t)(ivs2.len - 4); n++)
		// 				{
		// 					clear[n] = (uint8_t)((clear[n] ^ h80211[z + 4 + n])
		// 										 & 0xFF);
		// 				}
		// 				// clear is now the keystream
		// 			}
		// 			else
		// 			{
		// 				// do it again to get it 2 bytes higher
		// 				num_xor = known_clear(
		// 					clear + 2, &clen, weight, h80211, dlen);
		// 				ivs2.flags |= IVS2_PTW;
		// 				// len = 4(iv+idx) + 1(num of keystreams) + 1(len per
		// 				// keystream) + 32*num_xor + 16*sizeof(int)(weight[16])
		// 				ivs2.len += 4 + 1 + 1 + 32 * num_xor + 16 * sizeof(int);
		// 				clear[0] = (uint8_t) num_xor;
		// 				clear[1] = (uint8_t) clen;
		// 				/* reveal keystream (plain^encrypted) */
		// 				for (o = 0; o < num_xor; o++)
		// 				{
		// 					for (n = 0; n < (size_t)(ivs2.len - 4); n++)
		// 					{
		// 						clear[2 + n + o * 32] = (uint8_t)(
		// 							(clear[2 + n + o * 32] ^ h80211[z + 4 + n])
		// 							& 0xFF);
		// 					}
		// 				}
		// 				memcpy(clear + 4 + 1 + 1 + 32 * num_xor,
		// 					   weight,
		// 					   16 * sizeof(int));
		// 				// clear is now the keystream
		// 			}

		// 			if (memcmp(lopt.prev_bssid, ap_cur->bssid, 6) != 0)
		// 			{
		// 				ivs2.flags |= IVS2_BSSID;
		// 				ivs2.len += 6;
		// 				memcpy(lopt.prev_bssid, ap_cur->bssid, 6);
		// 			}

		// 			if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), opt.f_ivs)
		// 				!= (size_t) sizeof(struct ivs2_pkthdr))
		// 			{
		// 				perror("fwrite(IV header) failed");
		// 				return (EXIT_FAILURE);
		// 			}

		// 			if (ivs2.flags & IVS2_BSSID)
		// 			{
		// 				if (fwrite(ap_cur->bssid, 1, 6, opt.f_ivs)
		// 					!= (size_t) 6)
		// 				{
		// 					perror("fwrite(IV bssid) failed");
		// 					return (1);
		// 				}
		// 				ivs2.len -= 6;
		// 			}

		// 			if (fwrite(h80211 + z, 1, 4, opt.f_ivs) != (size_t) 4)
		// 			{
		// 				perror("fwrite(IV iv+idx) failed");
		// 				return (EXIT_FAILURE);
		// 			}
		// 			ivs2.len -= 4;

		// 			if (fwrite(clear, 1, ivs2.len, opt.f_ivs)
		// 				!= (size_t) ivs2.len)
		// 			{
		// 				perror("fwrite(IV keystream) failed");
		// 				return (EXIT_FAILURE);
		// 			}
		// 		}

		// 		uniqueiv_mark(ap_cur->uiv_root, &h80211[z]);

		// 		ap_cur->nb_data++;
		// 	}

		// 	// Record all data linked to IV to detect WEP Cloaking
		// 	if (opt.f_ivs == NULL && lopt.detect_anomaly)
		// 	{
		// 		// Only allocate this when seeing WEP AP
		// 		if (ap_cur->data_root == NULL) ap_cur->data_root = data_init();

		// 		// Only works with full capture, not IV-only captures
		// 		if (data_check(ap_cur->data_root, &h80211[z], &h80211[z + 4])
		// 				== CLOAKING
		// 			&& ap_cur->EAP_detected == 0)
		// 		{

		// 			// If no EAP/EAP was detected, indicate WEP cloaking
		// 			memset(lopt.message, '\x00', sizeof(lopt.message));
		// 			snprintf(lopt.message,
		// 					 sizeof(lopt.message) - 1,
		// 					 "][ WEP Cloaking: %02X:%02X:%02X:%02X:%02X:%02X ",
		// 					 ap_cur->bssid[0],
		// 					 ap_cur->bssid[1],
		// 					 ap_cur->bssid[2],
		// 					 ap_cur->bssid[3],
		// 					 ap_cur->bssid[4],
		// 					 ap_cur->bssid[5]);
		// 		}
		// 	}
		// }
		// else
		{
			ap_cur->nb_data++;
		}

		z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
				? 24
				: 30;

		/* Check if 802.11e (QoS) */
		if ((h80211[0] & 0x80) == 0x80) z += 2;

		if (z + 26 > (unsigned) caplen) {
			goto write_packet;
		}
		z += 6; // skip LLC header

		/* check ethertype == EAPOL */
		if (h80211[z] == 0x88 && h80211[z + 1] == 0x8E
			&& (h80211[1] & 0x40) != 0x40)
		{
			ap_cur->EAP_detected = 1;

			z += 2; // skip ethertype

			if (st_cur == NULL)  {	
			  goto write_packet;
		  }

			/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

			// if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
			// 	&& (h80211[z + 6] & 0x80) != 0
			// 	&& (h80211[z + 5] & 0x01) == 0)
			// {
			// 	FlD("1 smth scary");
			// 	memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);

			// 	st_cur->wpa.state = 1;

			// 	if (h80211[z + 99] == IEEE80211_ELEMID_VENDOR)
			// 	{
			// 		const uint8_t rsn_oui[] = {RSN_OUI & 0xff,
			// 								   (RSN_OUI >> 8) & 0xff,
			// 								   (RSN_OUI >> 16) & 0xff};

			// 		if (memcmp(rsn_oui, &h80211[z + 101], 3) == 0
			// 			&& h80211[z + 104] == RSN_CSE_CCMP)
			// 		{
			// 			if (memcmp(ZERO, &h80211[z + 105], 16) != 0) //-V512
			// 			{
			// 				// Got a PMKID value?!
			// 				memcpy(st_cur->wpa.pmkid, &h80211[z + 105], 16);

			// 				/* copy the key descriptor version */
			// 				st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);

			// 				memcpy(st_cur->wpa.stmac, st_cur->stmac, 6);
			// 				memcpy(lopt.wpa_bssid, ap_cur->bssid, 6);
			// 				memset(lopt.message, '\x00', sizeof(lopt.message));
			// 				snprintf(lopt.message,
			// 						 sizeof(lopt.message) - 1,
			// 						 "][ PMKID found: "
			// 						 "%02X:%02X:%02X:%02X:%02X:%02X ",
			// 						 lopt.wpa_bssid[0],
			// 						 lopt.wpa_bssid[1],
			// 						 lopt.wpa_bssid[2],
			// 						 lopt.wpa_bssid[3],
			// 						 lopt.wpa_bssid[4],
			// 						 lopt.wpa_bssid[5]);
							
			// 				FlD("3 Skip to write_packet");	
			// 				goto write_packet;
			// 			}
			// 		}
			// 	}
			// }

			/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

		// 	if (z + 17 + 32 > (unsigned) caplen)  {
		// 	FlD("4 Skip to write_packet");	
		// 	goto write_packet;
		// }

			// if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
			// 	&& (h80211[z + 6] & 0x80) == 0
			// 	&& (h80211[z + 5] & 0x01) != 0)
			// {
			// 	if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
			// 	{
			// 		memcpy(st_cur->wpa.snonce, &h80211[z + 17], 32);
			// 		st_cur->wpa.state |= 2;
			// 	}

			// 	if ((st_cur->wpa.state & 4) != 4)
			// 	{
			// 		st_cur->wpa.eapol_size
			// 			= (uint32_t)((h80211[z + 2] << 8) + h80211[z + 3] + 4);

			// 		if (caplen - z < st_cur->wpa.eapol_size
			// 			|| st_cur->wpa.eapol_size == 0 //-V560
			// 			|| caplen - z < 81 + 16
			// 			|| st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
			// 		{
			// 			// Ignore the packet trying to crash us.
			// 			st_cur->wpa.eapol_size = 0;
			// 			 {
			// 					FlD("5 Skip to write_packet");	
			// 					goto write_packet;
			// 				}
			// 		}

			// 		memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
			// 		memcpy(
			// 			st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
			// 		memset(st_cur->wpa.eapol + 81, 0, 16);
			// 		st_cur->wpa.state |= 4;
			// 		st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
			// 	}
			// }

			/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

			// if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
			// 	&& (h80211[z + 6] & 0x80) != 0
			// 	&& (h80211[z + 5] & 0x01) != 0)
			// {
			// 	FlD("Frame 3");
			// 	if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
			// 	{
			// 		memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);
			// 		st_cur->wpa.state |= 1;
			// 	}

			// 	if ((st_cur->wpa.state & 4) != 4)
			// 	{
			// 		st_cur->wpa.eapol_size
			// 			= (h80211[z + 2] << 8) + h80211[z + 3] + 4u;

			// 		if (st_cur->wpa.eapol_size == 0 //-V560
			// 			|| st_cur->wpa.eapol_size
			// 				   >= sizeof(st_cur->wpa.eapol) - 16)
			// 		{
			// 			// Ignore the packet trying to crash us.
			// 			st_cur->wpa.eapol_size = 0;
			// 			goto write_packet;
			// 		}

			// 		memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
			// 		memcpy(
			// 			st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
			// 		memset(st_cur->wpa.eapol + 81, 0, 16);
			// 		st_cur->wpa.state |= 4;
			// 		st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
			// 	}
			// }

			// if (st_cur->wpa.state == 7 && !is_filtered_essid(ap_cur->essid))
			// {
			// 	FlD("WAP handShake");
			// 	memcpy(st_cur->wpa.stmac, st_cur->stmac, 6);
			// 	memcpy(lopt.wpa_bssid, ap_cur->bssid, 6);
			// 	memset(lopt.message, '\x00', sizeof(lopt.message));
			// 	snprintf(lopt.message,
			// 			 sizeof(lopt.message) - 1,
			// 			 "][ WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X ",
			// 			 lopt.wpa_bssid[0],
			// 			 lopt.wpa_bssid[1],
			// 			 lopt.wpa_bssid[2],
			// 			 lopt.wpa_bssid[3],
			// 			 lopt.wpa_bssid[4],
			// 			 lopt.wpa_bssid[5]);

			// 	if (opt.f_ivs != NULL)
			// 	{
			// 		memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
			// 		ivs2.flags = 0;

			// 		ivs2.len = sizeof(struct WPA_hdsk);
			// 		ivs2.flags |= IVS2_WPA;

			// 		if (memcmp(lopt.prev_bssid, ap_cur->bssid, 6) != 0)
			// 		{
			// 			ivs2.flags |= IVS2_BSSID;
			// 			ivs2.len += 6;
			// 			memcpy(lopt.prev_bssid, ap_cur->bssid, 6);
			// 		}

			// 		if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), opt.f_ivs)
			// 			!= (size_t) sizeof(struct ivs2_pkthdr))
			// 		{
			// 			perror("fwrite(IV header) failed");
			// 			return (EXIT_FAILURE);
			// 		}

			// 		if (ivs2.flags & IVS2_BSSID)
			// 		{
			// 			if (fwrite(ap_cur->bssid, 1, 6, opt.f_ivs)
			// 				!= (size_t) 6)
			// 			{
			// 				perror("fwrite(IV bssid) failed");
			// 				return (EXIT_FAILURE);
			// 			}
			// 			ivs2.len -= 6;
			// 		}

			// 		if (fwrite(&(st_cur->wpa),
			// 				   1,
			// 				   sizeof(struct WPA_hdsk),
			// 				   opt.f_ivs)
			// 			!= (size_t) sizeof(struct WPA_hdsk))
			// 		{
			// 			perror("fwrite(IV wpa_hdsk) failed");
			// 			return (EXIT_FAILURE);
			// 		}
			// 	}
			// }
		}
	}


write_packet:
	if (ap_cur != NULL)
	{
		if (h80211[0] == 0x80 && lopt.one_beacon)
		{
			if (!ap_cur->beacon_logged)
				ap_cur->beacon_logged = 1;
			else {
				return (0);
			}
		}
	}

	/* this changes the local ap_cur, st_cur and na_cur variables and should be
	 * the last check before the actual write */
	if (caplen < 24 && caplen >= 10 && h80211[0])
	{
		/* RTS || CTS || ACK || CF-END || CF-END&CF-ACK*/
		//(h80211[0] == 0xB4 || h80211[0] == 0xC4 || h80211[0] == 0xD4 ||
		// h80211[0] == 0xE4 || h80211[0] == 0xF4)

		/* use general control frame detection, as the structure is always the
		 * same: mac(s) starting at [4] */
		if (h80211[0] & 0x04)
		{
			p = h80211 + 4;
			while ((uintptr_t) p <= adds_uptr((uintptr_t) h80211, 16)
				   && (uintptr_t) p <= adds_uptr((uintptr_t) h80211, caplen))
			{
				memcpy(namac, p, 6);

				if (memcmp(namac, NULL_MAC, 6) == 0)
				{
					p += 6;
					continue;
				}

				if (memcmp(namac, BROADCAST, 6) == 0)
				{
					p += 6;
					continue;
				}

				if (lopt.hide_known)
				{
					/* check AP list */
					ap_cur = lopt.ap_1st;

					while (ap_cur != NULL)
					{
						if (!memcmp(ap_cur->bssid, namac, 6)) break;

						ap_cur = ap_cur->next;
					}

					/* if it's an AP, try next mac */

					if (ap_cur != NULL)
					{
						p += 6;
						continue;
					}

					/* check ST list */
					st_cur = lopt.st_1st;

					while (st_cur != NULL)
					{
						if (!memcmp(st_cur->stmac, namac, 6)) break;

						st_cur = st_cur->next;
					}

					/* if it's a client, try next mac */

					if (st_cur != NULL)
					{
						p += 6;
						continue;
					}
				}

				/* not found in either AP list or ST list, look through NA list
				 */
				na_cur = lopt.na_1st;
				na_prv = NULL;

				while (na_cur != NULL)
				{
					if (!memcmp(na_cur->namac, namac, 6)) break;

					na_prv = na_cur;
					na_cur = na_cur->next;
				}

				/* update our chained list of unknown stations */
				/* if it's a new mac, add it */

				if (na_cur == NULL)
				{
					if (!(na_cur
						  = (struct NA_info *) malloc(sizeof(struct NA_info))))
					{
						perror("malloc failed");
						return (1);
					}

					memset(na_cur, 0, sizeof(struct NA_info));

					if (lopt.na_1st == NULL)
						lopt.na_1st = na_cur;
					else
						na_prv->next = na_cur;

					memcpy(na_cur->namac, namac, 6);

					na_cur->prev = na_prv;

					na_cur->power = -1;
					na_cur->channel = -1;
					na_cur->ack = 0;
					na_cur->ack_old = 0;
					na_cur->ackps = 0;
					na_cur->cts = 0;
					na_cur->rts_r = 0;
					na_cur->rts_t = 0;
				}

				/* update the last time seen & power*/
				na_cur->power = ri->ri_power;
				na_cur->channel = ri->ri_channel;

				switch (h80211[0] & 0xF0)
				{
					case 0xB0:
						if (p == h80211 + 4) na_cur->rts_r++;
						if (p == h80211 + 10) na_cur->rts_t++;
						break;

					case 0xC0:
						na_cur->cts++;
						break;

					case 0xD0:
						na_cur->ack++;
						break;

					default:
						na_cur->other++;
						break;
				}

				/*grab next mac (for rts frames)*/
				p += 6;
			}
		}
	}

	// if (opt.f_cap != NULL && caplen >= 10)
	// {
	// 	FlD("cap writing?");
	// 	pkh.len = pkh.caplen = (uint32_t) caplen;

	// 	gettimeofday(&tv, NULL);

	// 	pkh.tv_sec = (int32_t) tv.tv_sec;
	// 	pkh.tv_usec = (int32_t) tv.tv_usec;

	// 	n = sizeof(pkh);

	// 	if (fwrite(&pkh, 1, n, opt.f_cap) != (size_t) n)
	// 	{
	// 		perror("fwrite(packet header) failed");
	// 		return (1);
	// 	}

	// 	fflush(stdout);

	// 	n = pkh.caplen;

	// 	if (fwrite(h80211, 1, n, opt.f_cap) != (size_t) n)
	// 	{
	// 		perror("fwrite(packet data) failed");
	// 		return (1);
	// 	}

	// 	fflush(stdout);
	// }
	return (0);
}

void scanner::launch() {
  int fd_raw = wi->wi_fd(wi);
  int fdh = fd_raw > 0 ? fd_raw : 0;
  int chan_count = getchancount(0);

  fd_set rfds;
  pid_t main_pid = getpid();
  struct rx_info ri;

	pipe(lopt.ch_pipe);
	pipe(lopt.cd_pipe);

{
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
}

	if (setuid(getuid()) == -1)
	{
		perror("setuid");
	}

  struct sigaction action;
	action.sa_flags = 0;
	action.sa_handler = &sighandler;
	sigemptyset(&action.sa_mask);

	if (sigaction(SIGINT, &action, NULL) == -1) perror("sigaction(SIGINT)");
	if (sigaction(SIGSEGV, &action, NULL) == -1) perror("sigaction(SIGSEGV)");
	if (sigaction(SIGTERM, &action, NULL) == -1) perror("sigaction(SIGTERM)");
	if (sigaction(SIGWINCH, &action, NULL) == -1) perror("sigaction(SIGWINCH)");


	lopt.manufList = load_oui_file();
	// Do not start the interactive mode input thread if running in the
	// background
	if (lopt.background_mode == -1) lopt.background_mode = is_background();

	// if (!lopt.background_mode
	// 	&& pthread_create(&(lopt.input_tid), NULL, &input_thread, NULL) != 0) // yes, in backgroung
	// {
	// 	perror("pthread_create failed");
	// 	exit(-1);
	// }
	struct timeval tv0;
  unsigned char buffer[4096];
	unsigned char * h80211;
  int it = 100;
  while(it--) {

    if (lopt.s_iface != NULL)
		{
			/* capture one packet */
			FD_ZERO(&rfds);
			for (int i = 0; i < lopt.num_cards; i++)
			{
				FD_SET(fd_raw, &rfds); // NOLINT(hicpp-signed-bitwise)
			}
      tv0.tv_sec = lopt.update_s;
			tv0.tv_usec = (lopt.update_s == 0) ? 100000 : 0;
			int select_state = select(fdh + 1, &rfds, NULL, NULL, &tv0);
			if (select_state < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}
				perror("select failed");
				/* Restore terminal */
				exit(-1);
			}
		}
		else
			usleep(1);
    int read_pkts = 0;
    if (lopt.s_iface != NULL)
		{
			for (int i = 0; i < lopt.num_cards; i++)
			{
				if (FD_ISSET(fd_raw, &rfds)) // NOLINT(hicpp-signed-bitwise)
				{
					memset(buffer, 0, sizeof(buffer));
					h80211 = buffer;
          int caplen = 0;
					if ((caplen = wi->wi_read(
							 wi, NULL, NULL, h80211, sizeof(buffer), &ri))
						== -1)
					{
						printf("Cannot read. Monitor is down");
					}
					read_pkts++;
					dump_add_packet(h80211, caplen, &ri, i);
				}
			}
		}

    printAT_ST();

  }

}


void printAT_ST()
{
  AP_info * ap_current =  lopt.ap_1st;
  if (!ap_current)
    return;

  static int it = 0;
  int ap_c = 0;
  printf("IT: %d\n", it++);
  printf("%p, %p\n", ap_current, lopt.ap_end);
  while (ap_current != lopt.ap_end) {
    printf("AP: %d\n\t", ap_c);
    for (int i = 0; i != 6; ++i) {
      printf("%d:", ap_current->bssid[i]);
    }
    printf("\n");
  }

  printf("AP: %d\n\t", ap_c);
  for (int i = 0; i != 6; ++i) {
    printf("%d:", ap_current->bssid[i]);
  }

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