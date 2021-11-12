#include <AP_Selecter.h>

#include <station.h>
#include <wif.h>

#include <iostream>

#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <csignal>
#include <unistd.h>
#include <errno.h>
#include <cstring>

#define MIN(x,y) ((x) > (y) ? (y) : (x))

static AP_info * launch(char const * Iface);
static void release(AP_info * AP_Node);

AP_Selecter::AP_Selecter(char const * Iface) {
  AP_info * AP_first = launch(Iface);
  GetAPs(AP_first);
  release(AP_first);
};

void AP_Selecter::GetAPs(AP_info * AP_1st) {
  while (AP_1st != NULL) {
    if (strlen((char*)AP_1st->essid))
    m_AP_Chain.emplace_back(AP_1st->bssid, AP_1st->essid, AP_1st->channel);
    AP_1st = AP_1st->next;
  }
}

AP_Selecter & AP_Selecter::ChooseAP() {
  PrintAPs();
  bool isSelectBad = true;
  uint value {0};
  while (isSelectBad) {
    std::cout << "\nEnter valid AcessPoint number: ";
    std::cin.clear();
    std::cin >> value;

    isSelectBad = !(value < m_AP_Chain.size());
  }

  m_PreferedAP = m_AP_Chain.begin() + value;
	return *this;
}

AP_info_tiny const & AP_Selecter::GetPreferedAP() const {
  return *m_PreferedAP;
}

void AP_Selecter::PrintAPs() {
  int it = 0;
  for (auto && x : m_AP_Chain) {
    std::cout << '[' << it++ << "] ";
    x.Print(); 
  }
}

AP_info_tiny::AP_info_tiny(uint8_t * bssid_in, uint8_t * essid_in, uint8_t channel_in) {
  memcpy(bssid, bssid_in, sizeof(bssid));
  memcpy(essid, essid_in, ESSID_LENGTH + 1);
	channel = channel_in;
}
void AP_info_tiny::Print() const {
	printf("{%02d} - ", channel);
  for (int i = 0; i != 5; ++i)
    printf("%02x:", bssid[i]);
  printf("%02x   %s\n", bssid[5], essid);
}

static void release(AP_info * AP_Node) {
  assert(AP_Node && "Node is NULL");
  AP_info * AP_Next {nullptr};
	while (AP_Node != NULL) {
		// Freeing AP List
		AP_Next = AP_Node->next;
		free(AP_Node);
		AP_Node = AP_Next;
	}
}

static int bg_chans[] = {10, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0};

/* bunch of global stuff */
static struct local_options
{
	struct AP_info *ap_1st, *ap_end;
	int channel;
	int ch_pipe[2];
	int * channels;
	int update_s;
	volatile int do_exit;
	int hopfreq;
	char const * s_iface;
} lopt;

static int add_packet(unsigned char * h80211,
						   int caplen, int ch) {
  assert(h80211 && "packet is NULL");
	size_t n;
	unsigned char *p;
	unsigned char bssid[6];

	struct AP_info * ap_cur = NULL;
	struct AP_info * ap_prv = NULL;


	/* skip packets smaller than a 802.11 header */
	if (caplen < (int) sizeof(struct ieee80211_frame)) return 0;

	/* skip (uninteresting) control frames */
	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
		return 0;

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK) {
		case IEEE80211_FC1_DIR_NODS:
			memcpy(bssid, h80211 + 16, 6); //-V525
			break; // Adhoc
		case IEEE80211_FC1_DIR_TODS:
			memcpy(bssid, h80211 + 4, 6);
			break; // ToDS
		case IEEE80211_FC1_DIR_FROMDS:
		case IEEE80211_FC1_DIR_DSTODS:
			memcpy(bssid, h80211 + 10, 6);
			break; // WDS -> Transmitter taken as BSSID
		default:
			abort();
	}

	/* update our chained list of access points */
	ap_cur = lopt.ap_1st;
	ap_prv = NULL;

	while (ap_cur != NULL) {
		if (!memcmp(ap_cur->bssid, bssid, 6)) break;

		ap_prv = ap_cur;
		ap_cur = ap_cur->next;
	}

	if (ap_cur == NULL) {
		if (!(ap_cur = (struct AP_info *) calloc(1, sizeof(struct AP_info)))) {
			perror("calloc failed");
			return (1);
		}

		if (lopt.ap_1st == NULL)
			lopt.ap_1st = ap_cur;
		else if (ap_prv != NULL)
			ap_prv->next = ap_cur;

		memcpy(ap_cur->bssid, bssid, 6);
		ap_cur->prev = ap_prv;
		lopt.ap_end = ap_cur;
		memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
		ap_cur->channel = ch;
	}


	if (h80211[0] == IEEE80211_FC0_SUBTYPE_BEACON
		|| h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
		p = h80211 + 36;

		while (p < h80211 + caplen) {
			if (p + 2 + p[1] > h80211 + caplen) break;

			// only update the essid length if the new length is > the old one
			if (p[0] == 0x00 && (ap_cur->ssid_length < p[1]))
				ap_cur->ssid_length = p[1];

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' ')) {
				/* found a non-cloaked ESSID */
				n = MIN(ESSID_LENGTH, p[1]);

				memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
				memcpy(ap_cur->essid, p + 2, n);
			}

			p += 2 + p[1];
		}
	}
	return (0);
}

static void sighandler(int signum) {
	if (signum == SIGINT || signum == SIGTERM)
		lopt.do_exit = 1;

	if (signum == SIGUSR1) {
		read(lopt.ch_pipe[0], &lopt.channel, sizeof(int));
	}

	if (signum == SIGSEGV) exit(1);

	if (signum == SIGALRM) exit(1);

	if (signum == SIGCHLD) wait(NULL);

	if (signum == SIGWINCH)
		fflush(stdout);
}

static void
channel_hopper(wif * wi, int chan_count, pid_t parent) {
	int chi = 0;
	while (0 == kill(parent, 0)) {
		int const ch = lopt.channels[chi++ % chan_count];
		if (wi->wi_set_channel(wi, ch) == 0) {
			lopt.channel = ch;
			write(lopt.ch_pipe[1], &ch, sizeof(int));
			kill(parent, SIGUSR1);
			usleep(1000);
		}
		usleep((useconds_t)(lopt.hopfreq * 1000));
	}
	exit(0);
}


static AP_info * launch(char const * Iface) {
	int caplen = 0, chan_count;
	int fd_raw;
	struct rx_info rx; // rx remove lots of empty ACs
	char ifnam[64];

	unsigned char buffer[4096];
	unsigned char * h80211;

	struct timeval tv0;
	fd_set rfds;


	pid_t main_pid = getpid();

	memset(&lopt, 0, sizeof(lopt));

	h80211 = NULL;
	lopt.channels = (int *) bg_chans;
	lopt.update_s = 0;
	lopt.hopfreq = DEFAULT_HOPFREQ;
	lopt.s_iface = NULL;

	fd_raw = -1;
	lopt.channel = 0;

	lopt.s_iface = Iface;

  wif * wi = wi_open(lopt.s_iface);
	fd_raw = wi->wi_fd(wi);

	chan_count = sizeof(bg_chans) / sizeof(int);
	pipe(lopt.ch_pipe);

	struct sigaction action;
	action.sa_flags = 0;
	action.sa_handler = &sighandler;
	sigemptyset(&action.sa_mask);

	if (sigaction(SIGUSR1, &action, NULL) == -1)
		perror("sigaction(SIGUSR1)");

  pid_t child_pid = fork();
	if (!child_pid) {
		strncpy(ifnam, wi_get_ifname(wi), ESSID_LENGTH);
    wi_close(wi);
		wi = wi_open(ifnam);
		if (!wi) {
			printf("Can't reopen %s\n", ifnam);
			exit(EXIT_FAILURE);
		}

		/* Drop privileges */
		if (setuid(getuid()) == -1)
			perror("setuid");

		channel_hopper(wi, chan_count, main_pid);
		exit(EXIT_FAILURE);
	}

	/* Drop privileges */
	if (setuid(getuid()) == -1)
		perror("setuid");

	if (sigaction(SIGINT, &action, NULL) == -1) perror("sigaction(SIGINT)");
	if (sigaction(SIGSEGV, &action, NULL) == -1) perror("sigaction(SIGSEGV)");
	if (sigaction(SIGTERM, &action, NULL) == -1) perror("sigaction(SIGTERM)");
	if (sigaction(SIGWINCH, &action, NULL) == -1) perror("sigaction(SIGWINCH)");

	
	time_t start = time(NULL);
	time_t end = time(NULL);

	tv0.tv_sec = lopt.update_s;
	tv0.tv_usec = (lopt.update_s == 0) ? REFRESH_RATE : 0;
	// MYW
	while (end - start < 5)
	{
		end = time(NULL);
		if (lopt.do_exit)
			break;

		FD_ZERO(&rfds);
		FD_SET(fd_raw, &rfds);

    int select_st = select(fd_raw + 1, &rfds, NULL, NULL, &tv0);
    // printf("%d\n", select_st);
		if (select_st < 0) {
			if (errno == EINTR)
				continue;
			perror("select failed");
			return nullptr;
		}

		if (FD_ISSET(fd_raw, &rfds)) {
			memset(buffer, 0, sizeof(buffer));
			h80211 = buffer;
			if ((caplen = wi_read(
						wi, NULL, NULL, h80211, sizeof(buffer), &rx))
				== -1) {
				perror("iface down");
				break;
			}
			int ch = lopt.channel;
			add_packet(h80211, caplen, ch);
		}
	}
  wi_close(wi);

  kill(child_pid, SIGKILL);

	return lopt.ap_1st;
}
