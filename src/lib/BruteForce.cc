#include <BruteForce.h>

#include <station.h>
#include <pcap.h>
#include <ieee80211_def.h>

#include <iostream>
#include <array>
#include <vector>
#include <cassert>

BruteForce::BruteForce(path const & bin, uint8_t const * bssid)
  : m_WordlistFile {path{bin + "Passwords.txt"}.getRaw()}
  , m_CapFile {path{bin + "Dump.cap"}.getRaw()} {
  if (!m_WordlistFile.is_open()) {
    std::cerr << "No password list: " << path{bin + "Passwords.txt"} << std::endl;
    return;
  }
  if (!m_CapFile.is_open()) {
    std::cerr << "No CAP file: " << path{bin + "Dump.cap"} << std::endl;
    return;
  }

  memcpy(m_BSSID, bssid, sizeof(m_BSSID));
  DoWPAHack();
}

bool BruteForce::GetNextKey(std::string & key) {
  while (m_WordlistFile.good()) {
    std::getline(m_WordlistFile, key);
    if (!key.size())
      continue;
    return true;
  }

  return false;
}

void BruteForce::DoWPAHack() {

  GetAPInfo();

  std::string key;
  bool IsHacked {false};
  while (!IsHacked && GetNextKey(key))
    IsHacked = CheckKey(key);

  if (IsHacked)
    std::cout << "Key found: [" << key << "]\n";
  else
    std::cout << "No key\n";
}

bool BruteForce::CheckKey(std::string const & key) {
  return true;
}

void BruteForce::GetAPInfo() {
	uint8_t * buffer {nullptr};

	pcap_pkthdr pkh;
	pcap_file_header pfh;

	if ((buffer = (unsigned char *) malloc(65536)) == NULL) {
		/* there is no buffer */
		perror("malloc failed");
    return;
	}

  if (!m_CapFile.read((char*)&pfh, 24).good()) {
		perror("read(file header) failed");
    free(buffer);
    return;
  }


	while (1) {
    if (!m_CapFile.read((char*)&pkh, sizeof(pkh)).eof())
      break;

    if (!m_CapFile.read((char*)buffer, pkh.caplen).eof())
      break;

    ProcessPacket(buffer, pkh);
	}

  free(buffer);
}

void BruteForce::ProcessPacket(uint8_t * h80211, pcap_pkthdr const & pkh) {
  uint8_t bssid[6];

  /* skip packets smaller than a 802.11 header */
  if (pkh.caplen < 24) return;

  /* skip (uninteresting) control frames */
  if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
    return;

  /* locate the access point's MAC address */
  switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
  {
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
      fprintf(stderr,
          "Expected a value between 0 and 3, got %d.\n",
          h80211[1] & IEEE80211_FC1_DIR_MASK);
      break;
  }

	if (memcmp(bssid, BROADCAST, 6) == 0)
		/* probe request or such - skip the packet */
		return;

  if (memcmp(bssid, m_BSSID, 6) != 0)
    return;

	/* if it's a new access point, add it */
	if (!m_CurrAp) {
    m_CurrAp = new AP_info{};
		memcpy(m_CurrAp->bssid, bssid, 6);

		// TODO not need this shit i belive
		// m_CurrAp->crypt = -1;
	}

	Update_APInfo(h80211, pkh);

	return;
}

void BruteForce::Update_APInfo(uint8_t * h80211, pcap_pkthdr const & pkh) {

	ST_info * st_cur = NULL;
	uint8_t stmac[6];
	unsigned char * p = NULL;


	switch (h80211[1] & IEEE80211_FC1_DIR_MASK) {
		case IEEE80211_FC1_DIR_NODS:
		case IEEE80211_FC1_DIR_TODS:
			memcpy(stmac, h80211 + 10, 6);
			break;

		case IEEE80211_FC1_DIR_FROMDS:
			/* reject broadcast MACs */
			if ((h80211[4] % 2) != 0) goto skip_station;
			memcpy(stmac, h80211 + 4, 6);
			break;

		default:
			goto skip_station;
	}

  {
    auto FindIt = m_Stations.find(stmac);
    if (FindIt == m_Stations.end()) {
      st_cur = new ST_info{};
      memset(st_cur, 0, sizeof(ST_info));

      memcpy(st_cur->stmac, stmac, sizeof(st_cur->stmac));
      auto [FindIt, IsEmplace] = m_Stations.emplace(stmac, st_cur);
      assert(IsEmplace && "Station has been replaced!");
    }
    st_cur = FindIt->second;
  }
skip_station:

	/* packet parsing: Beacon or Probe Response */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_BEACON
		|| h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
		p = h80211 + 36;

		while (p < h80211 + pkh.caplen) {
			if (p + 2 + p[1] > h80211 + pkh.caplen) break;

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0') {
				/* found a non-cloaked ESSID */
				size_t n = (p[1] > 32) ? 32 : p[1];

				memset(m_CurrAp->essid, 0, ESSID_LENGTH + 1);
				memcpy(m_CurrAp->essid, p + 2, n);
			}

			p += 2 + p[1];
		}
	}

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA)
		return;

	/* check minimum size */

	unsigned z
		= ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
			  ? 24
			  : 30;
	if ((h80211[0] & IEEE80211_FC0_SUBTYPE_BEACON)
		== IEEE80211_FC0_SUBTYPE_BEACON)
		z += 2; /* 802.11e QoS */

	if (z + 16 > pkh.caplen) return;

	z += 6;

	if (h80211[z] != 0x88 || h80211[z + 1] != 0x8E) return;

	z += 2;

	m_CurrAp->EAP_detected = 1;

	/* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

	if (h80211[z + 1] != 0x03
		|| (h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02))
		return;

	m_CurrAp->EAP_detected = 0;

	if (st_cur == NULL) {
		// NOTE: no station present; so we want to SKIP this AP.
		return;
	}

	/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

	if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
		&& (h80211[z + 6] & 0x80) == 0
		&& (h80211[z + 5] & 0x01) != 0) {
		if (memcmp(&h80211[z + 17], ZERO, sizeof(st_cur->wpa.snonce)) != 0) {
			memcpy(st_cur->wpa.snonce,
				   &h80211[z + 17],
				   sizeof(st_cur->wpa.snonce));

			/* supplicant nonce set */
			st_cur->wpa.state |= 2;
		}


		if ((st_cur->wpa.state & 4) != 4) {
			/* copy the MIC & eapol frame */
			st_cur->wpa.eapol_size
				= (uint32_t)((h80211[z + 2] << 8) + h80211[z + 3] + 4);

			if (st_cur->wpa.eapol_size == 0 //-V560
				|| st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol)
				|| pkh.len - z < st_cur->wpa.eapol_size) {
				// Ignore the packet trying to crash us.
				st_cur->wpa.eapol_size = 0;
				return;
			}

			memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
			memcpy(st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
			memset(st_cur->wpa.eapol + 81, 0, 16);


			/* eapol frame & keymic set */
			st_cur->wpa.state |= 4;

			/* copy the key descriptor version */
			st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
		}
	}

	/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */
	/* M3's replay counter MUST be larger than M1/M2's. */

	if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
		&& (h80211[z + 6] & 0x80) != 0
		&& (h80211[z + 5] & 0x01) != 0) {

		if (memcmp(&h80211[z + 17], ZERO, sizeof(st_cur->wpa.anonce)) != 0) {
			memcpy(st_cur->wpa.anonce,
				   &h80211[z + 17],
				   sizeof(st_cur->wpa.anonce));

			/* authenticator nonce set */
			st_cur->wpa.state |= 1;
		}

	}

	// The new PMKID attack permits any state greater than 0, with a PMKID
	// present.
	if (st_cur->wpa.state == 7
		|| (st_cur->wpa.state > 0 && st_cur->wpa.pmkid[0] != 0x00)) {
		/* got one valid handshake */
		memcpy(st_cur->wpa.stmac, stmac, 6);
		memcpy(&m_CurrAp->wpa, &st_cur->wpa, sizeof(WPA_hdsk));
	}

	return;
}

