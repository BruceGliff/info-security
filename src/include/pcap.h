#pragma once

#include <inttypes.h>

#define TCPDUMP_MAGIC 0xA1B2C3D4
#define TCPDUMP_CIGAM 0xD4C3B2A1

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define LINKTYPE_IEEE802_11 105

struct pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
};
struct pcap_pkthdr {
	int32_t tv_sec;
	int32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};