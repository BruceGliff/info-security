#ifndef __RADIOTAP_ITER_H
#define __RADIOTAP_ITER_H

#include <stdint.h>
#include "radiotap.h"
#include "platform.h"

struct radiotap_override {
	uint8_t field;
	uint8_t align:4, size:4;
};

struct radiotap_align_size {
	uint8_t align:4, size:4;
};

struct ieee80211_radiotap_namespace {
	const struct radiotap_align_size *align_size;
	int n_bits;
	uint32_t oui;
	uint8_t subns;
};

struct ieee80211_radiotap_vendor_namespaces {
	const struct ieee80211_radiotap_namespace *ns;
	int n_ns;
};

struct ieee80211_radiotap_iterator {
	struct ieee80211_radiotap_header *_rtheader;
	const struct ieee80211_radiotap_vendor_namespaces *_vns;
	const struct ieee80211_radiotap_namespace *current_namespace;

	unsigned char *_arg, *_next_ns_data;
	uint32_t *_next_bitmap;

	unsigned char *this_arg;
	const struct radiotap_override *overrides;	/* Only for RADIOTAP_SUPPORT_OVERRIDES */
	int n_overrides;				/* Only for RADIOTAP_SUPPORT_OVERRIDES */
	int this_arg_index;
	int this_arg_size;

	int is_radiotap_ns;

	int _max_length;
	int _arg_index;
	uint32_t _bitmap_shifter;
	int _reset_on_ext;
};

#ifdef __cplusplus
#define CALLING_CONVENTION "C"
#else
#define CALLING_CONVENTION
#endif

extern CALLING_CONVENTION int ieee80211_radiotap_iterator_init(
	struct ieee80211_radiotap_iterator *iterator,
	struct ieee80211_radiotap_header *radiotap_header,
	int max_length, const struct ieee80211_radiotap_vendor_namespaces *vns);

extern CALLING_CONVENTION int ieee80211_radiotap_iterator_next(
	struct ieee80211_radiotap_iterator *iterator);

#endif /* __RADIOTAP_ITER_H */
