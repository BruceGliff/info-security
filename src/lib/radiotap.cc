/*
 * Radiotap parser
 *
 * Copyright 2007		Andy Green <andy@warmcat.com>
 * Copyright 2009		Johannes Berg <johannes@sipsolutions.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of ISC
 * license, see COPYING for more details.
 */
#include "radiotap_iter.h"
#include "platform.h"


int getChannelFromFrequency(int frequency) {
	if (frequency >= 2412 && frequency <= 2472)
		return (frequency - 2407) / 5;
	else if (frequency == 2484)
		return 14;

	else if (frequency >= 4920 && frequency <= 6100)
		return (frequency - 5000) / 5;
	else
		return -1;
}

/* function prototypes and related defs are in radiotap_iter.h */

static const struct radiotap_align_size rtap_namespace_sizes[] = {
	[IEEE80211_RADIOTAP_TSFT] = { .align = 8, .size = 8, },
	[IEEE80211_RADIOTAP_FLAGS] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_RATE] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_CHANNEL] = { .align = 2, .size = 4, },
	[IEEE80211_RADIOTAP_FHSS] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DBM_ANTNOISE] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_LOCK_QUALITY] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_TX_ATTENUATION] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_DBM_TX_POWER] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_ANTENNA] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DB_ANTSIGNAL] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DB_ANTNOISE] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_RX_FLAGS] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_TX_FLAGS] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_RTS_RETRIES] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DATA_RETRIES] = { .align = 1, .size = 1, },
  [18] = { .align = 12, .size = 32},
	[IEEE80211_RADIOTAP_MCS] = { .align = 1, .size = 3, },
	[IEEE80211_RADIOTAP_AMPDU_STATUS] = { .align = 4, .size = 8, },
	[IEEE80211_RADIOTAP_VHT] = { .align = 2, .size = 12, },
	[IEEE80211_RADIOTAP_TIMESTAMP] = { .align = 8, .size = 12, },
	/*
	 * add more here as they are defined in radiotap.h
	 */
};

static const struct ieee80211_radiotap_namespace radiotap_ns = {
	.align_size = rtap_namespace_sizes,
	.n_bits = sizeof(rtap_namespace_sizes) / sizeof(rtap_namespace_sizes[0])
};

EXPORT
int ieee80211_radiotap_iterator_init(
	struct ieee80211_radiotap_iterator *iterator,
	struct ieee80211_radiotap_header *radiotap_header,
	int max_length, const struct ieee80211_radiotap_vendor_namespaces *vns)
{
	/* must at least have the radiotap header */
	if (max_length < (int)sizeof(struct ieee80211_radiotap_header))
		return -EINVAL;

	/* Linux only supports version 0 radiotap format */
	if (radiotap_header->it_version)
		return -EINVAL;

	/* sanity check for allowed length and radiotap length field */
	if (max_length < get_unaligned_le16(UNALIGNED_ADDRESS(&radiotap_header->it_len)))
		return -EINVAL;

	iterator->_rtheader = radiotap_header;
	iterator->_max_length = get_unaligned_le16(UNALIGNED_ADDRESS(&radiotap_header->it_len));
	iterator->_arg_index = 0;
	iterator->_bitmap_shifter = get_unaligned_le32(UNALIGNED_ADDRESS(&radiotap_header->it_present));
	iterator->_arg = (uint8_t *)radiotap_header + sizeof(*radiotap_header);
	iterator->_reset_on_ext = 0;
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif
	iterator->_next_bitmap = (uint32_t*) UNALIGNED_ADDRESS(&radiotap_header->it_present);
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9
#pragma GCC diagnostic pop
#endif
	iterator->_next_bitmap++;
	iterator->_vns = vns;
	iterator->current_namespace = &radiotap_ns;
	iterator->is_radiotap_ns = 1;
#ifdef RADIOTAP_SUPPORT_OVERRIDES
	iterator->n_overrides = 0;
	iterator->overrides = NULL;
#endif

	/* find payload start allowing for extended bitmap(s) */

	if (iterator->_bitmap_shifter & (1<<IEEE80211_RADIOTAP_EXT)) {
		if ((unsigned long)iterator->_arg -
		    (unsigned long)iterator->_rtheader + sizeof(uint32_t) >
		    (unsigned long)iterator->_max_length)
			return -EINVAL;
		while (get_unaligned_le32(iterator->_arg) &
					(1 << IEEE80211_RADIOTAP_EXT)) {
			iterator->_arg += sizeof(uint32_t);

			/*
			 * check for insanity where the present bitmaps
			 * keep claiming to extend up to or even beyond the
			 * stated radiotap header length
			 */

			if ((unsigned long)iterator->_arg -
			    (unsigned long)iterator->_rtheader +
			    sizeof(uint32_t) >
			    (unsigned long)iterator->_max_length)
				return -EINVAL;
		}

		iterator->_arg += sizeof(uint32_t);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	iterator->this_arg = iterator->_arg;

	/* we are all initialized happily */

	return 0;
}

static void find_ns(struct ieee80211_radiotap_iterator *iterator,
		    uint32_t oui, uint8_t subns)
{
	int i;

	iterator->current_namespace = NULL;

	if (!iterator->_vns)
		return;

	for (i = 0; i < iterator->_vns->n_ns; i++) {
		if (iterator->_vns->ns[i].oui != oui)
			continue;
		if (iterator->_vns->ns[i].subns != subns)
			continue;

		iterator->current_namespace = &iterator->_vns->ns[i];
		break;
	}
}

EXPORT
int ieee80211_radiotap_iterator_next(
	struct ieee80211_radiotap_iterator *iterator)
{
	while (1) {
		int hit = 0;
		int pad, align, size, subns;
		uint32_t oui;

		/* if no more EXT bits, that's it */
		if ((iterator->_arg_index % 32) == IEEE80211_RADIOTAP_EXT &&
		    !(iterator->_bitmap_shifter & 1))
			return -ENOENT;

		if (!(iterator->_bitmap_shifter & 1))
			goto next_entry; /* arg not present */

		/* get alignment/size of data */
		switch (iterator->_arg_index % 32) {
		case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
		case IEEE80211_RADIOTAP_EXT:
			align = 1;
			size = 0;
			break;
		case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
			align = 2;
			size = 6;
			break;
		default:
#ifdef RADIOTAP_SUPPORT_OVERRIDES
			if (find_override(iterator, &align, &size)) {
				/* all set */
			} else
#endif
			if (!iterator->current_namespace ||
			    iterator->_arg_index >= iterator->current_namespace->n_bits) {
				if (iterator->current_namespace == &radiotap_ns)
					return -ENOENT;
				align = 0;
			} else {
				align = iterator->current_namespace->align_size[iterator->_arg_index].align;
				size = iterator->current_namespace->align_size[iterator->_arg_index].size;
			}
			if (!align) {
				/* skip all subsequent data */
				iterator->_arg = iterator->_next_ns_data;
				/* give up on this namespace */
				iterator->current_namespace = NULL;
				goto next_entry;
			}
			break;
		}


		pad = ((unsigned long)iterator->_arg -
		       (unsigned long)iterator->_rtheader) & (align - 1);

		if (pad)
			iterator->_arg += align - pad;

		if (iterator->_arg_index % 32 == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
			int vnslen;

			if ((unsigned long)iterator->_arg + size -
			    (unsigned long)iterator->_rtheader >
			    (unsigned long)iterator->_max_length)
				return -EINVAL;

			oui = (*iterator->_arg << 16) |
				(*(iterator->_arg + 1) << 8) |
				*(iterator->_arg + 2);
			subns = *(iterator->_arg + 3);

			find_ns(iterator, oui, subns);

			vnslen = get_unaligned_le16(iterator->_arg + 4);
			iterator->_next_ns_data = iterator->_arg + size + vnslen;
			if (!iterator->current_namespace)
				size += vnslen;
		}

		iterator->this_arg_index = iterator->_arg_index;
		iterator->this_arg = iterator->_arg;
		iterator->this_arg_size = size;

		/* internally move on the size of this arg */
		iterator->_arg += size;

		if ((unsigned long)iterator->_arg -
		    (unsigned long)iterator->_rtheader >
		    (unsigned long)iterator->_max_length)
			return -EINVAL;

		/* these special ones are valid in each bitmap word */
		switch (iterator->_arg_index % 32) {
		case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
			iterator->_reset_on_ext = 1;

			iterator->is_radiotap_ns = 0;
			iterator->this_arg_index =
				IEEE80211_RADIOTAP_VENDOR_NAMESPACE;
			if (!iterator->current_namespace)
				hit = 1;
			goto next_entry;
		case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
			iterator->_reset_on_ext = 1;
			iterator->current_namespace = &radiotap_ns;
			iterator->is_radiotap_ns = 1;
			goto next_entry;
		case IEEE80211_RADIOTAP_EXT:
			/*
			 * bit 31 was set, there is more
			 * -- move to next u32 bitmap
			 */
			iterator->_bitmap_shifter =
				get_unaligned_le32(iterator->_next_bitmap);
			iterator->_next_bitmap++;
			if (iterator->_reset_on_ext)
				iterator->_arg_index = 0;
			else
				iterator->_arg_index++;
			iterator->_reset_on_ext = 0;
			break;
		default:
			/* we've got a hit! */
			hit = 1;
 next_entry:
			iterator->_bitmap_shifter >>= 1;
			iterator->_arg_index++;
		}

		/* if we found a valid arg earlier, return it now */
		if (hit)
			return 0;
	}
}
