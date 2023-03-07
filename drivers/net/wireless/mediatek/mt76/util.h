/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
 * Copyright (C) 2004 - 2009 Ivo van Doorn <IvDoorn@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __MT76_UTIL_H
#define __MT76_UTIL_H

#include <linux/skbuff.h>
#include <linux/bitops.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,8,17)
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define __scalar_type_to_unsigned_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(unsigned type)0
#define __unsigned_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			char:	(unsigned char)0,			\
			__scalar_type_to_unsigned_cases(char),		\
			__scalar_type_to_unsigned_cases(short),		\
			__scalar_type_to_unsigned_cases(int),		\
			__scalar_type_to_unsigned_cases(long),		\
			__scalar_type_to_unsigned_cases(long long),	\
			default: (x)))
#define FIELD_MAX(_mask)						\
	({								\
		(typeof(_mask))((_mask) >> __bf_shf(_mask));		\
	})
#define FIELD_FIT(_mask, _val)						\
	({								\
		!((((typeof(_mask))_val) << __bf_shf(_mask)) & ~(_mask)); \
	})
#define FIELD_PREP(_mask, _val)						\
	({								\
		((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask);	\
	})
#define FIELD_GET(_mask, _reg)						\
	({								\
		(typeof(_mask))(((_reg) & (_mask)) >> __bf_shf(_mask));	\
	})
#else
#include <linux/bitfield.h>
#endif

#define MT76_INCR(_var, _size) \
	_var = (((_var) + 1) % _size)

int mt76_wcid_alloc(unsigned long *mask, int size);

static inline void
mt76_wcid_free(unsigned long *mask, int idx)
{
	mask[idx / BITS_PER_LONG] &= ~BIT(idx % BITS_PER_LONG);
}

static inline void
mt76_skb_set_moredata(struct sk_buff *skb, bool enable)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;

	if (enable)
		hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_MOREDATA);
	else
		hdr->frame_control &= ~cpu_to_le16(IEEE80211_FCTL_MOREDATA);
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,16,18)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/**
 * sg_mark_end - Mark the end of the scatterlist
 * @sg:		 SG entryScatterlist
 *
 * Description:
 *   Marks the passed in sg entry as the termination point for the sg
 *   table. A call to sg_next() on this entry will return NULL.
 *
 **/
static inline void sg_mark_end(struct scatterlist *sg)
{
	/*
	 * Set termination bit, clear potential chain bit
	 */
	sg->page_link |= SG_END;
	sg->page_link &= ~SG_CHAIN;
}
#endif
/**
 * sg_init_marker - Initialize markers in sg table
 * @sgl:	   The SG table
 * @nents:	   Number of entries in table
 *
 **/
static inline void sg_init_marker(struct scatterlist *sgl,
				  unsigned int nents)
{
	sg_mark_end(&sgl[nents - 1]);
}
#endif
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,14)
static inline void *skb_put_data(struct sk_buff *skb, const void *data,
				 unsigned int len)
{
	void *tmp = skb_put(skb, len);

	memcpy(tmp, data, len);

	return tmp;
}
int __skb_pad(struct sk_buff *skb, int pad, bool free_on_error);
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,4,270)
static inline bool ieee80211_is_frag(struct ieee80211_hdr *hdr)
{
	return ieee80211_has_morefrags(hdr->frame_control) ||
	       hdr->seq_ctrl & cpu_to_le16(IEEE80211_SCTL_FRAG);
}
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,4,267)
#define is_signed_type(type)       (((type)(-1)) < (type)1)
#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - is_signed_type(type)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T)-type_max(T)-(T)1))
#define __unsigned_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a + __b;			\
	*__d < __a;				\
})

#define __unsigned_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a - __b;			\
	__a < __b;				\
})

#define __unsigned_mul_overflow(a, b, d) ({		\
	typeof(a) __a = (a);				\
	typeof(b) __b = (b);				\
	typeof(d) __d = (d);				\
	(void) (&__a == &__b);				\
	(void) (&__a == __d);				\
	*__d = __a * __b;				\
	__builtin_constant_p(__b) ?			\
	  __b > 0 && __a > type_max(typeof(__a)) / __b : \
	  __a > 0 && __b > type_max(typeof(__b)) / __a;	 \
})

#define __signed_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a + (u64)__b;		\
	(((~(__a ^ __b)) & (*__d ^ __a))	\
		& type_min(typeof(__a))) != 0;	\
})

#define __signed_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a - (u64)__b;		\
	((((__a ^ __b)) & (*__d ^ __a))		\
		& type_min(typeof(__a))) != 0;	\
})

#define __signed_mul_overflow(a, b, d) ({				\
	typeof(a) __a = (a);						\
	typeof(b) __b = (b);						\
	typeof(d) __d = (d);						\
	typeof(a) __tmax = type_max(typeof(a));				\
	typeof(a) __tmin = type_min(typeof(a));				\
	(void) (&__a == &__b);						\
	(void) (&__a == __d);						\
	*__d = (u64)__a * (u64)__b;					\
	(__b > 0   && (__a > __tmax/__b || __a < __tmin/__b)) ||	\
	(__b < (typeof(__b))-1  && (__a > __tmin/__b || __a < __tmax/__b)) || \
	(__b == (typeof(__b))-1 && __a == __tmin);			\
})

#define check_add_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_add_overflow(a, b, d),			\
			__unsigned_add_overflow(a, b, d))

#define check_sub_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_sub_overflow(a, b, d),			\
			__unsigned_sub_overflow(a, b, d))

#define check_mul_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_mul_overflow(a, b, d),			\
			__unsigned_mul_overflow(a, b, d))
static inline __must_check size_t __ab_c_size(size_t n, size_t size, size_t c)
{
	size_t bytes;

	if (check_mul_overflow(n, size, &bytes))
		return SIZE_MAX;
	if (check_add_overflow(bytes, c, &bytes))
		return SIZE_MAX;

	return bytes;
}
#define struct_size(p, member, n)					\
	__ab_c_size(n,							\
		    sizeof(*(p)->member) + __must_be_array((p)->member),\
		    sizeof(*(p)))
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,10,17)
bool cfg80211_does_bw_fit_range(const struct ieee80211_freq_range *freq_range,
				u32 center_freq_khz, u32 bw_khz);
static bool wiphy_freq_limits_valid_chan(struct wiphy *wiphy,
					 struct ieee80211_freq_range *freq_limits,
					 unsigned int n_freq_limits,
					 struct ieee80211_channel *chan)
{
	u32 bw = MHZ_TO_KHZ(20);
	int i;

	for (i = 0; i < n_freq_limits; i++) {
		struct ieee80211_freq_range *limit = &freq_limits[i];

		if (cfg80211_does_bw_fit_range(limit,
					       MHZ_TO_KHZ(chan->center_freq),
					       bw))
			return true;
	}

	return false;
}
static void wiphy_freq_limits_apply(struct wiphy *wiphy,
				    struct ieee80211_freq_range *freq_limits,
				    unsigned int n_freq_limits)
{
	enum nl80211_band band;
	int i;

	if (WARN_ON(!n_freq_limits))
		return;

	for (band = 0; band < 3; band++) {
		struct ieee80211_supported_band *sband = wiphy->bands[band];

		if (!sband)
			continue;

		for (i = 0; i < sband->n_channels; i++) {
			struct ieee80211_channel *chan = &sband->channels[i];

			if (chan->flags & IEEE80211_CHAN_DISABLED)
				continue;

			if (!wiphy_freq_limits_valid_chan(wiphy, freq_limits,
							  n_freq_limits,
							  chan)) {
				pr_debug("Disabling freq %d MHz as it's out of OF limits\n",
					 chan->center_freq);
				chan->flags |= IEEE80211_CHAN_DISABLED;
			}
		}
	}
}
void wiphy_read_of_freq_limits(struct wiphy *wiphy);
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,13,11)
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
}
#endif