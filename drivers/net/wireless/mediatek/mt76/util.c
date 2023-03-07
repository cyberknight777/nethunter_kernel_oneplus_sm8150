/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/module.h>
#include "mt76.h"

bool __mt76_poll(struct mt76_dev *dev, u32 offset, u32 mask, u32 val,
		 int timeout)
{
	u32 cur;

	timeout /= 10;
	do {
		cur = dev->bus->rr(dev, offset) & mask;
		if (cur == val)
			return true;

		udelay(10);
	} while (timeout-- > 0);

	return false;
}
EXPORT_SYMBOL_GPL(__mt76_poll);

bool __mt76_poll_msec(struct mt76_dev *dev, u32 offset, u32 mask, u32 val,
		      int timeout)
{
	u32 cur;

	timeout /= 10;
	do {
		cur = dev->bus->rr(dev, offset) & mask;
		if (cur == val)
			return true;

		usleep_range(10000, 20000);
	} while (timeout-- > 0);

	return false;
}
EXPORT_SYMBOL_GPL(__mt76_poll_msec);

int mt76_wcid_alloc(unsigned long *mask, int size)
{
	int i, idx = 0, cur;

	for (i = 0; i < size / BITS_PER_LONG; i++) {
		idx = ffs(~mask[i]);
		if (!idx)
			continue;

		idx--;
		cur = i * BITS_PER_LONG + idx;
		if (cur >= size)
			break;

		mask[i] |= BIT(idx);
		return cur;
	}

	return -1;
}
EXPORT_SYMBOL_GPL(mt76_wcid_alloc);

MODULE_LICENSE("Dual BSD/GPL");

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,14)
int __skb_pad(struct sk_buff *skb, int pad, bool free_on_error)
{
	int err;
	int ntail;

	/* If the skbuff is non linear tailroom is always zero.. */
	if (!skb_cloned(skb) && skb_tailroom(skb) >= pad) {
		memset(skb->data+skb->len, 0, pad);
		return 0;
	}

	ntail = skb->data_len + pad - (skb->end - skb->tail);
	if (likely(skb_cloned(skb) || ntail > 0)) {
		err = pskb_expand_head(skb, 0, ntail, GFP_ATOMIC);
		if (unlikely(err))
			goto free_skb;
	}

	/* FIXME: The use of this function with non-linear skb's really needs
	 * to be audited.
	 */
	err = skb_linearize(skb);
	if (unlikely(err))
		goto free_skb;

	memset(skb->data + skb->len, 0, pad);
	return 0;

free_skb:
	if (free_on_error)
		kfree_skb(skb);
	return err;
}
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,10,17)
bool cfg80211_does_bw_fit_range(const struct ieee80211_freq_range *freq_range,
				u32 center_freq_khz, u32 bw_khz)
{
	u32 start_freq_khz, end_freq_khz;

	start_freq_khz = center_freq_khz - (bw_khz / 2);
	end_freq_khz = center_freq_khz + (bw_khz / 2);

	if (start_freq_khz >= freq_range->start_freq_khz &&
	    end_freq_khz <= freq_range->end_freq_khz)
		return true;

	return false;
}
void wiphy_read_of_freq_limits(struct wiphy *wiphy)
{
	struct device *dev = wiphy_dev(wiphy);
	struct device_node *np;
	struct property *prop;
	struct ieee80211_freq_range *freq_limits;
	unsigned int n_freq_limits;
	const __be32 *p;
	int len, i;
	int err = 0;

	if (!dev)
		return;
	np = dev_of_node(dev);
	if (!np)
		return;

	prop = of_find_property(np, "ieee80211-freq-limit", &len);
	if (!prop)
		return;

	if (!len || len % sizeof(u32) || len / sizeof(u32) % 2) {
		dev_err(dev, "ieee80211-freq-limit wrong format");
		return;
	}
	n_freq_limits = len / sizeof(u32) / 2;

	freq_limits = kcalloc(n_freq_limits, sizeof(*freq_limits), GFP_KERNEL);
	if (!freq_limits) {
		err = -ENOMEM;
		goto out_kfree;
	}

	p = NULL;
	for (i = 0; i < n_freq_limits; i++) {
		struct ieee80211_freq_range *limit = &freq_limits[i];

		p = of_prop_next_u32(prop, p, &limit->start_freq_khz);
		if (!p) {
			err = -EINVAL;
			goto out_kfree;
		}

		p = of_prop_next_u32(prop, p, &limit->end_freq_khz);
		if (!p) {
			err = -EINVAL;
			goto out_kfree;
		}

		if (!limit->start_freq_khz ||
		    !limit->end_freq_khz ||
		    limit->start_freq_khz >= limit->end_freq_khz) {
			err = -EINVAL;
			goto out_kfree;
		}
	}

	wiphy_freq_limits_apply(wiphy, freq_limits, n_freq_limits);

out_kfree:
	kfree(freq_limits);
	if (err)
		dev_err(dev, "Failed to get limits: %d\n", err);
}
#endif