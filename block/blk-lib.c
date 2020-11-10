// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to generic helpers functions
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>

#include "blk.h"

struct bio *blk_next_bio(struct bio *bio, unsigned int nr_pages, gfp_t gfp)
{
	struct bio *new = bio_alloc(gfp, nr_pages);

	if (bio) {
		bio_chain(bio, new);
		submit_bio(bio);
	}

	return new;
}

int __blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, int flags,
		struct bio **biop)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct bio *bio = *biop;
	unsigned int op;
	sector_t bs_mask, part_offset = 0;

	if (!q)
		return -ENXIO;

	if (bdev_read_only(bdev))
		return -EPERM;

	if (flags & BLKDEV_DISCARD_SECURE) {
		if (!blk_queue_secure_erase(q))
			return -EOPNOTSUPP;
		op = REQ_OP_SECURE_ERASE;
	} else {
		if (!blk_queue_discard(q))
			return -EOPNOTSUPP;
		op = REQ_OP_DISCARD;
	}

	/* In case the discard granularity isn't set by buggy device driver */
	if (WARN_ON_ONCE(!q->limits.discard_granularity)) {
		char dev_name[BDEVNAME_SIZE];

		bdevname(bdev, dev_name);
		pr_err_ratelimited("%s: Error: discard_granularity is 0.\n", dev_name);
		return -EOPNOTSUPP;
	}

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	if (!nr_sects)
		return -EINVAL;

	/* In case the discard request is in a partition */
	if (bdev_is_partition(bdev))
		part_offset = bdev->bd_part->start_sect;

	while (nr_sects) {
		sector_t granularity_aligned_lba, req_sects;
		sector_t sector_mapped = sector + part_offset;

		granularity_aligned_lba = round_up(sector_mapped,
				q->limits.discard_granularity >> SECTOR_SHIFT);

		/*
		 * Check whether the discard bio starts at a discard_granularity
		 * aligned LBA,
		 * - If no: set (granularity_aligned_lba - sector_mapped) to
		 *   bi_size of the first split bio, then the second bio will
		 *   start at a discard_granularity aligned LBA on the device.
		 * - If yes: use bio_aligned_discard_max_sectors() as the max
		 *   possible bi_size of the first split bio. Then when this bio
		 *   is split in device drive, the split ones are very probably
		 *   to be aligned to discard_granularity of the device's queue.
		 */
		if (granularity_aligned_lba == sector_mapped)
			req_sects = min_t(sector_t, nr_sects,
					  bio_aligned_discard_max_sectors(q));
		else
			req_sects = min_t(sector_t, nr_sects,
					  granularity_aligned_lba - sector_mapped);

		WARN_ON_ONCE((req_sects << 9) > UINT_MAX);

		bio = blk_next_bio(bio, 0, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio_set_dev(bio, bdev);
		bio_set_op_attrs(bio, op, 0);

		bio->bi_iter.bi_size = req_sects << 9;
		sector += req_sects;
		nr_sects -= req_sects;

		/*
		 * We can loop for a long time in here, if someone does
		 * full device discards (like mkfs). Be nice and allow
		 * us to schedule out to avoid softlocking if preempt
		 * is disabled.
		 */
		cond_resched();
	}

	*biop = bio;
	return 0;
}
EXPORT_SYMBOL(__blkdev_issue_discard);

/**
 * blkdev_issue_discard - queue a discard
 * @bdev:	blockdev to issue discard for
 * @sector:	start sector
 * @nr_sects:	number of sectors to discard
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:	BLKDEV_DISCARD_* flags to control behaviour
 *
 * Description:
 *    Issue a discard request for the sectors in question.
 */
int blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, unsigned long flags)
{
	struct bio *bio = NULL;
	struct blk_plug plug;
	int ret;

	blk_start_plug(&plug);
	ret = __blkdev_issue_discard(bdev, sector, nr_sects, gfp_mask, flags,
			&bio);
	if (!ret && bio) {
		ret = submit_bio_wait(bio);
		if (ret == -EOPNOTSUPP)
			ret = 0;
		bio_put(bio);
	}
	blk_finish_plug(&plug);

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_discard);

int __blkdev_issue_copy(struct block_device *bdev, sector_t dest,
		sector_t nr_srcs, struct range_entry *rlist, gfp_t gfp_mask,
		int flags, struct bio **biop)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct bio *bio = *biop;
	struct range_entry *payload;
	unsigned int op;
	sector_t bs_mask;
	sector_t src_sects, len = 0, copy_len = 0, cdest, total_len = 0;
	int i, ret, total_size, max_copy_len, max_nr_srcs, copied_srcs;

	if (!q)
		return -ENXIO;

	if (bdev_read_only(bdev))
		return -EPERM;

	if (!blk_queue_copy(q))
		return -EOPNOTSUPP;
	op = REQ_OP_COPY;

	max_nr_srcs = q->limits.max_copy_nr_ranges;
	max_copy_len = q->limits.max_copy_sectors;

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if (dest & bs_mask)
		return -EINVAL;

	if (!nr_srcs)
		return -EINVAL;

	copied_srcs = 0;
	cdest = dest;

	while (copied_srcs < nr_srcs) {

		/* Adding one extra range-entry (first) for book keeping */
		payload = kmalloc_array(max_nr_srcs + 1, sizeof(*rlist),
				GFP_ATOMIC | __GFP_NOWARN);
		if (!payload)
			return -ENOMEM;

		bio = blk_next_bio(bio, 1, gfp_mask);
		if (!bio)
			return -ENOMEM; //TBD needed ?

		bio->bi_iter.bi_sector = cdest;
		bio_set_dev(bio, bdev);
		bio_set_op_attrs(bio, op, REQ_NOMERGE);

		for (i = 1, copy_len = 0; copied_srcs < nr_srcs &&
				i <= max_nr_srcs; i++, copied_srcs++) {
			/*  copy payload provided are in bytes */
			src_sects = rlist[copied_srcs].src;
			if (src_sects & bs_mask)
				return -EINVAL;
			src_sects = src_sects >> SECTOR_SHIFT;

			if (len & bs_mask)
				return -EINVAL;
			len = rlist[copied_srcs].len >> SECTOR_SHIFT;
			if (len > q->limits.max_copy_range_sectors)
				return -EINVAL;

			if (copy_len + len > max_copy_len)
				break;

			copy_len += len;
			total_len += len;

			WARN_ON_ONCE((src_sects << 9) > UINT_MAX);

			payload[i].src = src_sects;
			payload[i].len = len;
			cdest += len;
		}

		/* storing # of source ranges */
		payload[0].len = i - 1;
		/* storing copy len so far */
		bio->bi_copy_ranges = total_len;

		total_size = (max_nr_srcs + 1) * sizeof(*rlist);
		ret = bio_add_page(bio, virt_to_page(payload), total_size,
						   offset_in_page(payload));
		if (ret != total_size) {
			kfree(payload);
			return -ENOMEM;
		}
	}

	*biop = bio;
	return 0;
}
EXPORT_SYMBOL(__blkdev_issue_copy);

/**
 * blkdev_issue_copy - queue a copy
 * @bdev:       blockdev to issue copy for
 * @dest:	dest sector
 * @nr_srcs:	number of source ranges to copy
 * @rlist:	list of range entries
 * @gfp_mask:   memory allocation flags (for bio_alloc)
 * @flags:      BLKDEV_COPY_* flags to control behaviour	//TODO
 *
 * Description:
 *    Issue a copy request for dest sector with source in rlist
 */
int blkdev_issue_copy(struct block_device *bdev, sector_t dest,
		int nr_srcs, struct range_entry *rlist,
		gfp_t gfp_mask, unsigned long flags)
{
	struct bio *bio = NULL;
	int ret;

	ret = __blkdev_issue_copy(bdev, dest, nr_srcs, rlist, gfp_mask, flags,
			&bio);
	if (!ret && bio) {
		ret = submit_bio_wait(bio);
		if (ret == -EOPNOTSUPP)
			ret = 0;

		kfree(page_address(bio_first_bvec_all(bio)->bv_page) +
				bio_first_bvec_all(bio)->bv_offset);
		bio_put(bio);
	}

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_copy);

/**
 * __blkdev_issue_write_same - generate number of bios with same page
 * @bdev:	target blockdev
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @page:	page containing data to write
 * @biop:	pointer to anchor bio
 *
 * Description:
 *  Generate and issue number of bios(REQ_OP_WRITE_SAME) with same page.
 */
static int __blkdev_issue_write_same(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct page *page,
		struct bio **biop)
{
	struct request_queue *q = bdev_get_queue(bdev);
	unsigned int max_write_same_sectors;
	struct bio *bio = *biop;
	sector_t bs_mask;

	if (!q)
		return -ENXIO;

	if (bdev_read_only(bdev))
		return -EPERM;

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	if (!bdev_write_same(bdev))
		return -EOPNOTSUPP;

	/* Ensure that max_write_same_sectors doesn't overflow bi_size */
	max_write_same_sectors = bio_allowed_max_sectors(q);

	while (nr_sects) {
		bio = blk_next_bio(bio, 1, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio_set_dev(bio, bdev);
		bio->bi_vcnt = 1;
		bio->bi_io_vec->bv_page = page;
		bio->bi_io_vec->bv_offset = 0;
		bio->bi_io_vec->bv_len = bdev_logical_block_size(bdev);
		bio_set_op_attrs(bio, REQ_OP_WRITE_SAME, 0);

		if (nr_sects > max_write_same_sectors) {
			bio->bi_iter.bi_size = max_write_same_sectors << 9;
			nr_sects -= max_write_same_sectors;
			sector += max_write_same_sectors;
		} else {
			bio->bi_iter.bi_size = nr_sects << 9;
			nr_sects = 0;
		}
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/**
 * blkdev_issue_write_same - queue a write same operation
 * @bdev:	target blockdev
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @page:	page containing data
 *
 * Description:
 *    Issue a write same request for the sectors in question.
 */
int blkdev_issue_write_same(struct block_device *bdev, sector_t sector,
				sector_t nr_sects, gfp_t gfp_mask,
				struct page *page)
{
	struct bio *bio = NULL;
	struct blk_plug plug;
	int ret;

	blk_start_plug(&plug);
	ret = __blkdev_issue_write_same(bdev, sector, nr_sects, gfp_mask, page,
			&bio);
	if (ret == 0 && bio) {
		ret = submit_bio_wait(bio);
		bio_put(bio);
	}
	blk_finish_plug(&plug);
	return ret;
}
EXPORT_SYMBOL(blkdev_issue_write_same);

static int __blkdev_issue_write_zeroes(struct block_device *bdev,
		sector_t sector, sector_t nr_sects, gfp_t gfp_mask,
		struct bio **biop, unsigned flags)
{
	struct bio *bio = *biop;
	unsigned int max_write_zeroes_sectors;
	struct request_queue *q = bdev_get_queue(bdev);

	if (!q)
		return -ENXIO;

	if (bdev_read_only(bdev))
		return -EPERM;

	/* Ensure that max_write_zeroes_sectors doesn't overflow bi_size */
	max_write_zeroes_sectors = bdev_write_zeroes_sectors(bdev);

	if (max_write_zeroes_sectors == 0)
		return -EOPNOTSUPP;

	while (nr_sects) {
		bio = blk_next_bio(bio, 0, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio_set_dev(bio, bdev);
		bio->bi_opf = REQ_OP_WRITE_ZEROES;
		if (flags & BLKDEV_ZERO_NOUNMAP)
			bio->bi_opf |= REQ_NOUNMAP;

		if (nr_sects > max_write_zeroes_sectors) {
			bio->bi_iter.bi_size = max_write_zeroes_sectors << 9;
			nr_sects -= max_write_zeroes_sectors;
			sector += max_write_zeroes_sectors;
		} else {
			bio->bi_iter.bi_size = nr_sects << 9;
			nr_sects = 0;
		}
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/*
 * Convert a number of 512B sectors to a number of pages.
 * The result is limited to a number of pages that can fit into a BIO.
 * Also make sure that the result is always at least 1 (page) for the cases
 * where nr_sects is lower than the number of sectors in a page.
 */
static unsigned int __blkdev_sectors_to_bio_pages(sector_t nr_sects)
{
	sector_t pages = DIV_ROUND_UP_SECTOR_T(nr_sects, PAGE_SIZE / 512);

	return min(pages, (sector_t)BIO_MAX_PAGES);
}

static int __blkdev_issue_zero_pages(struct block_device *bdev,
		sector_t sector, sector_t nr_sects, gfp_t gfp_mask,
		struct bio **biop)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct bio *bio = *biop;
	int bi_size = 0;
	unsigned int sz;

	if (!q)
		return -ENXIO;

	if (bdev_read_only(bdev))
		return -EPERM;

	while (nr_sects != 0) {
		bio = blk_next_bio(bio, __blkdev_sectors_to_bio_pages(nr_sects),
				   gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio_set_dev(bio, bdev);
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

		while (nr_sects != 0) {
			sz = min((sector_t) PAGE_SIZE, nr_sects << 9);
			bi_size = bio_add_page(bio, ZERO_PAGE(0), sz, 0);
			nr_sects -= bi_size >> 9;
			sector += bi_size >> 9;
			if (bi_size < sz)
				break;
		}
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/**
 * __blkdev_issue_zeroout - generate number of zero filed write bios
 * @bdev:	blockdev to issue
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @biop:	pointer to anchor bio
 * @flags:	controls detailed behavior
 *
 * Description:
 *  Zero-fill a block range, either using hardware offload or by explicitly
 *  writing zeroes to the device.
 *
 *  If a device is using logical block provisioning, the underlying space will
 *  not be released if %flags contains BLKDEV_ZERO_NOUNMAP.
 *
 *  If %flags contains BLKDEV_ZERO_NOFALLBACK, the function will return
 *  -EOPNOTSUPP if no explicit hardware offload for zeroing is provided.
 */
int __blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct bio **biop,
		unsigned flags)
{
	int ret;
	sector_t bs_mask;

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	ret = __blkdev_issue_write_zeroes(bdev, sector, nr_sects, gfp_mask,
			biop, flags);
	if (ret != -EOPNOTSUPP || (flags & BLKDEV_ZERO_NOFALLBACK))
		return ret;

	return __blkdev_issue_zero_pages(bdev, sector, nr_sects, gfp_mask,
					 biop);
}
EXPORT_SYMBOL(__blkdev_issue_zeroout);

/**
 * blkdev_issue_zeroout - zero-fill a block range
 * @bdev:	blockdev to write
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:	controls detailed behavior
 *
 * Description:
 *  Zero-fill a block range, either using hardware offload or by explicitly
 *  writing zeroes to the device.  See __blkdev_issue_zeroout() for the
 *  valid values for %flags.
 */
int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, unsigned flags)
{
	int ret = 0;
	sector_t bs_mask;
	struct bio *bio;
	struct blk_plug plug;
	bool try_write_zeroes = !!bdev_write_zeroes_sectors(bdev);

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

retry:
	bio = NULL;
	blk_start_plug(&plug);
	if (try_write_zeroes) {
		ret = __blkdev_issue_write_zeroes(bdev, sector, nr_sects,
						  gfp_mask, &bio, flags);
	} else if (!(flags & BLKDEV_ZERO_NOFALLBACK)) {
		ret = __blkdev_issue_zero_pages(bdev, sector, nr_sects,
						gfp_mask, &bio);
	} else {
		/* No zeroing offload support */
		ret = -EOPNOTSUPP;
	}
	if (ret == 0 && bio) {
		ret = submit_bio_wait(bio);
		bio_put(bio);
	}
	blk_finish_plug(&plug);
	if (ret && try_write_zeroes) {
		if (!(flags & BLKDEV_ZERO_NOFALLBACK)) {
			try_write_zeroes = false;
			goto retry;
		}
		if (!bdev_write_zeroes_sectors(bdev)) {
			/*
			 * Zeroing offload support was indicated, but the
			 * device reported ILLEGAL REQUEST (for some devices
			 * there is no non-destructive way to verify whether
			 * WRITE ZEROES is actually supported).
			 */
			ret = -EOPNOTSUPP;
		}
	}

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_zeroout);
