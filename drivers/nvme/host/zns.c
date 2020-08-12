// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */

#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#include "nvme.h"

int nvme_revalidate_zones(struct nvme_ns *ns)
{
	struct request_queue *q = ns->queue;
	int ret;

	ret = blk_revalidate_disk_zones(ns->disk, NULL);
	if (!ret)
		blk_queue_max_zone_append_sectors(q, ns->ctrl->max_zone_append);
	return ret;
}

static int nvme_set_max_append(struct nvme_ctrl *ctrl)
{
	struct nvme_command c = { };
	struct nvme_id_ctrl_zns *id;
	int status;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id)
		return -ENOMEM;

	c.identify.opcode = nvme_admin_identify;
	c.identify.cns = NVME_ID_CNS_CS_CTRL;
	c.identify.csi = NVME_CSI_ZNS;

	status = nvme_submit_sync_cmd(ctrl->admin_q, &c, id, sizeof(*id));
	if (status) {
		kfree(id);
		return status;
	}

	if (id->zasl)
		ctrl->max_zone_append = 1 << (id->zasl + 3);
	else
		ctrl->max_zone_append = ctrl->max_hw_sectors;

	kfree(id);
	return 0;
}

int nvme_update_zone_info(struct nvme_ns *ns, unsigned lbaf)
{
	/* struct nvme_effects_log *log = ns->head->effects; */
	struct request_queue *q = ns->queue;
	struct nvme_command c = { };
	struct nvme_id_ns_zns *id;
	int status;

	/* Driver requires zone append support */
	/* if (!(le32_to_cpu(log->iocs[nvme_cmd_zone_append]) & */
			/* NVME_CMD_EFFECTS_CSUPP)) { */
		/* dev_warn(ns->ctrl->device, */
			/* "append not supported for zoned namespace:%d\n", */
			/* ns->head->ns_id); */
		/* return -EINVAL; */
	/* } */

	/* Lazily query controller append limit for the first zoned namespace */
	if (!ns->ctrl->max_zone_append) {
		status = nvme_set_max_append(ns->ctrl);
		if (status)
			return status;
	}

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id)
		return -ENOMEM;

	c.identify.opcode = nvme_admin_identify;
	c.identify.nsid = cpu_to_le32(ns->head->ns_id);
	c.identify.cns = NVME_ID_CNS_CS_NS;
	c.identify.csi = NVME_CSI_ZNS;

	status = nvme_submit_sync_cmd(ns->ctrl->admin_q, &c, id, sizeof(*id));
	if (status)
		goto free_data;

	/*
	 * We currently do not handle devices requiring any of the zoned
	 * operation characteristics.
	 */
	/* if (id->zoc) { */
		/* dev_warn(ns->ctrl->device, */
			/* "zone operations:%x not supported for namespace:%u\n", */
			/* le16_to_cpu(id->zoc), ns->head->ns_id); */
		/* status = -EINVAL; */
		/* goto free_data; */
	/* } */

	ns->zone_cap_lb = le64_to_cpu(id->lbafe[lbaf].zsze);
	ns->zone_sz_lb = 1 << get_count_order(ns->zone_cap_lb);
	ns->zsze_cap_diff = ns->zone_sz_lb - ns->zone_cap_lb;

	ns->zsze = nvme_lba_to_sect(ns, le64_to_cpu(id->lbafe[lbaf].zsze));
	ns->zsze_po2 = 1 << get_count_order(ns->zsze);

	ns->is_zmap = true;
	if (ns->zsze == ns->zsze_po2)
		ns->is_zmap = false;

	if (!is_power_of_2(ns->zsze_po2)) {
		dev_warn(ns->ctrl->device,
			"invalid zone size:%llu/%llu for namespace:%u\n",
			ns->zsze, ns->zsze_po2, ns->head->ns_id);
		status = -EINVAL;
		goto free_data;
	}
	ns->ozcs = le16_to_cpu(id->ozcs);
	ns->zrwas = le32_to_cpu(id->zrwas) << (ns->lba_shift - 9);
	ns->zrwafg = (le32_to_cpu(id->zrwafg));
	ns->zrwacap = le32_to_cpu(id->zrwacap);
	ns->numzrwa = le32_to_cpu(id->numzrwa);

	q->limits.zoned = BLK_ZONED_HM;
	blk_queue_flag_set(QUEUE_FLAG_ZONE_RESETALL, q);
	blk_queue_max_open_zones(q, le32_to_cpu(id->mor) + 1);
	blk_queue_max_active_zones(q, le32_to_cpu(id->mar) + 1);
	blk_queue_required_elevator_features(ns->queue, ELEVATOR_F_ZBD_SEQ_WRITE);
free_data:
	kfree(id);
	return status;
}

static void *nvme_zns_alloc_report_buffer(struct nvme_ns *ns,
					  unsigned int nr_zones, size_t *buflen)
{
	struct request_queue *q = ns->disk->queue;
	size_t bufsize;
	void *buf;

	const size_t min_bufsize = sizeof(struct nvme_zone_report) +
				   sizeof(struct nvme_zone_descriptor);

	nr_zones = min_t(unsigned int, nr_zones,
			 get_capacity(ns->disk) >> ilog2(ns->zsze));

	bufsize = sizeof(struct nvme_zone_report) +
		nr_zones * sizeof(struct nvme_zone_descriptor);
	bufsize = min_t(size_t, bufsize,
			queue_max_hw_sectors(q) << SECTOR_SHIFT);
	bufsize = min_t(size_t, bufsize, queue_max_segments(q) << PAGE_SHIFT);

	while (bufsize >= min_bufsize) {
		buf = __vmalloc(bufsize, GFP_KERNEL | __GFP_NORETRY);
		if (buf) {
			*buflen = bufsize;
			return buf;
		}
		bufsize >>= 1;
	}
	return NULL;
}

static int nvme_zone_parse_entry(struct nvme_ns *ns,
				 struct nvme_zone_descriptor *entry,
				 unsigned int idx, report_zones_cb cb,
				 void *data, u64 off)
{
	struct blk_zone zone = { };

	if ((entry->zt & 0xf) != NVME_ZONE_TYPE_SEQWRITE_REQ) {
		dev_err(ns->ctrl->device, "invalid zone type %#x\n",
				entry->zt);
		return -EINVAL;
	}

	/* Device PO2 zones sizes */
	if (!ns->is_zmap) {
		zone.start = nvme_lba_to_sect(ns, le64_to_cpu(entry->zslba));
		zone.wp = nvme_lba_to_sect(ns, le64_to_cpu(entry->wp));
		zone.capacity = nvme_lba_to_sect(ns, le64_to_cpu(entry->zcap));
		goto out;
	}

	/* Device !PO2 zones sizes */
	zone.start = nvme_lba_to_sect(ns, le64_to_cpu(entry->zslba + off));
	zone.wp = nvme_lba_to_sect(ns, le64_to_cpu(entry->wp + off));
	zone.capacity = nvme_lba_to_sect(ns, le64_to_cpu(ns->zone_cap_lb));

out:
	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = entry->zs >> 4;
	zone.len = ns->zsze_po2;

	return cb(&zone, idx, data);
}

inline sector_t adjust_po2_sector(struct nvme_ns *ns, sector_t sector)
{
	sector_t res;
	u64 zone = sector;

	do_div(zone, ns->zsze_po2);
	res = sector - zone * (ns->zsze_po2 - ns->zsze);
	return res;
}

static int nvme_ns_report_zones(struct nvme_ns *ns, sector_t sector,
			unsigned int nr_zones, report_zones_cb cb, void *data)
{
	struct nvme_zone_report *report;
	struct nvme_command c = { };
	int ret, zone_idx = 0;
	unsigned int nz, i;
	u64 off = 0;
	size_t buflen;
	/* Kanchan: workaround only for po2-emulation, find clean way */
	sector_t sector2 = 0;

	report = nvme_zns_alloc_report_buffer(ns, nr_zones, &buflen);
	if (!report)
		return -ENOMEM;

	c.zmr.opcode = nvme_cmd_zone_mgmt_recv;
	c.zmr.nsid = cpu_to_le32(ns->head->ns_id);
	c.zmr.numd = cpu_to_le32(nvme_bytes_to_numd(buflen));
	c.zmr.zra = NVME_ZRA_ZONE_REPORT;
	c.zmr.zrasf = NVME_ZRASF_ZONE_REPORT_ALL;
	c.zmr.pr = NVME_REPORT_ZONE_PARTIAL;

	/*
	 * sector is for po2 address space, bring that down to actual
	 * address-space
	 */
	sector2 = adjust_po2_sector(ns, sector);
	//sector &= ~(ns->zsze_po2 - 1);
	while (zone_idx < nr_zones && sector < get_capacity(ns->disk)) {
		memset(report, 0, buflen);

		c.zmr.slba = cpu_to_le64(nvme_sect_to_lba(ns, sector2));
		ret = nvme_submit_sync_cmd(ns->queue, &c, report, buflen);
		if (ret) {
			if (ret > 0)
				ret = -EIO;
			goto out_free;
		}

		nz = min((unsigned int)le64_to_cpu(report->nr_zones), nr_zones);
		if (!nz)
			break;

		for (i = 0; i < nz && zone_idx < nr_zones; i++) {
			ret = nvme_zone_parse_entry(ns, &report->entries[i],
						    zone_idx, cb, data, off);
			if (ret)
				goto out_free;
			zone_idx++;
			off += ns->zsze_cap_diff;
		}

		sector2 += ns->zsze * nz;
		sector += ns->zsze_po2 * nz;
	}

	if (zone_idx > 0)
		ret = zone_idx;
	else
		ret = -EINVAL;
out_free:
	kvfree(report);
	return ret;
}

int nvme_report_zones(struct gendisk *disk, sector_t sector,
		      unsigned int nr_zones, report_zones_cb cb, void *data)
{
	struct nvme_ns_head *head = NULL;
	struct nvme_ns *ns;
	int srcu_idx, ret;

	ns = nvme_get_ns_from_disk(disk, &head, &srcu_idx);
	if (unlikely(!ns))
		return -EWOULDBLOCK;

	if (ns->head->ids.csi == NVME_CSI_ZNS)
		ret = nvme_ns_report_zones(ns, sector, nr_zones, cb, data);
	else
		ret = -EINVAL;
	nvme_put_ns_from_disk(head, srcu_idx);

	return ret;
}

blk_status_t nvme_setup_zone_mgmt_send(struct nvme_ns *ns, struct request *req,
		struct nvme_command *c, enum nvme_zone_mgmt_action action)
{
	c->zms.opcode = nvme_cmd_zone_mgmt_send;
	c->zms.nsid = cpu_to_le32(ns->head->ns_id);
	c->zms.zsa = action;

	if (req_op(req) == REQ_OP_ZONE_RESET_ALL)
		c->zms.attributes |= NVME_CMD_ZMS_SELECT_ALL;
	else if ((req->bio)->bi_opf & REQ_ZONE_ZRWA) {
		if (ns->ozcs & NVME_ID_NS_ZNS_OZCS_ZRWASUP)
			c->zms.attributes |= NVME_CMD_ZMS_ZRWAA;
		else {
			dev_warn(ns->ctrl->device, "ZRWA is not supported\n");
			return BLK_STS_NOTSUPP;
		}
	} else if (req_op(req) ==  REQ_OP_ZONE_ZRWA_FLUSH &&
			(!(ns->zrwacap & NVME_ZNS_ZRWA_EXPFLUSHSUP))) {
		dev_warn(ns->ctrl->device,
				"ZRWA explicit commit is not supported\n");
		return BLK_STS_NOTSUPP;
	}

#ifdef CONFIG_BLK_DEV_ZONED
	if (ns->is_zmap)
		c->zms.slba = cpu_to_le64(nvme_zns_slba2po2(
				nvme_sect_to_lba(ns, blk_rq_pos(req)), ns, 0));
	else
		c->zms.slba = cpu_to_le64(nvme_sect_to_lba(ns, blk_rq_pos(req)));
#else
	c->zms.slba = cpu_to_le64(nvme_sect_to_lba(ns, blk_rq_pos(req)));
#endif

	return BLK_STS_OK;
}
