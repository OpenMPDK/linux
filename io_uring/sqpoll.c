// SPDX-License-Identifier: GPL-2.0
/*
 * Contains the core associated with submission side polling of the SQ
 * ring, offloading submissions from the application to a kernel thread.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/io_uring.h>
#include <linux/time.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "sqpoll.h"
#include "../kernel/sched/sched.h"
#include <linux/kfifo.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/spinlock.h>
#include <linux/limits.h>

#define IORING_SQPOLL_CAP_ENTRIES_VALUE 8

static struct io_sq_data __percpu **percpu_sqd;
static spinlock_t cpu_util_lock;
static struct kfifo busy_fifo;
static spinlock_t busy_fifo_lock;
static spinlock_t find_cpu;
static unsigned long merge_time;

#define CTX_FIFO_MAX			32
#define SCHED_CHECK_TIMEOUT		10*HZ
#define CTX_MERGE_TIMEOUT		30*HZ
#define TASK_UTIL_THRESHOLD_LOW		256
#define TASK_UTIL_THRESHOLD_HIGH	(TASK_UTIL_THRESHOLD_LOW*3)
//#define TASK_IDLE_THRESHOLD_MAX		LLONG_MAX
#define INVALID_CPU_ID			-1

#define IOURING_DEBUG 1

#ifdef IOURING_DEBUG
#define IOURING_DBG(fmt...)	pr_info(fmt)
#else 
#define IOURING_DBG(fmt...)	do { } while(0)
#endif /* end of IOURING_DEBUG */
#define IOURING_INFO(fmt...)	pr_info(fmt)
#define IOURING_WARN(fmt...)	pr_warn(fmt)
#define IOURING_ERR(fmt...)	pr_err(fmt)
#define IOURING_ALERT(fmt...)	pr_alert(fmt)

enum {
	IO_SQ_THREAD_SHOULD_STOP = 0,
	IO_SQ_THREAD_SHOULD_PARK,
};

enum SQ_MIGRATION_DIR {
        MIGRATION_IN,
        MIGRATION_OUT,
        MIGRATION_NONE
};

static void show_kfifo(void)
{
	struct io_ring_ctx * ctx;
	struct io_ring_ctx * ctxs[CTX_FIFO_MAX];
	int len, res, index, number;

	len = kfifo_len(&busy_fifo);
	res = kfifo_out_peek(&busy_fifo, &ctxs, len);
	if (len != res) {
		IOURING_WARN("kfifo_out_peek return:%d, kfifo len:%d \n", res, len);
		return;
	}

	number = len / sizeof(struct io_ring_ctx *);
	IOURING_INFO("@@ %d ctxs in kfifo: <id, schedule_state, sq> \n", number);
	for (index = 0; index < number; index++) {
		ctx = ctxs[index];
		BUG_ON(ctx == NULL);
		IOURING_INFO("            <%d,  %d, %d> \n", ctx->id, ctx->schedule_state,
					 ctx->sq_data->sq_cpu);
	}
}

static void show_sq_and_ctx(void)
{
#ifdef IOURING_DEBUG
	int cpu;
	struct task_struct *sq_thread;
	struct io_sq_data  *sqd;
	struct io_ring_ctx *ctx, *tmp_ctx;

	sqd = NULL;
	sq_thread = NULL;
	ctx = NULL;
	IOURING_INFO("\n\n################################################\n");
	IOURING_INFO("## sq    task_util    merge_state   ##\n");
	IOURING_INFO("ctx_list  : <id, schedule_state>\n");
	IOURING_INFO("merge_list: <id, schedule_state>\n");
	IOURING_INFO("sched_ctx : schedule_state: \n\n");
	for_each_online_cpu(cpu) {
		sqd = *per_cpu_ptr(percpu_sqd, cpu);
		if (list_empty_careful(&sqd->ctx_list) 
		   && list_empty_careful(&sqd->merge_list)
		   && (NULL == sqd->sched_ctx)) {
			continue;
		}
		sq_thread = sqd->thread;
		IOURING_INFO("## sq:%d, merge_state: %d ##\n", sqd->sq_cpu, sqd->merge_state); 

		IOURING_INFO("ctx_list  : ");
		list_for_each_entry_safe(ctx, tmp_ctx, &sqd->ctx_list, sqd_list) {
			IOURING_INFO("            <%d, %d> ", ctx->id, ctx->schedule_state);
		}

		IOURING_INFO("merge_list: ");
		list_for_each_entry_safe(ctx, tmp_ctx, &sqd->merge_list, sqd_merge_list) {
			IOURING_INFO("            <%d, %d> ", ctx->id, ctx->schedule_state);
		}

		if (NULL != sqd->sched_ctx) {
			IOURING_INFO("sched_ctx : %d, schedule_state:%d\n\n", \
				ctx->id, ctx->schedule_state);
		} else {
			IOURING_INFO("sched_ctx : NULL \n\n");
		}
	}
	show_kfifo();
	IOURING_INFO("################################################\n\n");
#endif
}

unsigned int find_idlest_cpu(void)
{
	unsigned long load, min_load = 1024;
	unsigned int id = INVALID_CPU_ID;
	int i;
	int idle_id = INVALID_CPU_ID;
	unsigned long _flags;

	spin_lock_irqsave(&cpu_util_lock, _flags);
	for_each_online_cpu(i) {
		struct task_struct *p = (*per_cpu_ptr(percpu_sqd, i))->thread;
		struct cfs_rq *cfs = task_cfs_rq(p);
		struct rq *rq = cfs->rq;

		if (rq->curr == rq->idle || !rq->nr_running) {
			if (INVALID_CPU_ID == idle_id) {
				idle_id = i;
				break;
			}
		} else {
			load = cfs->avg.load_avg;
			if (load < min_load) {
				min_load = load;
				id = i;
			}
		}
	}
	if (idle_id != INVALID_CPU_ID) 
		id = idle_id;
	else 
		id = (id == INVALID_CPU_ID ? 0:id);
	spin_unlock_irqrestore(&cpu_util_lock, _flags);
	
	return id;
}

unsigned int sq_thread_load(struct io_sq_data* sqd){
		unsigned long util_avg = sqd->thread->se.sq_avg.util_avg;
		// sqthread is busy
		if (util_avg > TASK_UTIL_THRESHOLD_HIGH)
			return -1;
		// sqthread is idle
		else if(util_avg < TASK_UTIL_THRESHOLD_LOW)
			return 1;
		return 0;
}

/*
* In order to keep workload balance among different sq threads,
* if task_util of a sq thead is greater than TASK_UTIL_THRESHOLD_HIGH, some of
* its ctx need to be migrate out.
* if task_util of a sq thead is less than TASK_UTIL_THRESHOLD_LOW, it can accept
* some ctx migrate in.
* Otherwise, the sq thread will keep unchange.
*/
enum SQ_MIGRATION_DIR  io_get_migration_dir(struct io_sq_data* sqd)
{
        int sq_load = sq_thread_load(sqd);
	if (sq_load == -1) {
		return MIGRATION_OUT;
	} else if (sq_load == 1) {
		return MIGRATION_IN;
	}
	return MIGRATION_NONE;
}

static bool fifo_check_full_and_put(struct kfifo* fifo, spinlock_t* fifo_lock,
                struct io_ring_ctx* ctx)
{
        unsigned long _flags;
        bool res = true;
        spin_lock_irqsave(fifo_lock, _flags);
        if(!kfifo_is_full(fifo))
                kfifo_in(fifo, &ctx, sizeof(struct io_ring_ctx*));
        else
                res = false;
        spin_unlock_irqrestore(fifo_lock, _flags);
        return res;
}

/* put a ctx in busy_fifo, not deleted from the ctx list yet.*/
static bool io_migrate_out(struct io_sq_data* sqd)
{
	struct io_ring_ctx *ctx;
	bool res = false;
	if (list_empty_careful(&sqd->ctx_list))
		return res;
	ctx = list_last_entry(&sqd->ctx_list, struct io_ring_ctx, sqd_list);
	if (ctx && ctx->schedule_state == CTX_SCHED_NONE) {
		res = fifo_check_full_and_put(&busy_fifo, &busy_fifo_lock, ctx);
		if (res) {
			ctx->schedule_state = CTX_SCHED_WAIT_TAKE;
			IOURING_INFO("sq %d puts ctx(%d) in kfifo success.\n", sqd->sq_cpu, ctx->id);
		} else 
			IOURING_WARN("sq %d puts ctx(%d) in kfifo failed.\n", sqd->sq_cpu, ctx->id);
	}
	return res;
}

static struct io_ring_ctx* fifo_check_empty_and_take(struct kfifo* fifo,
                spinlock_t* fifo_lock)
{
        unsigned long _flags;
        struct io_ring_ctx *ctx=NULL;
        int res;
        spin_lock_irqsave(fifo_lock, _flags);
        if(!kfifo_is_empty(fifo)){
                res = kfifo_out(fifo, &ctx, sizeof(struct io_ring_ctx*));
        }
        spin_unlock_irqrestore(fifo_lock, _flags);
        return ctx;
}

/*
* Take a ctx out of the fifo, not added to the ctx list yet.
*/
static bool io_migrate_in(struct io_sq_data* des_sqd)
{
	struct io_ring_ctx *ctx = NULL;
	struct io_sq_data  *src_sqd = NULL;
	bool put_back = false;
	bool result = false;
	int retry = 2;

	if (des_sqd->sched_ctx) {
		IOURING_WARN("sqd %d already has migration in ctx(%d)", \
				des_sqd->sq_cpu, des_sqd->sched_ctx->id);
		goto out;
	}

	ctx = fifo_check_empty_and_take(&busy_fifo, &busy_fifo_lock);
	while ((retry != 0) && (ctx != NULL)) {
		retry--;
		src_sqd = ctx->sq_data;
		if (!src_sqd) {
			IOURING_WARN("sq %d gets ctx(%d) from kfifo, but source sqd is null.\n",\
				des_sqd->sq_cpu, ctx->id);
			goto out;
		}
		
		if (src_sqd == des_sqd) {
			IOURING_WARN("Get ctx(%d) from kfifo, source and dest sqd are %d, retry=%d.\n", \
				  ctx->id, des_sqd->sq_cpu, retry);
			put_back = fifo_check_full_and_put(&busy_fifo, \
						&busy_fifo_lock, ctx);
			if (!put_back) {
				IOURING_WARN("Put back ctx(%d) to kfifo failed, retry=%d.\n", \
					ctx->id, retry);
				ctx->schedule_state = CTX_SCHED_NONE;
				continue;
			}
			if (retry != 0) {
				ctx = fifo_check_empty_and_take(&busy_fifo, \
							&busy_fifo_lock);
				continue;
			}
		} else {
			IOURING_INFO("sq %d gets ctx(%d) from kfifo success.\n",\
				des_sqd->sq_cpu, ctx->id);
			ctx->schedule_state = CTX_SCHED_CAN_TAKE;
			des_sqd->sched_ctx = ctx;
			result = true;
			goto out;
		}
	}
	
out:
	return result;
}

void fifo_remove_ctx(struct io_ring_ctx *ctx)
{
	struct io_ring_ctx * ctxs[CTX_FIFO_MAX];
	struct io_ring_ctx * tmp_ctx;
	int len, number, index;
	unsigned long _flags;
	bool exist = false;

	spin_lock_irqsave(&busy_fifo_lock, _flags);

	len = kfifo_len(&busy_fifo);
	number = len / sizeof(struct io_ring_ctx *);
	if (0 == number)
		goto out;

	kfifo_out(&busy_fifo, &ctxs, len);
	for (index = 0; index < number; index++) {
		tmp_ctx = ctxs[index];
		if (tmp_ctx == ctx) {
			exist = true;
			continue;
		}
		kfifo_in(&busy_fifo, &tmp_ctx, sizeof(struct io_ring_ctx *));
	}
out:
	spin_unlock_irqrestore(&busy_fifo_lock, _flags);
}

void swap_thread(struct io_sq_data* sqd, struct io_sq_data* min_load_sqd, int* min_cpu, int index)
{
	if (min_load_sqd == NULL) 
		return;
	if (min_load_sqd->thread->se.sq_avg.util_avg < sqd->thread->se.sq_avg.util_avg)
		*min_cpu = index;
}

/*
* If a sq thread only contains one ctx and its utilization is low(eg: < TASK_UTIL_THRESHOLD_LOW),
* we will reschedule it to a target sq thread which has lowerest utilization.
* The orginal sq thread which hosting the ctx ewill be idle and sleep. Therefore,
* the total CPU consumption will be reduced.
*/
static void do_ctx_merge(unsigned long old_merge_time)
{
	int i, min_cpu;
	struct task_struct *sq_thread;
	struct io_sq_data  *sqd, *min_sqd;
	struct io_ring_ctx* ctx;
        int sq_load;
        int judge_min;
	unsigned long new_merge_time = jiffies + CTX_MERGE_TIMEOUT;
	if(old_merge_time != cmpxchg(&merge_time, old_merge_time, new_merge_time)) {
		return;
	}
	show_sq_and_ctx();
	min_cpu = INVALID_CPU_ID;
	min_sqd = NULL;
	sqd = NULL;
	sq_thread = NULL;
	ctx = NULL;
        sq_load = 0;
	for_each_online_cpu(i) {
		sqd = *per_cpu_ptr(percpu_sqd, i);
		sq_thread = sqd->thread;
		sqd->merge_state = SQ_MERGE_NONE;
		if(list_empty_careful(&sqd->ctx_list))
			continue;

		sq_load = sq_thread_load(sqd);
		if (sq_load == 1) 
			swap_thread(sqd, min_sqd, &min_cpu, i);
	}

	if(min_cpu == INVALID_CPU_ID) {
		IOURING_INFO("Don't find any sqd for merge in.\n");
		return;
	}

	IOURING_INFO("Selected the lightest sq:%d.\n", \
			min_sqd->sq_cpu);
	for_each_online_cpu(i) {
		if(i == min_cpu) continue;
		sqd = *per_cpu_ptr(percpu_sqd, i);
		sq_thread = sqd->thread;

		if(list_empty_careful(&sqd->ctx_list)) continue;
		sq_load = sq_thread_load(sqd);
		if (sq_load != 1 || !list_is_singular(&sqd->ctx_list)) 
			continue;
		ctx = list_first_entry(&sqd->ctx_list, typeof(*ctx), sqd_list);
		if(ctx) {
			ctx->schedule_state = CTX_SCHED_CAN_TAKE;
			list_add(&ctx->sqd_merge_list, &min_sqd->merge_list);
			IOURING_INFO("sq %d gives ctx(%d) to merge.\n", \
					sqd->sq_cpu, ctx->id);
		}
	}
	smp_wmb();
	min_sqd->merge_state = SQ_MERGE_CAN_TAKE;
}

static struct io_sq_data *io_alloc_sq_data(void)
{
        struct io_sq_data *sqd;

        sqd = kzalloc(sizeof(*sqd), GFP_KERNEL);
        if (!sqd)
                return ERR_PTR(-ENOMEM);

        atomic_set(&sqd->park_pending, 0);
        refcount_set(&sqd->refs, 1);
        INIT_LIST_HEAD(&sqd->ctx_list);
        mutex_init(&sqd->lock);
        init_waitqueue_head(&sqd->wait);
        init_completion(&sqd->exited);
        mutex_init(&sqd->ctx_list_lock);
        spin_lock_init(&find_cpu);
        sqd->sched_check_timeout = jiffies + SCHED_CHECK_TIMEOUT;
        sqd->sched_ctx = NULL;
        sqd->merge_state = SQ_MERGE_NONE;
        INIT_LIST_HEAD(&sqd->merge_list);
        return sqd;
}

struct io_sq_data* get_percpu_sqd(int cpu_id)
{
	struct io_sq_data  *sqd;
	if (cpu_id >= 0 && cpu_online(cpu_id)) {
		sqd = *per_cpu_ptr(percpu_sqd, cpu_id);
		sqd->sched_check_timeout = jiffies + 30*HZ;
		return sqd;
	}
	/* cpu_id = min_usage_cpu();*/
	cpu_id = find_idlest_cpu();
	if(unlikely(!cpu_online(cpu_id))) {
		return NULL;
	}
	sqd = *per_cpu_ptr(percpu_sqd, cpu_id);

	sqd->sched_check_timeout = jiffies + SCHED_CHECK_TIMEOUT;
	/* printk("select the idlest cpu %d to poll the ctx.\n", sqd->sq_cpu);*/
	return sqd;
}

void io_sq_thread_unpark(struct io_sq_data *sqd)
	__releases(&sqd->lock)
{
	WARN_ON_ONCE(sqd->thread == current);

	/*
	 * Do the dance but not conditional clear_bit() because it'd race with
	 * other threads incrementing park_pending and setting the bit.
	 */
	clear_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
	if (atomic_dec_return(&sqd->park_pending))
		set_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
	mutex_unlock(&sqd->lock);
        merge_time = jiffies + CTX_MERGE_TIMEOUT;
}

void io_sq_thread_park(struct io_sq_data *sqd)
	__acquires(&sqd->lock)
{
	WARN_ON_ONCE(sqd->thread == current);

	atomic_inc(&sqd->park_pending);
	set_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
	mutex_lock(&sqd->lock);
	if (sqd->thread)
		wake_up_process(sqd->thread);
}

void io_sq_thread_stop(struct io_sq_data *sqd)
{
	WARN_ON_ONCE(sqd->thread == current);
	WARN_ON_ONCE(test_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state));

	set_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state);
	mutex_lock(&sqd->lock);
	if (sqd->thread)
		wake_up_process(sqd->thread);
	mutex_unlock(&sqd->lock);
	wait_for_completion(&sqd->exited);
}

static bool io_sqd_handle_event(struct io_sq_data *sqd)
{
	bool ret = false;
	if (test_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state)) {
		mutex_unlock(&sqd->lock);
		/* IOURING_DBG("@@ sq(%d) parked for mark begin, pending:%d\n", \
				sqd->sq_cpu, atomic_read(&sqd->park_pending)); */
		cond_resched();
		/* IOURING_DBG("@@ sq(%d) parked for mark end, pending:%d\n", \
				sqd->sq_cpu, atomic_read(&sqd->park_pending)); */
		mutex_lock(&sqd->lock);
		ret = true;
	}
	return ret;
}

void io_put_sq_data(struct io_sq_data *sqd)
{
	refcount_dec(&sqd->refs);
	IOURING_DBG("@@io_put_sq_data sq(%d) refs:%d\n",sqd->sq_cpu, \
		refcount_read(&sqd->refs));
}
/*
* TODO: the sqd->sq_thread_idle will be 0, when sqd->ctx_list is null
*/
static __cold void io_sqd_update_thread_idle(struct io_sq_data *sqd)
{
	struct io_ring_ctx *ctx;
	unsigned sq_thread_idle = 0;

	list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
		sq_thread_idle = max(sq_thread_idle, ctx->sq_thread_idle);
	sqd->sq_thread_idle = sq_thread_idle;
}

void release_ctx_from_sq(struct io_ring_ctx *ctx)
{
	struct io_sq_data *sqd = ctx->sq_data;
	if (sqd) {
		io_sq_thread_park(sqd);
		list_del_init(&ctx->sqd_list);
		list_del_init(&ctx->sqd_merge_list);
		io_sqd_update_thread_idle(sqd);
		io_sq_thread_unpark(sqd);
		ctx->sq_data = NULL;
	}
}

void io_sq_thread_finish(struct io_ring_ctx *ctx)
{
	struct io_sq_data *sqd = ctx->sq_data;
	release_ctx_from_sq(ctx);
	io_put_sq_data(sqd);
}

static struct io_sq_data *io_attach_sq_data(struct io_uring_params *p)
{
	struct io_ring_ctx *ctx_attach;
	struct io_sq_data *sqd;
	struct fd f;

	f = fdget(p->wq_fd);
	if (!f.file)
		return ERR_PTR(-ENXIO);
	if (!io_is_uring_fops(f.file)) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	ctx_attach = f.file->private_data;
	sqd = ctx_attach->sq_data;
	if (!sqd) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}
	if (sqd->task_tgid != current->tgid) {
		IOURING_DBG("sqd(%d) task_tgid (%d) not equal to current (%d)\n", \
			sqd->sq_cpu, sqd->task_tgid, current->tgid);
		fdput(f);
		return ERR_PTR(-EPERM);
	}

	refcount_inc(&sqd->refs);
	fdput(f);
	return sqd;
}

static struct io_sq_data *io_get_sq_data(struct io_uring_params *p,
					 bool *attached, int cpu_id)
{
	struct io_sq_data *sqd;

	*attached = false;
	if (p->flags & IORING_SETUP_ATTACH_WQ) {
		sqd = io_attach_sq_data(p);
		if (!IS_ERR(sqd)) {
			*attached = true;
			return sqd;
		}
		/* fall through for EPERM case, setup new sqd/task */
		if (PTR_ERR(sqd) != -EPERM)
			return sqd;
	}
        return get_percpu_sqd(cpu_id);
}

static inline bool io_sqd_events_pending(struct io_sq_data *sqd)
{
	return READ_ONCE(sqd->state);
}

static int __io_sq_thread(struct io_ring_ctx *ctx, bool cap_entries)
{
	unsigned int to_submit;
	int ret = 0;

	to_submit = io_sqring_entries(ctx);
	/* if we're handling multiple rings, cap submit size for fairness */
	if (cap_entries && to_submit > IORING_SQPOLL_CAP_ENTRIES_VALUE)
		to_submit = IORING_SQPOLL_CAP_ENTRIES_VALUE;

	if (!wq_list_empty(&ctx->iopoll_list) || to_submit) {
		const struct cred *creds = NULL;

		if (ctx->sq_creds != current_cred())
			creds = override_creds(ctx->sq_creds);

		mutex_lock(&ctx->uring_lock);
		if (!wq_list_empty(&ctx->iopoll_list))
			io_do_iopoll(ctx, true);

		/*
		 * Don't submit if refs are dying, good for io_uring_register(),
		 * but also it is relied upon by io_ring_exit_work()
		 */
		if (to_submit && likely(!percpu_ref_is_dying(&ctx->refs)) &&
		    !(ctx->flags & IORING_SETUP_R_DISABLED))
			ret = io_submit_sqes(ctx, to_submit);
		mutex_unlock(&ctx->uring_lock);

		if (to_submit && wq_has_sleeper(&ctx->sqo_sq_wait))
			wake_up(&ctx->sqo_sq_wait);
		if (creds)
			revert_creds(creds);
	}

	return ret;
}

static int io_sq_thread(void *data)
{
	struct io_sq_data *sqd = data;
	struct io_ring_ctx *ctx;
	unsigned long timeout = 0;
        struct mm_struct *oldmm, *mm;

        struct io_uring_task *io_tctx;
	DEFINE_WAIT(wait);
        oldmm = current->mm;
        sqd->thread = current;

        merge_time = jiffies + CTX_MERGE_TIMEOUT;
	mutex_lock(&sqd->lock);
	bool first = true;
	struct timespec64 ts_start, ts_end;
	struct timespec64 ts_delta;
	struct sched_entity *se = &sqd->thread->se;
	while (1) {
		bool cap_entries, sqt_spin = false, needs_sched=true;
		struct io_ring_ctx* temp_ctx;

                if (io_sqd_handle_event(sqd)){
			timeout = jiffies + sqd->sq_thread_idle;
                }
		
		if (time_after(jiffies, timeout)) {
			mutex_unlock(&sqd->lock);
			cond_resched();
			mutex_lock(&sqd->lock);
			timeout = jiffies + sqd->sq_thread_idle;
		}

                cap_entries = !list_is_singular(&sqd->ctx_list);
                mm = current->mm;
                io_tctx = current->io_uring;
		ktime_get_boottime_ts64(&ts_start);
		ts_delta = timespec64_sub(ts_start, ts_end);
		unsigned long long now = ts_delta.tv_sec * NSEC_PER_SEC + ts_delta.tv_nsec +
		se->sq_avg.last_update_time;

		if (first) {
			now = 0;
			first = false;
		}
		__update_sq_avg_block(now, se);
                list_for_each_entry_safe(ctx, temp_ctx, &sqd->ctx_list, sqd_list) {
                        int ret;
                        if (!ctx->rings || percpu_ref_is_dying(&ctx->refs)) {
                                list_del_init_careful(&ctx->sqd_list);
                                continue;
                        }

                        if(ctx->schedule_state == CTX_SCHED_CAN_TAKE) {
                                list_del_init(&ctx->sqd_list);
                                smp_wmb();
                                ctx->schedule_state = CTX_SCHED_REMOVED;
                                IOURING_INFO("sq %d removed ctx(%d).\n", sqd->sq_cpu, ctx->id);
                                continue;
                        }
                        current->io_uring = ctx->io_uring;
                        current->mm = ctx->mm_account;

                        ret = __io_sq_thread(ctx, cap_entries);

                        if (!sqt_spin && (ret > 0 || !wq_list_empty(&ctx->iopoll_list)))
                                sqt_spin = true;
                }
		ktime_get_boottime_ts64(&ts_end);
		ts_delta = timespec64_sub(ts_end, ts_start);
		now = ts_delta.tv_sec * NSEC_PER_SEC + ts_delta.tv_nsec +
		se->sq_avg.last_update_time;

		if (sqt_spin)
			__update_sq_avg(now, se);
		else
			__update_sq_avg_block(now, se);
                current->mm = mm;
                current->io_uring = io_tctx;

                /* Take the scheduled ctx in, if it's removed from the origin sq */
                if(sqd->sched_ctx && sqd->sched_ctx->schedule_state == CTX_SCHED_REMOVED) {
                        list_add_tail(&sqd->sched_ctx->sqd_list, &sqd->ctx_list);
                        IOURING_INFO("sq %d took ctx(%d) in.\n", sqd->sq_cpu, sqd->sched_ctx->id);
                        sqd->sched_ctx->schedule_state = CTX_SCHED_NONE;
                        sqd->sched_ctx->sq_data = sqd;
                        sqd->sched_ctx = NULL;
                }
                /* Take in all ctxs in merge list if they are ready */
                if(sqd->merge_state == SQ_MERGE_CAN_TAKE && !list_empty_careful(&sqd->merge_list)) {
                        list_for_each_entry_safe(ctx, temp_ctx, &sqd->merge_list, sqd_merge_list) {
                                if(ctx->schedule_state == CTX_SCHED_REMOVED) {
                                        list_del_init_careful(&ctx->sqd_merge_list);
                                        list_add_tail(&ctx->sqd_list, &sqd->ctx_list);
                                        ctx->schedule_state = CTX_SCHED_NONE;
                                        ctx->sq_data = sqd;
                                        IOURING_INFO("sq %d merged ctx(%d).\n", sqd->sq_cpu, ctx->id);
                                }
                        }
                }
                if(time_after(jiffies, sqd->sched_check_timeout)) {
                        sqd->sched_check_timeout = jiffies + SCHED_CHECK_TIMEOUT;
                        switch(io_get_migration_dir(sqd)) {
                                case MIGRATION_OUT:
                                        io_migrate_out(sqd);
                                        break;
                                case MIGRATION_IN:
                                        io_migrate_in(sqd);
                                        break;
                                default:
                                        break;
                        }
                }


                if(time_after(jiffies, merge_time)) {
                        do_ctx_merge(merge_time);
                }

		if (io_sqd_events_pending(sqd)) continue;

                if (io_run_task_work()) sqt_spin = true;

		if (sqt_spin || !time_after(jiffies, timeout)) {
			mutex_unlock(&sqd->lock);
			cond_resched();
			mutex_lock(&sqd->lock);
			if (sqt_spin)
				timeout = jiffies + sqd->sq_thread_idle;
			continue;
		}

		prepare_to_wait(&sqd->wait, &wait, TASK_INTERRUPTIBLE);
                list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
                        if ((ctx->flags & IORING_SETUP_IOPOLL) && !wq_list_empty(&ctx->iopoll_list)) {
                                needs_sched = false;
                                break;
                        }

                        if (io_sqring_entries(ctx)) {
                                needs_sched = false;
                                break;
                        }
                }

		if (needs_sched) {
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list){
			        atomic_or(IORING_SQ_NEED_WAKEUP, &ctx->rings->sq_flags);
                        }
			mutex_unlock(&sqd->lock);
			schedule();
			mutex_lock(&sqd->lock);
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list){
			        atomic_andnot(IORING_SQ_NEED_WAKEUP, &ctx->rings->sq_flags);
                        }
		}

		finish_wait(&sqd->wait, &wait);
		timeout = jiffies + sqd->sq_thread_idle;
	}
        current->mm = oldmm;
	sqd->thread = NULL;
        current->io_uring = NULL;
	mutex_unlock(&sqd->lock);
	kthread_parkme();
	return 0;
}

int io_sqpoll_wait_sq(struct io_ring_ctx *ctx)
{
	DEFINE_WAIT(wait);

	do {
		if (!io_sqring_full(ctx))
			break;
		prepare_to_wait(&ctx->sqo_sq_wait, &wait, TASK_INTERRUPTIBLE);

		if (!io_sqring_full(ctx))
			break;
		schedule();
	} while (!signal_pending(current));

	finish_wait(&ctx->sqo_sq_wait, &wait);
	return 0;
}

__cold int io_sq_offload_create(struct io_ring_ctx *ctx,
				struct io_uring_params *p)
{
	int ret;

	/* Retain compatibility with failing for an invalid attach attempt */
	if ((ctx->flags & (IORING_SETUP_ATTACH_WQ | IORING_SETUP_SQPOLL)) ==
				IORING_SETUP_ATTACH_WQ) {
		struct fd f;

		f = fdget(p->wq_fd);
		if (!f.file)
			return -ENXIO;
		if (!io_is_uring_fops(f.file)) {
			fdput(f);
			return -EINVAL;
		}
		fdput(f);
	}
	if (ctx->flags & IORING_SETUP_SQPOLL) {
		struct io_sq_data *sqd;
		bool attached;
		int cpu_id;
                unsigned long _flags;

		ret = security_uring_sqpoll();
		if (ret)
			return ret;

                if(p->flags & IORING_SETUP_SQ_AFF) {
                        cpu_id = p->sq_thread_cpu;
                        ret = -EINVAL;
                        if(cpu_id >= nr_cpu_ids || !cpu_online(cpu_id))
                                goto err_sqpoll;
                } else {
                        cpu_id = -1;
                }

		sqd = io_get_sq_data(p, &attached, cpu_id);

		if (IS_ERR(sqd)) {
			ret = PTR_ERR(sqd);
			goto err;
		}

		ctx->sq_creds = get_current_cred();
		ctx->sq_data = sqd;
		ctx->sq_thread_idle = msecs_to_jiffies(p->sq_thread_idle);
                if (!ctx->sq_thread_idle)
                        ctx->sq_thread_idle = HZ;

                if(!sqd->thread) {
                        IOURING_ERR("sqd->thread == null \n");
                        goto err;
                }

		io_sq_thread_park(sqd);
		list_add_tail(&ctx->sqd_list, &sqd->ctx_list);
		io_sqd_update_thread_idle(sqd);
		ret = (attached && !sqd->thread) ? -ENXIO : 0;
		io_sq_thread_unpark(sqd);

		IOURING_INFO("@@ add ctx(%d) to sq(%d) ctx_list success\n", \
			ctx->id, sqd->sq_cpu);
		
		/* don't attach to a dying SQPOLL thread, would be racy */
		if (ret < 0) {
			IOURING_WARN("attach ctx(%d) to dying sq(%d) \n", \
				ctx->id, sqd->sq_cpu);
                        goto err;
                }
                if (attached)
                        return 0;

		ret = io_uring_alloc_task_context(sqd->thread, ctx);

		if (ret) {
			IOURING_WARN("Failed to alloc task context for ctx(%d)\n", ctx->id);
			goto err;
		}
	} else if (p->flags & IORING_SETUP_SQ_AFF) {
		/* Can't have SQ_AFF without SQPOLL */
		ret = -EINVAL;
		goto err;
	}

	return 0;
err_sqpoll:
	complete(&ctx->sq_data->exited);
err:
	io_sq_thread_finish(ctx);
	return ret;
}

static int __init io_thread_init(void)
{
	struct io_sq_data *sqd;
	char buf[TASK_COMM_LEN];
	int cpu, res;
	percpu_sqd = alloc_percpu(struct io_sq_data *);
	for_each_possible_cpu(cpu) {
		sqd = *per_cpu_ptr(percpu_sqd, cpu) = io_alloc_sq_data();

		snprintf(buf, sizeof(buf), "io-sqt-%d", cpu);
		sqd->thread = kthread_create_on_cpu(io_sq_thread, sqd, cpu, buf);
		sqd->sq_cpu = cpu;
	}
	spin_lock_init(&cpu_util_lock);
	res = kfifo_alloc(&busy_fifo, CTX_FIFO_MAX * sizeof(struct io_ring_ctx *), GFP_KERNEL);
	spin_lock_init(&busy_fifo_lock);
	merge_time = jiffies + CTX_MERGE_TIMEOUT;
	return 0;
};
__initcall(io_thread_init);
