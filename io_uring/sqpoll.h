// SPDX-License-Identifier: GPL-2.0

enum sq_merge_state
{
        SQ_MERGE_NONE=0,
        SQ_MERGE_CAN_TAKE,
        SQ_MERGE_CAN_GIVE
};

struct io_sq_data {
	refcount_t		refs;
	atomic_t		park_pending;
	struct mutex		lock;

	/* ctx's that are using this sqd */
	struct list_head	ctx_list;
	struct mutex		ctx_list_lock;
	unsigned long		sched_check_timeout;
	struct io_ring_ctx      *sched_ctx;

	struct task_struct	*thread;
	struct wait_queue_head	wait;

	unsigned		sq_thread_idle;
	int			sq_cpu;
	pid_t			task_pid;
	pid_t			task_tgid;

        unsigned long		state;
	struct completion	exited;

	enum sq_merge_state     merge_state;
	struct list_head        merge_list;
};

int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p);
void fifo_remove_ctx(struct io_ring_ctx *ctx);
void release_ctx_from_sq(struct io_ring_ctx *ctx);
void io_sq_thread_finish(struct io_ring_ctx *ctx);
void io_sq_thread_stop(struct io_sq_data *sqd);
void io_sq_thread_park(struct io_sq_data *sqd);
void io_sq_thread_unpark(struct io_sq_data *sqd);
void io_put_sq_data(struct io_sq_data *sqd);
int io_sqpoll_wait_sq(struct io_ring_ctx *ctx);
