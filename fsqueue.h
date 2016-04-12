#if ! defined(FSQUEUE_H_INCLUDED)
#define FSQUEUE_H_INCLUDED

#include <stdint.h>
#include <time.h>
#include <pthread.h>

struct fsq_produce {
	int dirfd;
	int data_dirfd;
};

struct fsq_consume {
	struct fsq_produce hdr;

	int head_fd;
	const char *head_buf;
	size_t head_buflen;

	int inotify_evt_q;
	int inotify_wr_idx_wd;
	pthread_t watch_thread;
	int watch_thread_created;
	int wr_idx_updated;
	pthread_mutex_t update_mux;
	pthread_cond_t update_cond;
};

int fsq_produce_open(struct fsq_produce *q, const char *path);
void fsq_produce_close(struct fsq_produce *q);

int fsq_consume_open(struct fsq_consume *q, const char *path);
void fsq_consume_close(struct fsq_consume *q);

int fsq_enq(struct fsq_produce *q, const char *buf, size_t buflen);

int fsq_deq(struct fsq_consume *q, struct timespec *timeout, char **buf, size_t *buflen);

// lock the queue and map the first item in the queue into memory
int fsq_head(struct fsq_consume *q, struct timespec *timeout, const char **buf, size_t *buflen);
// unmap first item in queue from memory and advance the queue
int fsq_advance(struct fsq_consume *q);

#endif
