#if ! defined(FSQUEUE_H_INCLUDED)
#define FSQUEUE_H_INCLUDED

#include <stdint.h>
#include <time.h>
#include <pthread.h>

struct fsq {
	int dirfd;

	int data_dirfd;

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

int fsq_open(struct fsq *q, const char *path);
void fsq_close(struct fsq *q);

int fsq_enq(struct fsq *q, const char *buf, size_t buflen);
int fsq_deq(struct fsq *q, struct timespec *timeout, char **buf, size_t *buflen);

// lock the queue and map the first item in the queue into memory
int fsq_head(struct fsq *q, struct timespec *timeout, const char **buf, size_t *buflen);
// unmap first item in queue from memory and advance the queue
int fsq_advance(struct fsq *q);

#endif
