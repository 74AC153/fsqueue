#if ! defined(FSQUEUE_H_INCLUDED)
#define FSQUEUE_H_INCLUDED

#include <stdint.h>
#include <time.h>
#include <pthread.h>

#define FSQ_OK 0
#define FSQ_TIMEOUT -1
#define FSQ_SYS_ERR -2
#define FSQ_INTERNAL_ERR -3
#define FSQ_USER_ERR -4
#define FSQ_IN_USE -5
#define FSQ_EMPTY -6

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
int fsq_enq_file(struct fsq_produce *q, int dirfd, const char *path);

int fsq_len(struct fsq_produce *q, uint64_t *len);

// map the first item in the queue into memory
// timeout can be NULL, meaning block forever
int fsq_head(
	struct fsq_consume *q, struct timespec *timeout,
	const char **buf, size_t *buflen);
// path is modified and must be at least length 17
int fsq_head_file(
	struct fsq_consume *q, struct timespec *timeout,
	int *dirfd, char *path);

// unmap first item in queue from memory and advance the queue
int fsq_advance(struct fsq_consume *q);



#endif
