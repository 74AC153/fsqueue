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

#define FSQ_PATH_LEN 17

struct fsq_common {
	int dirfd;
	int data_dirfd;
};

struct dir_watch_info {
	int inotify_evt_q;
	int inotify_wd;
	pthread_t watch_thread;
	int watch_thread_created;
	int updated;
	pthread_mutex_t update_mux;
	pthread_cond_t update_cond;
};

struct fsq_produce {
	struct fsq_common hdr;
	struct dir_watch_info watch;
};

struct fsq_consume {
	struct fsq_common hdr;
	struct dir_watch_info watch;
};

int fsq_produce_open(struct fsq_produce *q, const char *path);
void fsq_produce_close(struct fsq_produce *q);

int fsq_consume_open(struct fsq_consume *q, const char *path);
void fsq_consume_close(struct fsq_consume *q);

// if maxlen == 0, don't block on max queue length
int fsq_tail_file(
	struct fsq_produce *q, uint64_t maxlen, struct timespec *timeout,
	int *dirfd, char *path);
int fsq_tail_advance(struct fsq_produce *q);

int fsq_len(struct fsq_produce *q, uint64_t *len);

// timeout can be NULL, meaning block forever
// path is modified and must be at least length 17
int fsq_head_file(
	struct fsq_consume *q, uint64_t off, struct timespec *timeout,
	int *dirfd, char *path);
int fsq_head_advance(struct fsq_consume *q);



#endif
