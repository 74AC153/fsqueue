#if ! defined(FSQUEUE_H_INCLUDED)
#define FSQUEUE_H_INCLUDED

#include <stdint.h>
#include <time.h>

struct fsq {
	int dirfd;

	int rd_idx_fd;
	uint64_t *rd_idx_base;

	int wr_idx_fd;
	uint64_t *wr_idx_base;

	int data_dirfd;

	int head_fd;
	const char *head_buf;
	size_t head_buflen;
};

int fsq_openat(struct fsq *q, int dirfd, const char *path);
int fsq_init(struct fsq *q);
void fsq_close(struct fsq *q);

int fsq_enq(struct fsq *q, const char *buf, size_t buflen);
int fsq_deq(struct fsq *q, struct timespec *timeout, char **buf, size_t *buflen);

// lock the queue and map the first item in the queue into memory
int fsq_head(struct fsq *q, struct timespec *timeout, const char **buf, size_t *buflen);
// unmap first item in queue from memory and advance the queue
int fsq_advance(struct fsq *q);

// unlock the queue in case the system crashed while lock was held
int fsq_recover(struct fsq *q);

#endif
