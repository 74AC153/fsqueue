#if ! defined(FSQUEUE_H_INCLUDED)
#define FSQUEUE_H_INCLUDED

struct fsq {
	int rd_idx_fd;
	void *rd_idx_base;

	int wr_idx_fd;
	void *wr_idx_base;

	int data_dirfd;
};

int fsq_open(int dirfd, struct fsq *q);
int fsq_init(struct fsq *q);
void fsq_close(struct fsq *q);

int fsq_enq(struct fsq *q, const char *buf, size_t buflen);
int fsq_deq(struct fsq *q, char **buf, size_t *buflen);

#endif
