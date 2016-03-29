#include <endian.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "fsqueue.h"


static void fsq_struct_init(struct fsq *q)
{
	q->dirfd = -1;
	q->rd_idx_fd = -1;
	q->rd_idx_base = MAP_FAILED;
	q->wr_idx_fd = -1;
	q->wr_idx_base = MAP_FAILED;
	q->data_dirfd = -1;
}

int fsq_openat(int dirfd, const char *path, struct fsq *q)
{
	int status = 0;

	fsq_struct_init(q);

	q->dirfd = openat(dirfd, path, O_RDONLY | O_DIRECTORY);
	if(q->dirfd < 0) {
		status = -1;
		goto error;
	}

	q->rd_idx_fd = openat(q->dirfd, "rd_idx", O_CREAT | O_RDWR, 0644);
	if(q->rd_idx_fd < 0) {
		status = -2;
		goto error;
	}
	if(ftruncate(q->rd_idx_fd, sizeof(uint64_t))) {
		status = -3;
		goto error;
	}

	q->wr_idx_fd = openat(q->dirfd, "wr_idx", O_CREAT | O_RDWR, 0644);
	if(q->wr_idx_fd < 0) {
		status = -4;
		goto error;
	}
	if(ftruncate(q->wr_idx_fd, sizeof(uint64_t))) {
		status = -5;
		goto error;
	}

	if(mkdirat(q->dirfd, "data", 0755)) {
		if(errno != EEXIST) {
			status = -6;
			goto error;
		}
	}

	q->data_dirfd = openat(q->dirfd, "data", O_RDONLY | O_DIRECTORY);
	if(q->data_dirfd < 0) {
		status = -7;
		goto error;
	}

	q->rd_idx_base =
		mmap(NULL, sizeof(uint64_t),
		     PROT_READ | PROT_WRITE, MAP_SHARED,
		     q->rd_idx_fd, 0);
	if(q->rd_idx_base == MAP_FAILED) {
		status = -8;
		goto error;
	}

	q->wr_idx_base =
		mmap(NULL, sizeof(uint64_t),
		     PROT_READ | PROT_WRITE, MAP_SHARED,
		     q->wr_idx_fd, 0);
	if(q->wr_idx_base == MAP_FAILED) {
		status = -9;
		goto error;
	}

done:
	return status;

error:
	fsq_close(q);
	goto done;
}

int fsq_init(struct fsq *q)
{
	int status = 0;

	memset(q->rd_idx_base, 0, sizeof(uint64_t));
	memset(q->wr_idx_base, 0, sizeof(uint64_t));

	if(msync(q->wr_idx_base, sizeof(uint64_t), MS_SYNC)) {
		status = -1;
		goto error;
	}

	if(msync(q->rd_idx_base, sizeof(uint64_t), MS_SYNC)) {
		status = -2;
		goto error;
	}

done:
	return status;

error:
	goto done;
}

void fsq_close(struct fsq *q)
{
	if(q->dirfd >= 0)
		close(q->dirfd);

	if(q->rd_idx_base != MAP_FAILED)
		munmap(q->rd_idx_base, sizeof(uint64_t));

	if(q->rd_idx_fd >= 0)
		close(q->rd_idx_fd);

	if(q->wr_idx_base != MAP_FAILED)
		munmap(q->wr_idx_base, sizeof(uint64_t));

	if(q->wr_idx_fd >= 0)
		close(q->wr_idx_fd);

	if(q->data_dirfd >= 0)
		close(q->data_dirfd);
}

int fsq_enq(struct fsq *q, const char *buf, size_t buflen)
{
	int status = 0;
	char name[32];
	uint64_t idx;
	int fd = -1;

	idx = be64toh(*(uint64_t *)q->wr_idx_base);

	snprintf(name, sizeof(name), "%16.16" PRIx64, idx);

	fd = openat(q->data_dirfd, name, O_CREAT | O_WRONLY, 0644);
	if(fd < 0) {
		status = -1;
		goto error;
	}

	ssize_t wstatus = 0;
	while((wstatus = write(fd, buf, buflen)) < 0) {
		if(errno == EINTR)
			continue;
		status = -2;
		goto error;
	}

	if(wstatus != (ssize_t)buflen) {
		status = -3;
		goto error;
	}

	*(uint64_t *)q->wr_idx_base = htobe64(idx+1);
	if(msync(q->wr_idx_base, sizeof(uint64_t), MS_SYNC)) {
		status = -4;
		goto error;
	}

done:
	if(fd >= 0)
		close(fd);
	return status;

error:
	goto done;
}

int fsq_deq(struct fsq *q, char **buf, size_t *buflen)
{
	int status = 0;
	char name[32];
	uint64_t idx;
	int fd = -1;
	struct stat sb;

	*buf = NULL;
	*buflen = 0;

	if(*(uint64_t*)q->wr_idx_base <= *(uint64_t*)q->rd_idx_base)
		return -1;

	idx = be64toh(*(uint64_t *)q->rd_idx_base);

	snprintf(name, sizeof(name), "%16.16" PRIx64, idx);

	fd = openat(q->data_dirfd, name, O_RDONLY);
	if(fd < 0) {
		status = -2;
		goto error;
	}

	if(fstat(fd, &sb)) {
		status = -3;
		goto error;
	}

	*buflen = sb.st_size;
	*buf = malloc(*buflen);
	while(read(fd, *buf, *buflen) < 0) {
		if(errno == EINTR)
			continue;
		status = -4;
		goto error;
	}

	if(unlinkat(q->data_dirfd, name, 0)) {
		status = -5;
		goto error;
	}

	*(uint64_t *)q->rd_idx_base = htobe64(idx+1);
	
done:
	close(fd);
	return status;

error:
	if(*buf) {
		free(*buf);
		*buf = NULL;
		*buflen = 0;
	}
	goto done;
}
