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
#include <time.h>

#include "fsqueue.h"


static void fsq_struct_init(struct fsq *q)
{
	q->dirfd = -1;
	q->rd_idx_fd = -1;
	q->rd_idx_base = MAP_FAILED;
	q->wr_idx_fd = -1;
	q->wr_idx_base = MAP_FAILED;
	q->data_dirfd = -1;
	q->head_fd = -1;
	q->head_buf = MAP_FAILED;
	q->head_buflen = 0;
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
		mmap(NULL, sizeof(*q->rd_idx_base),
		     PROT_READ | PROT_WRITE, MAP_SHARED,
		     q->rd_idx_fd, 0);
	if(q->rd_idx_base == MAP_FAILED) {
		status = -8;
		goto error;
	}

	q->wr_idx_base =
		mmap(NULL, sizeof(*q->wr_idx_base),
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

	memset(q->rd_idx_base, 0, sizeof(*q->rd_idx_base));
	memset(q->wr_idx_base, 0, sizeof(*q->wr_idx_base));

	{
		struct timespec times[2] = {
			[0] = { .tv_sec = 0, .tv_nsec = UTIME_OMIT }, // atime
			[1] = { .tv_sec = 0, .tv_nsec = UTIME_NOW } // mtime
		};
		// since this is only advisory, ignore failures
		futimens(q->rd_idx_fd, times);
		futimens(q->wr_idx_fd, times);
	}

	return status;
}

void fsq_close(struct fsq *q)
{
	if(q->dirfd >= 0)
		close(q->dirfd);

	if(q->rd_idx_base != MAP_FAILED)
		munmap(q->rd_idx_base, sizeof(*q->rd_idx_base));

	if(q->rd_idx_fd >= 0)
		close(q->rd_idx_fd);

	if(q->wr_idx_base != MAP_FAILED)
		munmap(q->wr_idx_base, sizeof(*q->wr_idx_base));

	if(q->wr_idx_fd >= 0)
		close(q->wr_idx_fd);

	if(q->data_dirfd >= 0)
		close(q->data_dirfd);

	if(q->head_buf != MAP_FAILED)
		munmap((char*)q->head_buf, q->head_buflen);

	if(q->head_fd >= 0)
		close(q->head_fd);
}

// return lhs >= rhs
static _Bool timespec_geq(struct timespec lhs, struct timespec rhs)
{
	if(lhs.tv_sec > rhs.tv_sec)
		return 1;

	if(lhs.tv_sec == rhs.tv_sec)
		return lhs.tv_nsec >= rhs.tv_nsec;

	return 0;
}

#define POLL_INTERVAL_US 100000
enum lock_type {
	LOCK_READ,
	LOCK_WRITE
};
static int fsq_lock(struct fsq *q, struct timespec *timeout, enum lock_type type)
{
	int status = 0;

	char *lock_name = NULL;
	if(type == LOCK_READ)
		lock_name = "rdlock";
	else
		lock_name = "wrlock";

	struct timespec ts;
	if(clock_gettime(CLOCK_REALTIME, &ts))
		return -2;

again:
	while(1) {
		struct stat sb;
			
		if(fstatat(q->dirfd, lock_name, &sb, 0)) {
			if(errno == ENOENT)
				break;
			status = -3;
			goto error;
		}
		usleep(POLL_INTERVAL_US);

		if(timeout) {
			if(clock_gettime(CLOCK_REALTIME, &ts))
				return -4;
	
			if(timespec_geq(ts, *timeout))
				return -1;
		}
	}

	int fd = openat(q->dirfd, lock_name, O_RDWR | O_CREAT | O_EXCL, 0644);
	if(fd < 0) {
		if(errno == EEXIST)
			goto again;

		status = -5;
		goto error;
	}

done:
	if(fd >= 0)
		close(fd);
	return status;

error:
	goto done;
}

static int fsq_unlock(struct fsq *q, enum lock_type type)
{
	int status = 0;

	char *lock_name = NULL;
	if(type == LOCK_READ)
		lock_name = "rdlock";
	else
		lock_name = "wrlock";

	if(unlinkat(q->dirfd, lock_name, 0))
		if(errno != ENOENT)
			status = -1;

	return status;
}

int fsq_enq(struct fsq *q, const char *buf, size_t buflen)
{
	int status = 0;
	int fd = -1;

	if(fsq_lock(q, NULL, LOCK_WRITE)) // NB: will not timeout
		return -2;

	uint64_t idx = be64toh(*q->wr_idx_base);

	{
		char name[32];
		snprintf(name, sizeof(name), "%16.16" PRIx64, idx);
		fd = openat(q->data_dirfd, name, O_CREAT | O_WRONLY, 0644);
		if(fd < 0) {
			status = -3;
			goto error;
		}
	}

	ssize_t wstatus = 0;
	while((wstatus = write(fd, buf, buflen)) < 0) {
		if(errno == EINTR)
			continue;
		status = -4;
		goto error;
	}
	// in case of overwrite of existing data file
	if(ftruncate(fd, buflen)) {
		status = -5;
		goto error;
	}

	if(wstatus != (ssize_t)buflen) {
		status = -6;
		goto error;
	}

	*q->wr_idx_base = htobe64(idx+1);
	{
		struct timespec times[2] = {
			[0] = { .tv_sec = 0, .tv_nsec = UTIME_OMIT }, // atime
			[1] = { .tv_sec = 0, .tv_nsec = UTIME_NOW } // mtime
		};
		// since this is only advisory, ignore failures
		futimens(q->wr_idx_fd, times);
	}
	
done:
	fsq_unlock(q, LOCK_WRITE);

	if(fd >= 0)
		close(fd);
	return status;

error:
	goto done;
}

int fsq_head(struct fsq *q, struct timespec *timeout, const char **buf, size_t *buflen)
{
	int status = 0;

	// short-circut repeated calls to fsq_head without an fsq_advance between
	if(q->head_fd >= 0) {
		*buf = q->head_buf;
		*buflen = q->head_buflen;
		return 0;
	}

	// try to acquire queue lock

	while(1) {
		int rc;
		if((rc = fsq_lock(q, timeout, LOCK_READ)) == -1)
			return -1;
		if(rc)
			return -2;
	
		if(*q->wr_idx_base <= *q->rd_idx_base) {
			// empty queue -- unlock and sleep to try again later
			fsq_unlock(q, LOCK_READ);
		} else {
			break;
		}

		usleep(POLL_INTERVAL_US);

		if(timeout) {
			struct timespec ts;
			if(clock_gettime(CLOCK_REALTIME, &ts))
				return -3;
	
			if(timespec_geq(ts, *timeout))
				return -1;
		}
	}

	// map head of queue into memory

	{
		uint64_t idx = be64toh(*q->rd_idx_base);
		char name[32];
		snprintf(name, sizeof(name), "%16.16" PRIx64, idx);
	
		q->head_fd = openat(q->data_dirfd, name, O_RDONLY);
		if(q->head_fd < 0) {
			status = -4;
			goto error;
		}
	}

	{
		struct stat sb;
		if(fstat(q->head_fd, &sb)) {
			status = -5;
			goto error;
		}
		q->head_buflen = sb.st_size;
	}

	q->head_buf =
		mmap(NULL, q->head_buflen,
		     PROT_READ, MAP_SHARED,
		     q->head_fd, 0);
	if(q->head_buf == MAP_FAILED) {
		status = -8;
		goto error;
	}

	// output buffer

	*buf = q->head_buf;
	*buflen = q->head_buflen;

done:
	return status;

error:
	if(q->head_buf != MAP_FAILED)
		munmap((char*)q->head_buf, q->head_buflen);
	q->head_buf = MAP_FAILED;
	q->head_buflen = 0;

	if(q->head_fd >= 0)
		close(q->head_fd);
	q->head_fd = -1;

	goto done;
}

int fsq_advance(struct fsq *q)
{
	int status = 0;

	// short-circuit repeated calls to fsq_advance without an fsq_head between
	if(q->head_fd < 0)
		return 0;

	// advance queue read index

	uint64_t idx = be64toh(*q->rd_idx_base);
	*q->rd_idx_base = htobe64(idx+1);
	{
		struct timespec times[2] = {
			[0] = { .tv_sec = 0, .tv_nsec = UTIME_OMIT }, // atime
			[1] = { .tv_sec = 0, .tv_nsec = UTIME_NOW } // mtime
		};
		// since this is only advisory, ignore failures
		futimens(q->rd_idx_fd, times);
	}

	// clean up stale queue head buffer

	munmap((char*)q->head_buf, q->head_buflen);
	q->head_buf = MAP_FAILED;
	q->head_buflen = 0;

	close(q->head_fd);
	q->head_fd = -1;

	// remove data file

	{
		char name[32];
		snprintf(name, sizeof(name), "%16.16" PRIx64, idx);
		if(unlinkat(q->data_dirfd, name, 0)) {
			status = -7;
			goto error;
		}
	}


done:
	fsq_unlock(q, LOCK_READ);
	return status;

error:
	goto done;
}

int fsq_recover(struct fsq *q)
{
	// clean up lock
	if(fsq_unlock(q, LOCK_READ))
		return -1;
	if(fsq_unlock(q, LOCK_WRITE))
		return -2;
	return 0;
}

int fsq_deq(struct fsq *q, struct timespec *timeout, char **buf, size_t *buflen)
{
	const char* temp_buf;
	int rc;
	if((rc = fsq_head(q, timeout, &temp_buf, buflen)) == -1)
		return -1;
	if(rc)
		return (rc << 16) | (-2 & 0xFFFF);

	*buf = malloc(*buflen);
	memcpy(*buf, temp_buf, *buflen);

	rc = fsq_advance(q);
	if(rc)
		return (rc << 16) | (-3 & 0xFFFF);

	return 0;
}
