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

#define FSQ_OK 0
#define FSQ_TIMEOUT -1
#define FSQ_SYS_ERR -2
#define FSQ_INTERNAL_ERR -3
#define FSQ_USER_ERR -4

static int __attribute__((noinline)) _gen_err(int val)
{
	return val;
}

static void fsq_struct_init(struct fsq *q)
{
	q->dirfd = -1;
	q->rd_idx_fd = -1;
	q->wr_idx_fd = -1;
	q->data_dirfd = -1;
	q->head_fd = -1;
	q->head_buf = MAP_FAILED;
	q->head_buflen = 0;
}

int fsq_openat(struct fsq *q, int dirfd, const char *path)
{
	int status = 0;

	fsq_struct_init(q);

	q->dirfd = openat(dirfd, path, O_RDONLY | O_DIRECTORY);
	if(q->dirfd < 0) {
		status = _gen_err(FSQ_USER_ERR);
		goto error;
	}

	q->rd_idx_fd = openat(q->dirfd, "rd_idx", O_CREAT | O_RDWR, 0644);
	if(q->rd_idx_fd < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}
	if(ftruncate(q->rd_idx_fd, sizeof(uint64_t))) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}

	q->wr_idx_fd = openat(q->dirfd, "wr_idx", O_CREAT | O_RDWR, 0644);
	if(q->wr_idx_fd < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}
	if(ftruncate(q->wr_idx_fd, sizeof(uint64_t))) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}

	if(mkdirat(q->dirfd, "data", 0755)) {
		if(errno != EEXIST) {
			status = _gen_err(FSQ_SYS_ERR);
			goto error;
		}
	}

	q->data_dirfd = openat(q->dirfd, "data", O_RDONLY | O_DIRECTORY);
	if(q->data_dirfd < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}

done:
	return status;

error:
	fsq_close(q);
	goto done;
}

static int read_idx(int fd, uint64_t *val)
{
	if(lseek(fd, 0, SEEK_SET))
		return _gen_err(FSQ_SYS_ERR);
	ssize_t rc;
	while((rc = read(fd, val, sizeof(*val))) < 0)
		if(errno != EINTR)
			break;
	if(rc < 0)
		return _gen_err(FSQ_SYS_ERR);
	if(rc != sizeof(*val))
		return _gen_err(FSQ_INTERNAL_ERR);
	*val = be64toh(*val);
	return FSQ_OK; 
}

static int write_idx(int fd, uint64_t val)
{
	int rc;
	if(lseek(fd, 0, SEEK_SET))
		return _gen_err(FSQ_SYS_ERR);
	val = htobe64(val);
	while((rc = write(fd, &val, sizeof(val))) < 0)
		if(errno != EINTR)
			break;;
	if(rc < 0)
		return _gen_err(FSQ_SYS_ERR);
	if(rc != sizeof(val))
		return _gen_err(FSQ_INTERNAL_ERR);
	return FSQ_OK;
}


int fsq_init(struct fsq *q)
{
	int status = FSQ_OK;
	if((status = write_idx(q->wr_idx_fd, 0)))
		return status;
	if((status = write_idx(q->rd_idx_fd, 0)))
		return status;

	return status;
}

void fsq_close(struct fsq *q)
{
	if(q->dirfd >= 0)
		close(q->dirfd);

	if(q->rd_idx_fd >= 0)
		close(q->rd_idx_fd);

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
	int status = FSQ_OK;

	char *lock_name = NULL;
	if(type == LOCK_READ)
		lock_name = "rdlock";
	else
		lock_name = "wrlock";

	struct timespec ts;
	if(clock_gettime(CLOCK_REALTIME, &ts))
		return _gen_err(FSQ_SYS_ERR);

again:
	while(1) {
		struct stat sb;
			
		if(fstatat(q->dirfd, lock_name, &sb, 0)) {
			if(errno == ENOENT)
				break;
			status = _gen_err(FSQ_SYS_ERR);
			goto error;
		}
		usleep(POLL_INTERVAL_US);

		if(timeout) {
			if(clock_gettime(CLOCK_REALTIME, &ts))
				return _gen_err(FSQ_SYS_ERR);
	
			if(timespec_geq(ts, *timeout))
				return FSQ_TIMEOUT;
		}
	}

	int fd = openat(q->dirfd, lock_name, O_RDWR | O_CREAT | O_EXCL, 0644);
	if(fd < 0) {
		if(errno == EEXIST)
			goto again;

		status = _gen_err(FSQ_SYS_ERR);
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
	int status = FSQ_OK;

	char *lock_name = NULL;
	if(type == LOCK_READ)
		lock_name = "rdlock";
	else
		lock_name = "wrlock";

	if(unlinkat(q->dirfd, lock_name, 0))
		if(errno != ENOENT)
			status = _gen_err(FSQ_SYS_ERR);

	return status;
}

int fsq_enq(struct fsq *q, const char *buf, size_t buflen)
{
	int status = FSQ_OK;
	int fd = -1;

	if((status = fsq_lock(q, NULL, LOCK_WRITE))) // NB: will not timeout
		return status;

	uint64_t wr_idx;
	if((status = read_idx(q->wr_idx_fd, &wr_idx)))
		goto error;

	{
		char name[32];
		snprintf(name, sizeof(name), "%16.16" PRIx64, wr_idx);
		fd = openat(q->data_dirfd, name, O_CREAT | O_WRONLY, 0644);
		if(fd < 0) {
			status = _gen_err(FSQ_SYS_ERR);
			goto error;
		}
	}

	ssize_t wstatus = 0;
	while((wstatus = write(fd, buf, buflen)) < 0) {
		if(errno != EINTR)
			break;
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}
	if(wstatus < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}
	if(wstatus != (ssize_t)buflen) {
		status = _gen_err(FSQ_INTERNAL_ERR);
		goto error;
	}
	// in case of overwrite of existing data file
	if(ftruncate(fd, buflen)) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}

	if((status = write_idx(q->wr_idx_fd, wr_idx+1)))
		goto error;

	{
		struct timespec times[2] = {
			[0] = { .tv_sec = 0, .tv_nsec = UTIME_OMIT }, // atime
			[1] = { .tv_sec = 0, .tv_nsec = UTIME_NOW } // mtime
		};
		// since this is only advisory, ignore failures
		futimens(q->wr_idx_fd, times);
	}
	
done:
	status = fsq_unlock(q, LOCK_WRITE);

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
		if((status = fsq_lock(q, timeout, LOCK_READ)))
			return status;

		uint64_t wr_idx, rd_idx;
		if((status = read_idx(q->rd_idx_fd, &rd_idx)))
			goto error;

		if((status = read_idx(q->wr_idx_fd, &wr_idx)))
			goto error;
	
		if(wr_idx > rd_idx)
			break; // queue is not empty

		// queue empty: unlock and sleep
		if((status = fsq_unlock(q, LOCK_READ)))
			goto error;

		usleep(POLL_INTERVAL_US);

		if(timeout) {
			struct timespec ts;
			if(clock_gettime(CLOCK_REALTIME, &ts))
				return _gen_err(FSQ_SYS_ERR);
	
			if(timespec_geq(ts, *timeout))
				return FSQ_TIMEOUT;
		}
	}

	// map head of queue into memory

	{
		uint64_t rd_idx;
		if((status = read_idx(q->rd_idx_fd, &rd_idx))) {
			goto error;
		}

		char name[32];
		snprintf(name, sizeof(name), "%16.16" PRIx64, rd_idx);
	
		q->head_fd = openat(q->data_dirfd, name, O_RDONLY);
		if(q->head_fd < 0) {
			status = _gen_err(FSQ_SYS_ERR);
			goto error;
		}
	}

	{
		struct stat sb;
		if(fstat(q->head_fd, &sb)) {
			status = _gen_err(FSQ_SYS_ERR);
			goto error;
		}
		q->head_buflen = sb.st_size;
	}

	q->head_buf =
		mmap(NULL, q->head_buflen,
		     PROT_READ, MAP_SHARED,
		     q->head_fd, 0);
	if(q->head_buf == MAP_FAILED) {
		status = _gen_err(FSQ_SYS_ERR);
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
		return FSQ_OK;

	// advance queue read index

	uint64_t rd_idx;
	if((status = read_idx(q->rd_idx_fd, &rd_idx)))
		return status;

	if((status = write_idx(q->rd_idx_fd, rd_idx+1)))
		return status;

	// clean up stale queue head buffer

	munmap((char*)q->head_buf, q->head_buflen);
	q->head_buf = MAP_FAILED;
	q->head_buflen = 0;

	close(q->head_fd);
	q->head_fd = -1;

	// remove data file

	{
		char name[32];
		snprintf(name, sizeof(name), "%16.16" PRIx64, rd_idx);
		if(unlinkat(q->data_dirfd, name, 0)) {
			status = _gen_err(FSQ_SYS_ERR);
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
	int status = 0;
	// clean up lock
	if((status = fsq_unlock(q, LOCK_READ)))
		return status;
	if((status = fsq_unlock(q, LOCK_WRITE)))
		return status;
	return FSQ_OK;
}

int fsq_deq(struct fsq *q, struct timespec *timeout, char **buf, size_t *buflen)
{
	const char* temp_buf;
	int status = FSQ_OK;
	if((status = fsq_head(q, timeout, &temp_buf, buflen)))
		return status;

	*buf = malloc(*buflen);
	memcpy(*buf, temp_buf, *buflen);

	if((status = fsq_advance(q)))
		return status;

	return status;
}
