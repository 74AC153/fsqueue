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
#include <sys/inotify.h>
#include <limits.h>

#include "fsqueue.h"

#define FSQ_OK 0
#define FSQ_TIMEOUT -1
#define FSQ_SYS_ERR -2
#define FSQ_INTERNAL_ERR -3
#define FSQ_USER_ERR -4
#define FSQ_NOENT -5

#define RD_IDX_NAME "rd_idx"
#define WR_IDX_NAME "wr_idx"
#define DATA_DIR_NAME "data"

static int __attribute__((noinline)) _gen_err(int val)
{
	return val;
}

static void fsq_struct_init(struct fsq *q)
{
	q->dirfd = -1;

	q->data_dirfd = -1;

	q->head_fd = -1;
	q->head_buf = MAP_FAILED;
	q->head_buflen = 0;

	q->inotify_evt_q = -1;
	q->inotify_wr_idx_wd = -1;
	//pthread_t watch_thread;
	q->watch_thread_created = 0;
	q->wr_idx_updated = 0;
	pthread_mutex_init(&q->update_mux, NULL);
	pthread_cond_init(&q->update_cond, NULL);
}

static int get_idx(int dirfd, const char *path, uint64_t *val)
{
	int status = FSQ_OK;

	int fd = openat(dirfd, path, O_RDONLY);
	if(fd < 0) {
		if(errno == ENOENT) {
			*val = 0;
			return FSQ_OK;
		}
		return _gen_err(FSQ_SYS_ERR);
	}

	ssize_t rc;
	while((rc = read(fd, val, sizeof(*val))) < 0)
		if(errno != EINTR)
			break;
	if(rc < 0) {
		status = _gen_err(FSQ_SYS_ERR);
	} else if(rc != sizeof(*val)) {
		status = _gen_err(FSQ_INTERNAL_ERR);
	} else {
		*val = be64toh(*val);
	}

	close(fd);
	return status; 
}

static int set_idx(int dirfd, const char *path, uint64_t val)
{
	int status = FSQ_OK;
	int rc;

	int fd = openat(dirfd, path, O_WRONLY | O_CREAT, 0644);
	if(fd < 0)
		return _gen_err(FSQ_SYS_ERR);

	val = htobe64(val);
	while((rc = write(fd, &val, sizeof(val))) < 0)
		if(errno != EINTR)
			break;;
	if(rc < 0)
		status = _gen_err(FSQ_SYS_ERR);
	else if(rc != sizeof(val))
		status = _gen_err(FSQ_INTERNAL_ERR);

	return status;
}

void *watch_thread_fn(void *arg)
{
	struct fsq *q = (struct fsq *)arg;
	union {
		struct inotify_event evt;
		char padding[sizeof(struct inotify_event) + NAME_MAX + 1];
	} evtbuf;
	ssize_t len = sizeof(evtbuf.padding);

	while(1) {
		ssize_t rc;
		evtbuf.evt.mask = 0;
		if(0 < (rc = read(q->inotify_evt_q, &evtbuf, len))) {
			if(evtbuf.evt.mask & IN_CLOSE_WRITE) {
				int oldstate;
				pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

				pthread_mutex_lock(&q->update_mux);
				q->wr_idx_updated = 1;
				pthread_cond_signal(&q->update_cond);
				pthread_mutex_unlock(&q->update_mux);

				pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
			}
		}
	}

	return NULL;
}

int fsq_open(struct fsq *q, const char *path)
{
	int status = 0;

	fsq_struct_init(q);

	q->dirfd = open(path, O_RDONLY | O_DIRECTORY);
	if(q->dirfd < 0) {
		status = _gen_err(FSQ_USER_ERR);
		goto error;
	}

	q->inotify_evt_q = inotify_init();
	if(q->inotify_evt_q < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}
	q->inotify_wr_idx_wd =
		inotify_add_watch(q->inotify_evt_q, path, IN_CLOSE_WRITE);
	if(q->inotify_wr_idx_wd < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}

	if(mkdirat(q->dirfd, DATA_DIR_NAME, 0755)) {
		if(errno != EEXIST) {
			status = _gen_err(FSQ_SYS_ERR);
			goto error;
		}
	}

	q->data_dirfd = openat(q->dirfd, DATA_DIR_NAME, O_RDONLY | O_DIRECTORY);
	if(q->data_dirfd < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}

	if(pthread_create(&q->watch_thread, NULL, watch_thread_fn, q)) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}

done:
	return status;

error:
	fsq_close(q);
	goto done;
}

void fsq_close(struct fsq *q)
{
	if(q->dirfd >= 0)
		close(q->dirfd);

	if(q->data_dirfd >= 0)
		close(q->data_dirfd);

	if(q->head_buf != MAP_FAILED)
		munmap((char*)q->head_buf, q->head_buflen);

	if(q->head_fd >= 0)
		close(q->head_fd);

	if(q->watch_thread_created) {
		pthread_cancel(q->watch_thread);
		pthread_join(q->watch_thread, NULL);
	}

	if(q->inotify_wr_idx_wd >= 0)
		inotify_rm_watch(q->inotify_evt_q, q->inotify_wr_idx_wd);

	if(q->inotify_evt_q >= 0)
		close(q->inotify_evt_q);
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

int fsq_enq(struct fsq *q, const char *buf, size_t buflen)
{
	int status = FSQ_OK;
	int fd = -1;

	uint64_t wr_idx;
	if((status = get_idx(q->dirfd, WR_IDX_NAME, &wr_idx)))
		return status;

	{
		char name[32];
		snprintf(name, sizeof(name), "%16.16" PRIx64, wr_idx);
		fd = openat(q->data_dirfd, name, O_CREAT | O_WRONLY, 0644);
		if(fd < 0)
			return _gen_err(FSQ_SYS_ERR);
	}

	ssize_t wstatus = 0;
	while((wstatus = write(fd, buf, buflen)) < 0) {
		if(errno != EINTR)
			break;
		status = _gen_err(FSQ_SYS_ERR);
		goto done;
	}
	if(wstatus < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto done;
	} else if(wstatus != (ssize_t)buflen) {
		status = _gen_err(FSQ_INTERNAL_ERR);
		goto done;
	}
	// in case of overwrite of existing data file
	if(ftruncate(fd, buflen)) {
		status = _gen_err(FSQ_SYS_ERR);
		goto done;
	}

done:
	if(fd >= 0)
		close(fd);

	if(status == FSQ_OK)
		return set_idx(q->dirfd, WR_IDX_NAME, wr_idx+1);
	else
		return status;
}

int fsq_head(struct fsq *q, struct timespec *timeout, const char **buf, size_t *buflen)
{
	int status = FSQ_OK;

	// short-circut repeated calls to fsq_head without an fsq_advance between
	if(q->head_fd >= 0) {
		*buf = q->head_buf;
		*buflen = q->head_buflen;
		return 0;
	}

	// wait for queue elements

	while(status == FSQ_OK) {
		uint64_t wr_idx, rd_idx;
		if((status = get_idx(q->dirfd, RD_IDX_NAME, &rd_idx)))
			break;

		if((status = get_idx(q->dirfd, WR_IDX_NAME, &wr_idx)))
			break;
	
		if(wr_idx > rd_idx)
			break; // queue has elements -- no waiting necessary

		pthread_mutex_lock(&q->update_mux);
		while(status == FSQ_OK) {
			if(q->wr_idx_updated) {
				q->wr_idx_updated = 0;
				break;
			}
			if(! timeout) {
				pthread_cond_wait(&q->update_cond, &q->update_mux);
			} else {
				pthread_cond_timedwait(&q->update_cond, &q->update_mux, timeout);
				struct timespec ts;
				if(clock_gettime(CLOCK_REALTIME, &ts)) {
					status = _gen_err(FSQ_SYS_ERR);
				} else if(timespec_geq(ts, *timeout)) {
					status = FSQ_TIMEOUT;
				}
			}
		}
		pthread_mutex_unlock(&q->update_mux);
	}
	if(status != FSQ_OK)
		return status;

	// map head of queue into memory

	{
		uint64_t rd_idx;
		if((status = get_idx(q->dirfd, RD_IDX_NAME, &rd_idx)))
			goto error;

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
	if((status = get_idx(q->dirfd, RD_IDX_NAME, &rd_idx)))
		return status;
	if((status = set_idx(q->dirfd, RD_IDX_NAME, rd_idx+1)))
		return status;

	// clean up stale queue head buffer
	munmap((char*)q->head_buf, q->head_buflen);
	q->head_buf = MAP_FAILED;
	q->head_buflen = 0;
	close(q->head_fd);
	q->head_fd = -1;

	// remove data file
	char name[32];
	snprintf(name, sizeof(name), "%16.16" PRIx64, rd_idx);
	if(unlinkat(q->data_dirfd, name, 0)) {
		status = _gen_err(FSQ_SYS_ERR);
	}

	return status;
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
