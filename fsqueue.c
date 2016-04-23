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

#define RD_IDX_NAME "rd_idx"
#define WR_IDX_NAME "wr_idx"
#define RD_LOCK_NAME "rd_lock"
#define WR_LOCK_NAME "wr_lock"
#define DATA_DIR_NAME "data"

static int __attribute__((noinline)) _gen_err(int val)
{
	return val;
}

static void fsq_produce_struct_init(struct fsq_produce *q)
{
	q->dirfd = -1;
	q->data_dirfd = -1;
}

// NB: must also call fsq_produce_struct_init()
static void fsq_consume_struct_init(struct fsq_consume *q)
{
	(void)q;
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

	close(fd);
	return status;
}

void *watch_thread_fn(void *arg)
{
	struct dir_watch_info *info = (struct dir_watch_info*)arg;
	union {
		struct inotify_event evt;
		char padding[sizeof(struct inotify_event) + NAME_MAX + 1];
	} evtbuf;
	ssize_t len = sizeof(evtbuf.padding);

	while(1) {
		ssize_t rc;
		evtbuf.evt.mask = 0;
		if(0 < (rc = read(info->inotify_evt_q, &evtbuf, len))) {
			if(evtbuf.evt.mask & IN_CLOSE_WRITE) {
				int oldstate;
				pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

				pthread_mutex_lock(&info->update_mux);
				info->updated = 1;
				pthread_cond_signal(&info->update_cond);
				pthread_mutex_unlock(&info->update_mux);

				pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
			}
		}
	}

	return NULL;
}

static void _common_close(struct fsq_produce *q)
{
	if(q->dirfd >= 0)
		close(q->dirfd);

	if(q->data_dirfd >= 0)
		close(q->data_dirfd);
}

static int _common_open(struct fsq_produce *q, const char *path)
{
	int status = FSQ_OK;

	fsq_produce_struct_init(q);

	q->dirfd = open(path, O_RDONLY | O_DIRECTORY);
	if(q->dirfd < 0) {
		status = _gen_err(FSQ_USER_ERR);
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

done:
	return status;

error:
	_common_close(q);
	goto done;
}

static int _lock(struct fsq_produce *q, char *which)
{
	int status = FSQ_OK;

	int fd = openat(
		q->dirfd, which, O_CREAT | O_WRONLY | O_EXCL, 0644);
	if(fd < 0) {
		if(errno == EEXIST)
			status = _gen_err(FSQ_IN_USE);
		else
			status = _gen_err(FSQ_SYS_ERR);
	} else {
		close(fd);
	}

	return status;
}

static void _unlock(struct fsq_produce *q, char *which)
{
	unlinkat(q->dirfd, which, 0);
}

int fsq_produce_open(struct fsq_produce *q, const char *path)
{
	int status = FSQ_OK;

	if((status = _common_open(q, path)))
		return status;

	if((status = _lock(q, WR_LOCK_NAME)))
		goto error;

done:
	return status;

error:
	_common_close(q);
	goto done;
}

void fsq_produce_close(struct fsq_produce *q)
{
	_unlock(q, WR_LOCK_NAME);
	_common_close(q);
}

static int _dir_watch_reset(struct dir_watch_info *info)
{
	int status = FSQ_OK;

	if(info->watch_thread_created) {
		pthread_cancel(info->watch_thread);
		pthread_join(info->watch_thread, NULL);
	}

	if(info->inotify_wd >= 0)
		inotify_rm_watch(info->inotify_evt_q, info->inotify_wd);

	if(info->inotify_evt_q >= 0)
		close(info->inotify_evt_q);

	pthread_mutex_destroy(&info->update_mux);
	pthread_cond_destroy(&info->update_cond);

	return status;
}

static int _dir_watch_init(struct dir_watch_info *info, const char *path)
{
	int status = FSQ_OK;

	info->inotify_evt_q = -1;
	info->inotify_wd = -1;
	info->watch_thread_created = 0;
	info->updated = 0;

	pthread_mutex_init(&info->update_mux, NULL);
	pthread_cond_init(&info->update_cond, NULL);

	info->inotify_evt_q = inotify_init();
	if(info->inotify_evt_q < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}

	info->inotify_wd =
		inotify_add_watch(info->inotify_evt_q, path, IN_CLOSE_WRITE);
	if(info->inotify_wd < 0) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}

	if(pthread_create(&info->watch_thread, NULL, watch_thread_fn, info)) {
		status = _gen_err(FSQ_SYS_ERR);
		goto error;
	}
	info->watch_thread_created = 1;

done:
	return status;

error:
	_dir_watch_reset(info);
	goto done;
}

int fsq_consume_open(struct fsq_consume *q, const char *path)
{
	int status = FSQ_OK;

	fsq_consume_struct_init(q);

	if((status = _common_open(&q->hdr, path)))
		return status;

	if((status = _lock(&q->hdr, RD_LOCK_NAME)))
		goto error;

	if((status = _dir_watch_init(&q->watch, path)))
		goto error;

done:
	return status;

error:
	fsq_consume_close(q);
	goto done;
}

void fsq_consume_close(struct fsq_consume *q)
{
	_dir_watch_reset(&q->watch);

	_unlock(&q->hdr, RD_LOCK_NAME);

	_common_close(&q->hdr);
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

int fsq_enq_buf(struct fsq_produce *q, const char *buf, size_t buflen)
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

int fsq_tail_file(struct fsq_produce *q, int *dirfd, char *path)
{
	int status = FSQ_OK;

	uint64_t wr_idx;
	if((status = get_idx(q->dirfd, WR_IDX_NAME, &wr_idx)))
		return status;

	*dirfd = q->data_dirfd;
	snprintf(path, FSQ_PATH_LEN, "%16.16" PRIx64, wr_idx);

	return status;
}

int fsq_tail_advance(struct fsq_produce *q)
{
	int status = FSQ_OK;
	uint64_t wr_idx;
	if((status = get_idx(q->dirfd, WR_IDX_NAME, &wr_idx)))
		return status;
	return set_idx(q->dirfd, WR_IDX_NAME, wr_idx+1);
}

int fsq_len(struct fsq_produce *q, uint64_t *len)
{
	int status = FSQ_OK;
	uint64_t rd_idx, wr_idx;

	if((status = get_idx(q->dirfd, RD_IDX_NAME, &rd_idx)))
		return status;

	if((status = get_idx(q->dirfd, WR_IDX_NAME, &wr_idx)))
		return status;

	*len = (wr_idx - rd_idx);
	return FSQ_OK;
}

struct consume_ready_args {
	struct fsq_consume *q;
	uint64_t off;
	uint64_t rd_idx;
};

static int consume_ready(void *_arg, _Bool *met)
{
	int status = FSQ_OK;

	struct consume_ready_args *args = (struct consume_ready_args *) _arg;
	if((status = get_idx(args->q->hdr.dirfd, RD_IDX_NAME, &args->rd_idx)))
		return status;

	uint64_t wr_idx;
	if((status = get_idx(args->q->hdr.dirfd, WR_IDX_NAME, &wr_idx)))
		return status;

	if(wr_idx > args->rd_idx + args->off)
		*met = 1;
	else
		*met = 0;

	return status;
}

static int _watch_condition_wait(
	struct dir_watch_info *info,
	int (*test_fn)(void *arg, _Bool *met), void *arg,
	struct timespec *timeout)
{
	int status = FSQ_OK;

	while(status == FSQ_OK) {
		_Bool met = 0;
		if((status = test_fn(arg, &met)))
			break;
		if(met)
			break;

		pthread_mutex_lock(&info->update_mux);
		while(status == FSQ_OK) {
			if(info->updated) {
				// ack update and retry test
				info->updated = 0;
				break;
			}
			if(! timeout) {
				pthread_cond_wait(&info->update_cond, &info->update_mux);
			} else {
				pthread_cond_timedwait(&info->update_cond, &info->update_mux, timeout);
				struct timespec ts;
				if(clock_gettime(CLOCK_REALTIME, &ts)) {
					status = _gen_err(FSQ_SYS_ERR);
				} else if(timespec_geq(ts, *timeout)) {
					status = FSQ_TIMEOUT;
				}
			}
		}
		pthread_mutex_unlock(&info->update_mux);
	}

	return status;
}

int fsq_head_file(
	struct fsq_consume *q, uint64_t off, struct timespec *timeout,
	int *dirfd, char *path)
{
	int status = FSQ_OK;

	// wait for queue elements
	struct consume_ready_args args = { .q = q, .off = off, .rd_idx = 0 };
	if((status = _watch_condition_wait(&q->watch, consume_ready, &args, timeout)))
		return status;

	snprintf(path, FSQ_PATH_LEN, "%16.16" PRIx64, args.rd_idx);
	*dirfd = q->hdr.data_dirfd;

	return FSQ_OK;
}

int fsq_head_advance(struct fsq_consume *q)
{
	int status = FSQ_OK;

	// advance queue read index
	uint64_t rd_idx, wr_idx;
	if((status = get_idx(q->hdr.dirfd, RD_IDX_NAME, &rd_idx)))
		return status;
	if((status = get_idx(q->hdr.dirfd, WR_IDX_NAME, &wr_idx)))
		return status;
	if(rd_idx >= wr_idx)
		return FSQ_EMPTY;

	if((status = set_idx(q->hdr.dirfd, RD_IDX_NAME, rd_idx+1)))
		return status;

	// remove data file
	char name[32];
	snprintf(name, sizeof(name), "%16.16" PRIx64, rd_idx);
	if(unlinkat(q->hdr.data_dirfd, name, 0))
		status = _gen_err(FSQ_SYS_ERR);

	return status;
}
