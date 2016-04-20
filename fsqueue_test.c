#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <fcntl.h>

#include "fsqueue.h"

void print_fsq_err(char *fn_name, int rc)
{
	switch(rc) {
	case FSQ_OK:
		break;
	case FSQ_TIMEOUT:
		fprintf(stderr, "%s() failed (timeout)\n", fn_name); break;
	case FSQ_SYS_ERR:
		fprintf(stderr, "%s() failed (errno=%d: %s)\n",
		       fn_name, errno, strerror(errno));
		break;
	case FSQ_INTERNAL_ERR:
		fprintf(stderr, "%s() failed (internal err)\n", fn_name); break;
	case FSQ_USER_ERR:
		fprintf(stderr, "%s() failed (user err)\n", fn_name); break;
	case FSQ_IN_USE:
		fprintf(stderr, "%s() failed (already in use)\n", fn_name); break;
	default:
		fprintf(stderr, "%s() failed error=%d\n", fn_name, rc); break;
	}
}

size_t fcopy(FILE *outstream, FILE *instream)
{
	size_t n, count = 0;
	char temp[1024];
	while((n = fread(temp, 1, sizeof(temp), instream))) {
		size_t m = fwrite(temp, 1, n, outstream);
		count += m;
		if(m == 0)
			break;
	}
	return count;
}

int spew_buf(int dirfd, char *path, char *buf, size_t len)
{
	FILE *stream;
	int fd = openat(dirfd, path, O_WRONLY | O_CREAT, 0644);
	if(fd < 0)
		return -1;
	stream = fdopen(fd, "wb");
	if(! stream)
		return -1;
	size_t count = fwrite(buf, 1, len, stream);
	fclose(stream);
	return count;
}

int slurp_buf(int dirfd, char *path, char **buf, size_t *len)
{
	FILE *instream, *outstream;
	outstream = open_memstream(buf, len);
	if(! outstream)
		return -1;

	int fd = openat(dirfd, path, O_RDONLY);
	if(fd < 0)
		return -1;
	instream = fdopen(fd, "rb");
	
	size_t count = fcopy(outstream, instream);

	fclose(outstream);
	fclose(instream);

	return count;
}

int main(int argc, char *argv[])
{
	if(argc != 4) {
usage:
		fprintf(stderr, "usage: %s <queue> {source|dest} <iters>\n", argv[0]);
		return 1;
	}

	char *queuename = argv[1];
	char *mode = argv[2];
	char *iters_str = argv[3];
	
	char *endp;
	unsigned long iters = strtoul(iters_str, &endp, 0);
	if(*endp) {
		fprintf(stderr, "bad <iters>: %s\n", iters_str);
		goto usage;
	}

	if(strcmp(mode, "source") == 0) {
		struct fsq_produce q;
		int rc = fsq_produce_open(&q, queuename);
		if(rc) {
			print_fsq_err("fsq_produce_open", rc);
			return 1;
		}

		for(uint32_t i = 0; i < iters; i++) {
			int dirfd;
			char fname[FSQ_PATH_LEN];
			if((rc = fsq_tail_file(&q, &dirfd, fname))) {
				print_fsq_err("fsq_tail_file", rc);
				return 1;
			}

			if(0 >= spew_buf(dirfd, fname, (char*)&i, sizeof(i))) {
				perror("spew_buf()");
				return 1;
			}

			if((rc = fsq_tail_advance(&q))) {
				print_fsq_err("fsq_tail_advance", rc);
				return 1;
			}
		}

		fsq_produce_close(&q);
	} else if(strcmp(mode, "dest") == 0) {
		struct fsq_consume q;
		int rc = fsq_consume_open(&q, queuename);
		if(rc) {
			print_fsq_err("fsq_consume_open", rc);
			return 1;
		}


		for(uint32_t i = 0; i < iters; i++) {
			char *buf = NULL;
			size_t buflen = 0;

			int dirfd;
			char fname[FSQ_PATH_LEN];
			int rc = fsq_head_file(&q, 0, NULL, &dirfd, fname);
			if(rc) {
				print_fsq_err("fsq_head_file", rc);
				return 1;
			}

			if(0 >= slurp_buf(dirfd, fname, &buf, &buflen)) {
				perror("slurp_buf()");
				return 1;
			}

			if(*(uint32_t *)buf != i) {
				fprintf(stderr, "got %" PRId32 ", expected %" PRId32 "\n",
				        *(uint32_t *)buf, i);
				return 1;
			}
			rc = fsq_head_advance(&q);
			if(rc) {
				print_fsq_err("fsq_head_advance", rc);
				return 1;
			}
		}

		fsq_consume_close(&q);
	} else {
		fprintf(stderr, "bad mode: %s\n", mode);
		goto usage;
	}
}
