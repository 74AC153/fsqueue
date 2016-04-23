#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

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

static struct timespec timespec_add(struct timespec x, struct timespec y)
{
	struct timespec ret = {0, 0};

	ret.tv_nsec = x.tv_nsec + y.tv_nsec;
	if(ret.tv_nsec > 1000000000) {
		ret.tv_sec++;
		ret.tv_nsec -= 1000000000;
	}
	ret.tv_sec += x.tv_sec + y.tv_sec;

	return ret;
}

static struct timespec timespec_ms(unsigned long ms)
{
	struct timespec ret = {
		.tv_sec = ms / 1000, 
		.tv_nsec = (ms % 1000) * 1000000
	};
	return ret;
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

int main(int argc, char *argv[])
{
	int status = 0;


	char *qname = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	char *wait_ms_str = NULL;
	unsigned long wait_ms = -1UL;

	int rc;

	int opt = -1;
	if(argc == 1)
		goto usage;
	while((opt = getopt(argc, argv, "q:w:e:d:h")) != -1) {
		switch(opt) {
			default:
			case 'h':
usage:
				printf("usage: %s -q <queue> [-w <wait-ms>] [-e <infile> | -d <outfile>]\n", argv[0]);
				printf("omit -e and -d to create queue only.\n");
				printf("if <infile> or <outfile> are \"--\", use stdin/stdout.\n");
				printf("if -w <wait-ms> is omitted, wait forever.\n");
				printf("exit code 1 on error, 2 on timeout\n");
				return opt != 'h';
			case 'q':
				qname = optarg;
				break;
			case 'e':
				infile = optarg;
				break;
			case 'd':
				outfile = optarg;
				break;	
			case 'w':
				wait_ms_str = optarg;
				break;
		}
	}

	if(qname == NULL) {
		fprintf(stderr, "error: -q <queue> required\n");
		goto usage;
	}

	if(wait_ms_str) {
		char *endptr;
		errno = 0;
		wait_ms = strtoul(wait_ms_str, &endptr, 0);
		if((endptr == wait_ms_str) ||
		   (wait_ms == 0 && errno == ERANGE) ||
		   (errno == EINVAL)) {
			fprintf(stderr, "error: <wait-ms> must be positive integer: %s\n",
			        wait_ms_str);
			goto usage;
		}
	}

	if(outfile && infile) {
		fprintf(stderr, "error: only one of -e <infile> or -d <outfile> allowed\n");
		goto usage;
	}

	if(infile) {
		struct fsq_produce q;
		char fname[FSQ_PATH_LEN];
		int dirfd;

		if((rc = fsq_produce_open(&q, qname))) {
			print_fsq_err("fsq_produce_open", rc);
			return 1;
		}

		if((rc = fsq_tail_file(&q, 0, NULL, &dirfd, fname))) {
			print_fsq_err("fsq_tail_file", rc);
			status = 1;
			goto produce_done;
		}

		if(strcmp(infile, "--") == 0) {
			FILE *outstream;
			int fd = openat(dirfd, fname, O_WRONLY | O_CREAT, 0644);
			if(fd < 0) {
				perror("openat()");
				status = 1;
				goto produce_done;
			}
			outstream = fdopen(fd, "wb");
			if(! outstream) {
				perror("fdopen()");
				status = 1;
				goto produce_done;
			}
			fcopy(outstream, stdin);
			fclose(outstream);
		} else {
			if(linkat(AT_FDCWD, infile, dirfd, fname, 0)) {
				perror("linkat()");
				status = 1;
				goto produce_done;
			}
		}

		if((rc = fsq_tail_advance(&q))) {
			print_fsq_err("fsq_tail_advance", rc);
			status = 1;
			goto produce_done;
		}

produce_done:
		fsq_produce_close(&q);

	} else if(outfile) {
		struct fsq_consume q;
		struct timespec now, timeout, *ptimeout = NULL;
		char fname[FSQ_PATH_LEN];
		int dirfd;

		if((rc = fsq_consume_open(&q, qname))) {
			print_fsq_err("fsq_consume_open", rc);
			return 1;
		}

		if(wait_ms_str) {
			if(clock_gettime(CLOCK_REALTIME, &now)) {
				perror("clock_gettime()");
				status = 1;
				goto produce_done;
			}
			timeout = timespec_add(now, timespec_ms(wait_ms));
			ptimeout = &timeout;
		}

		rc = fsq_head_file(&q, 0, ptimeout, &dirfd, fname);
		if(rc == FSQ_TIMEOUT) {
			status = 2;
			goto consume_done;
		}
		if(rc) {
			print_fsq_err("fsq_head_file", rc);
			status =  1;
			goto consume_done;
		}

		if(strcmp(outfile, "--") == 0) {
			FILE *instream;
			int fd = openat(dirfd, fname, O_RDONLY);
			if(fd < 0) {
				perror("openat()");
				status = 1;
				goto produce_done;
			}
			instream = fdopen(fd, "rb");
			if(! instream) {
				perror("fdopen()");
				status = 1;
				goto produce_done;
			}
			fcopy(stdout, instream);
			fclose(instream);
		} else if(linkat(dirfd, fname, AT_FDCWD, outfile, 0)) {
			perror("linkat()");
			status = 1;
			goto consume_done;
		}

		rc = fsq_head_advance(&q);
		if(rc) {
			print_fsq_err("fsq_advance", rc);
			status = 1;
			goto consume_done;
		}

consume_done:
		fsq_consume_close(&q);
	}

	return status;
}
