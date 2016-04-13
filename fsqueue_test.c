#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

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
	default:
		fprintf(stderr, "%s() failed error=%d\n", fn_name, rc); break;
	}
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
			int rc = fsq_enq(&q, (char*)&i, sizeof(i));
			if(rc) {
				print_fsq_err("fsq_enq", rc);
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
			const char *buf;
			size_t buflen;
			int rc = fsq_head(&q, NULL, &buf, &buflen);
			if(rc) {
				print_fsq_err("fsq_head", rc);
				return 1;
			}
			if(*(uint32_t *)buf != i) {
				fprintf(stderr, "got %" PRId32 ", expected %" PRId32 "\n",
				        *(uint32_t *)buf, i);
				return 1;
			}
			rc = fsq_advance(&q);
			if(rc) {
				print_fsq_err("fsq_advance", rc);
				return 1;
			}
		}

		fsq_consume_close(&q);
	} else {
		fprintf(stderr, "bad mode: %s\n", mode);
		goto usage;
	}
}
