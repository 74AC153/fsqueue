#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "fsqueue.h"

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
	if(argc == 1)
		goto usage;

	char *qname = NULL;
	char *infile = NULL;
	char *outfile = NULL;

	struct fsq q;
	int rc;
	char *buf = NULL;
	size_t buflen = 0;
	FILE *bufstream = NULL;

	int opt;
	while((opt = getopt(argc, argv, "q:e:d:h")) != -1) {
		switch(opt) {
			default:
			case 'h':
usage:
				printf("usage: %s -q <queue> [-e <infile> | -d <outfile>]\n", argv[0]);
				printf("omit -e and -d to create queue\n");
				printf("if <infile> or <outfile> are \"--\", use stdin/stdout\n");
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
		}
	}

	if(qname == NULL) {
		fprintf(stderr, "error: -q <queue> required\n");
		goto usage;
	}

	if(outfile && infile) {
		fprintf(stderr, "error: only one of -e <infile> or -d <outfile> allowed\n");
		goto usage;
	}

	if((rc = fsq_openat(AT_FDCWD, qname, &q))) {
		fprintf(stderr, "error: fsq_openat() returned %d (errno=%d, %s)\n",
		        rc, errno, strerror(errno));
		return 1;
	}

	if(infile) {
		FILE *instream = NULL;

		if(strcmp(infile, "--") == 0)
			instream = stdin;
		else
			instream = fopen(infile, "rb");

		if(! instream) {
			perror("error: fopen(<infile>)");
			return 1;
		}

		bufstream = open_memstream(&buf, &buflen);
		fcopy(bufstream, instream);
		fclose(bufstream);
		if(instream != stdin)
			fclose(instream);

		if((rc = fsq_enq(&q, buf, buflen))) {
			fprintf(stderr, "error: fsq_enq() returned %d (errno=%d, %s)\n",
			        rc, errno, strerror(errno));
			return 1;
		}

		free(buf);

	} else if(outfile) {
		FILE *outstream = NULL;

		if(strcmp(outfile, "--") == 0)
			outstream = stdout;
		else
			outstream = fopen(outfile, "wb");

		if(! outstream) {
			perror("error: fopen(<outfile>)");
			return 1;
		}

		if((rc = fsq_deq(&q, -1U, &buf, &buflen))) {
			if(rc != -1)
				fprintf(stderr, "error: fsq_deq() returned %d (errno=%d, %s)\n",
				        rc, errno, strerror(errno));
			return 1;
		}

		bufstream = fmemopen(buf, buflen, "rb");
		fcopy(outstream, bufstream);
		fclose(bufstream);
		if(outstream != stdout)
			fclose(outstream);

		free(buf);

	} else {
		if((rc = fsq_init(&q))) {
			fprintf(stderr, "error: fsq_init() returned %d (errno=%d, %s)\n",
			        rc, errno, strerror(errno));
			return 1;
		}
	}

	fsq_close(&q);

	return 0;
}
