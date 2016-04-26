# FSQueue

A small library to implement a single-producer / single-consumer filesystem-
backed queue.

Useful for:

- IPC that can survive a reboot.
- message queues on top of a network file system.

# How to use:

    #include "fsqueue.h"
    
    struct fsq q;
    char filename[FSQ_PATH_LEN];
    int dirfd;
    FILE *stream;
    int streamfd;
    int ch;
    
    // create & open the queue as both a producer and consumer
    mkdir("/var/queues/foo", 0755);
    fsq_open(&q, "/var/queues/foo", FSQ_PRODUCE | FSQ_CONSUME);
    
    // get the next queue entry to write to
    fsq_tail_file(&q, 0, NULL, &dirfd, filename);
    streamfd = openat(dirfd, filename, O_CREAT | O_WRONLY);
	 stream = fdopen(streamfd, "wb");
    fprintf(stream, "hello world");
    fclose(stream);
    fsq_tail_advance(&q);
    
    // get the next queue entry to read from
    fsq_head_file(&q, 0, NULL, &dirfd, filename);
    streamfd = openat(dirfd, filename, O_RDONLY)
    stream = fdopen(streamfd, "rb");
    while(EOF != (ch = fgetc(stream)))
		fputc(ch, stdout);
    fclose(stream);
    fsq_head_advance(&q);
    
    // done
    fsq_close(&q);
