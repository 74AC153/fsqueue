OUTBINS=fsqueue.so fsq fsqueue_test

default: all
all: ${OUTBINS}

CFLAGS=-Wall -Wextra -g3 --std=c99 -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE
LIBS=-lrt -lpthread

fsqueue.so: fsqueue.c
	gcc ${CFLAGS} ${LIBS} -fPIC -shared -o $@ $^

fsq: fsq.c fsqueue.c 
	gcc ${CFLAGS} ${LIBS} -o $@ $^

fsqueue_test: fsqueue_test.c fsqueue.c
	gcc ${CFLAGS} ${LIBS} -o $@ $^

clean:
	-rm ${OUTBINS}
