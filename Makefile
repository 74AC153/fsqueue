OUTBINS=fsqueue.so fsq

default: all
all: ${OUTBINS}

fsqueue.so: fsqueue.c
	gcc -Wall -Wextra -g3 --std=c99 -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE -fPIC -shared -lrt -o $@ $^

fsq: fsqueue.c fsq.c
	gcc -Wall -Wextra -g3 --std=c99 -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE -lrt -o $@ $^

clean:
	-rm ${OUTBINS}
