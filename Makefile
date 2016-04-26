OUTBINS=fsqueue.o libfsqueue.so fsq fsqueue_test

default: all
all: ${OUTBINS}

#COVERAGE=-coverage
CFLAGS=-Wall -Wshadow -Wextra -g3 --std=c99 -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE ${COVERAGE}
LIBS=-lrt -lpthread

fsqueue.o: fsqueue.c
	gcc ${CFLAGS} -fPIC -c -o $@ $^

libfsqueue.so: fsqueue.o
	gcc ${LIBS} -shared -o $@ $^

fsq: fsq.c fsqueue.o 
	gcc ${CFLAGS} ${LIBS} -o $@ $^

fsqueue_test: fsqueue_test.c fsqueue.o
	gcc ${CFLAGS} ${LIBS} -o $@ $^

testqueue:
	-mkdir testqueue

test: fsq fsqueue_test testqueue
	-./fsq -q testqueue -w 1000 -d --
	./fsq -q testqueue -w 2000 -d -- &
	sleep 1
	echo "OK" | ./fsq -q testqueue -e --
	sleep 1
	./fsqueue_test testqueue dest 1000 &
	./fsqueue_test testqueue source 1000

coverage_report: fsqueue.gcno
	gcov fsqueue.gcno

clean:
	-rm -r ${OUTBINS} *.gcda *.gcno testqueue
