###############################################################################
#Author: Samuel Jero
#
# Date: 3/2013
#
# Makefile for program strip6in4
###############################################################################

CFLAGS= -O2 -Wall -Werror -g

# for solaris, you probably want:
#	LDLIBS = -lpcap -lnsl -lsocket
# for HP, I'm told that you need:
#	LDLIBS = -lpcap -lstr
# everybody else (that I know of) just needs:
#	LDLIBS = -lpcap
LDLIBS = -lpcap

BINDIR = /usr/local/bin
MANDIR = /usr/local/man


all: strip6in4 
#strip6in4.1

strip6in4: strip6in4.o encap.o
	gcc ${CFLAGS} --std=gnu99 strip6in4.o encap.o -ostrip6in4 ${LDLIBS}

strip6in4.o: strip6in4.h strip6in4.c
	gcc ${CFLAGS} ${LDLIBS} --std=gnu99 -c strip6in4.c -ostrip6in4.o

encap.o: encap.c strip6in4.h encap.h
	gcc ${CFLAGS} ${LDLIBS} --std=gnu99 -c encap.c -oencap.o

#strip6in4.1: strip6in4.pod
#	pod2man -s 1 -c "strip6in4" strip6in4.pod > strip6in4.1

install: strip6in4
	install -m 755 -o bin -g bin strip6in4 ${BINDIR}/strip6in4
#	install -m 444 -o bin -g bin strin6in4 ${MANDIR}/man1/strip6in4.1

uninstall:
	rm -f ${BINDIR}/strip6in4
	rm -f ${MANDIR}/man1/strip6in4.1

clean:
	rm -f *~ strip6in4 core *.o strip6in4.1
