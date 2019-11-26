CFLAGS = -Wall -m64 -ggdb -I.
CC = cc
TARGET = mmcomm
BINPATH = /usr/local/bin


all : mmcomm

mmcomm : mmcomm.o addrinfo_debug.o addrinfo_debug.h socktalk.o
	${CC} -o ${TARGET} mmcomm.o addrinfo_debug.o socktalk.o -lreadini -lssl -lcrypto -lcode64

mmcomm.o : mmcomm.c addrinfo_debug.h
	${CC} ${CFLAGS} -c -o mmcomm.o mmcomm.c

socktalk.o : socktalk.c socktalk.h
	$(CC) $(CFLAGS) -c -o socktalk.o socktalk.c

addrinfo_debug.o : addrinfo_debug.h addrinfo_debug.c
	${CC} ${CFLAGS} -c -o addrinfo_debug.o addrinfo_debug.c

install :
	cp -f ${TARGET} ${BINPATH}

uninstall :
	rm ${BINPATH}/${TARGET}


