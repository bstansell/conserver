#	$Id: Makefile,v 1.12 1999-02-02 17:02:25-08 bryan Exp $
#
#	Makefile for console server
#

PROG=conserver
PREFIX=/usr/local
BIN=${PREFIX}/bin
ETC=${PREFIX}/etc
MAN=${PREFIX}/man
MANSECT=8

CFLAGS= ${DEBUG} ${CDEFS} ${INCLUDE}

HDR=	cons.h \
	access.h client.h consent.h group.h main.h master.h \
	readcfg.h
SRC=	access.c client.c consent.c group.c main.c master.c \
	readcfg.c fallback.c
OBJ=	access.o client.o consent.o group.o main.o master.o \
	readcfg.o fallback.o
INIT=	conserver.rc

all: ${PROG}

${PROG}: ${OBJ}
	${CC} -o $@ ${CFLAGS} ${OBJ} ${LIBS}

clean: FRC
	rm -f Makefile.bak ${PROG} *.tbl a.out *.o core errs lint.out tags

depend: ${HDR} ${SRC} FRC
	makedepend ${CDEFS} ${INCLUDE} ${SRC}

dirs: ${BIN} ${ETC}

install: all dirs ${INIT} FRC
	${INSTALL} -cs ${PROG} ${BIN}/${PROG}
	${INSTALL} -c ${INIT} ${ETC}/${INIT}

${MAN}/man${MANSECT}:
	${INSTALL} -d $@

install.man: ${MAN}/man${MANSECT}
	tbl conserver.man > conserver.tbl
	${INSTALL} -c conserver.tbl ${MAN}/man${MANSECT}/conserver.${MANSECT}

lint: ${HDR} ${SRC} FRC
	lint -h ${CDEFS} ${INCLUDE} ${SRC}

tags: ${HDR} ${SRC}
	ctags -t ${HDR} ${SRC}

/ ${BIN} ${ETC}:
	${INSTALL} -d $@

FRC:

# DO NOT DELETE THIS LINE -- make depend depends on it.

access.o: cons.h port.h access.h consent.h client.h group.h readcfg.h main.h
client.o: cons.h port.h consent.h client.h
consent.o: cons.h port.h consent.h client.h main.h
fallback.o: cons.h port.h
group.o: cons.h port.h consent.h client.h access.h group.h version.h main.h
main.o: cons.h port.h consent.h client.h group.h master.h access.h readcfg.h
main.o: version.h
master.o: cons.h port.h consent.h client.h group.h access.h master.h
master.o: readcfg.h version.h main.h
readcfg.o: cons.h port.h consent.h client.h group.h access.h readcfg.h
readcfg.o: master.h main.h
