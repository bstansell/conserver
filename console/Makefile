#	$Id: Makefile,v 1.9 1999-01-14 13:05:58-08 bryan Exp $
#
#	Makefile for console client progran
#

PROG=console
PREFIX=/usr/local
BIN=${PREFIX}/bin
ETC=${PREFIX}/etc
MAN=${PREFIX}/man
MANSECT=8

C=../conserver

LINCLUDE= ${INCLUDE} -I$C
CFLAGS= ${DEBUG} ${CDEFS} ${LINCLUDE}

HDR=	
SRC=	console.c
OBJ=	console.o

all: ${PROG}

${PROG}: ${OBJ}
	${CC} -o $@ ${CFLAGS} ${OBJ} ${LIBS}

clean: FRC
	rm -f Makefile.bak ${PROG} a.out *.o core errs lint.out tags

depend: ${HDR} ${SRC} FRC
	makedepend ${CDEFS} ${LINCLUDE} ${SRC}

dirs: ${BIN}

install: all dirs FRC
	${INSTALL} -cs ${PROG} ${BIN}/${PROG}

${MAN}/man${MANSECT}:
	${INSTALL} -d $@

install.man: ${MAN}/man${MANSECT}
	${INSTALL} -c console.man ${MAN}/man${MANSECT}/console.${MANSECT}

lint: ${HDR} ${SRC} FRC
	lint -h ${CDEFS} ${LINCLUDE} ${SRC}

tags: ${HDR} ${SRC}
	ctags -t ${HDR} ${SRC}

/ ${BIN}:
	${INSTALL} -d $@

FRC:

# DO NOT DELETE THIS LINE -- make depend depends on it.

console.o: ../conserver/cons.h ../conserver/port.h ../conserver/version.h
