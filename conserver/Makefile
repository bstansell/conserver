#	$Id: Makefile,v 1.3 1998-11-17 23:45:05-08 bryan Exp $
#
#	Makefile for console server
#
# two steps (1) and (2)

# (1) change ETC below to where you would like the console server installed
# I would not change the name, you have to much with the docs then...
PROG=	conserver
ETC=	${DESTDIR}/usr/local/etc
DOC=	${DESTDIR}/usr/local/man

# if we have to PUCC ptyd daemon we can use it to get ptys, else use fallback.o
# and change the CDEFS line below to =0
FALLBACK=fallback.o
PUCCLIB=
#FALLBACK=
#PUCCLIB=-lpucc

I=/usr/include
S=/usr/include/sys
L=/usr/local/include
P=

INCLUDE=
DEBUG=-O
CDEFS=  -DSUN5 -DHAVE_PTYD=0 -DDO_VIRTUAL=1
CFLAGS= ${DEBUG} ${CDEFS} ${INCLUDE}

HDR=	cons.h \
	access.h client.h consent.h group.h main.h master.h \
	readcfg.h
SRC=	access.c client.c consent.c group.c main.c master.c \
	readcfg.c fallback.c
OBJ=	access.o client.o consent.o group.o main.o master.o \
	readcfg.o ${FALLBACK}
MAN=	conserver.man
OTHER=	README Sun-serial
SOURCE=	Makefile ${OTHER} ${MAN} ${HDR} ${SRC}

all: ${PROG}

${PROG}:$P ${OBJ}
	${CC} -o $@ ${CFLAGS} ${OBJ} ${PUCCLIB} -lsocket -lnsl

clean: FRC
	rm -f Makefile.bak ${PROG} a.out *.o core errs lint.out tags

deinstall: ${MAN} ${DOC} FRC
	install -R ${ETC}/${PROG}
	mkcat -r${DOC} -D ${MAN}

depend: ${HDR} ${SRC} FRC
	maketd ${CDEFS} ${INCLUDE} ${SRC}

dirs: ${ETC} ${LIB}

distrib: FRC
	distrib -c ${ETC}/${PROG}

install: all dirs FRC
	install -c -s ${PROG} ${ETC}/${PROG}

lint: ${HDR} ${SRC} FRC
	lint -h ${CDEFS} ${INCLUDE} ${SRC}

mkcat: ${MAN} ${DOC} FRC
	mkcat -r${DOC} ${MAN}

print: source FRC
	lpr -J"${PROG} source" ${SOURCE}

source: ${SOURCE}

spotless: clean
	rcsclean ${SOURCE}

tags: ${HDR} ${SRC}
	ctags -t ${HDR} ${SRC}

/ ${ETC} ${LIB}:
	install -dr $@

${SOURCE}:
	co -q $@

FRC:

# DO NOT DELETE THIS LINE - maketd DEPENDS ON IT

access.o: access.c access.h client.h cons.h consent.h group.h main.h readcfg.h

client.o: client.c client.h cons.h consent.h

consent.o: client.h cons.h consent.c consent.h main.h

group.o: access.h client.h cons.h consent.h group.c group.h main.h version.h

main.o: access.h client.h cons.h consent.h group.h main.c master.h readcfg.h version.h

master.o: access.h client.h cons.h consent.h group.h main.h master.c master.h \
	readcfg.h version.h

readcfg.o: access.h client.h cons.h consent.h group.h main.h master.h \
	readcfg.c readcfg.h

fallback.o: fallback.c

# *** Do not add anything here - It will go away. ***
