#	$Id: Make.host,v 5.10 94/07/26 11:06:26 ksb Exp $
#
#	Makefile for console client progran
#

# edit the ETC directory below to change where the console client
# is installed.
PROG=	console
ETC=	${DESTDIR}/usr/local/etc
DOC=	${DESTDIR}/usr/local/man

I=/usr/include
S=/usr/include/sys
L=/usr/local/include
C=../conserver
P=

INCLUDE= -I$C
DEBUG=-O
CDEFS=  -DSUN5
CFLAGS= ${DEBUG} ${CDEFS} ${INCLUDE}

HDR=	
ONEC=	console.c
MAN=	console.man
OTHER=	README 
SOURCE=	Makefile ${OTHER} ${MAN} ${HDR} ${ONEC}

all: ${PROG}

${PROG}:
	${CC} -o $@ ${CFLAGS} ${ONEC} -lsocket -lnsl

clean: FRC
	rm -f Makefile.bak ${PROG} a.out *.o core errs lint.out tags

deinstall: ${MAN} ${DOC} FRC
	install -R ${ETC}/${PROG}
	mkcat -r${DOC} -D ${MAN}

depend: ${HDR} ${ONEC} FRC
	maketd -b ${CDEFS} ${INCLUDE} ${ONEC}

dirs: ${ETC}

distrib: FRC
	distrib -c ${ETC}/${PROG}

install: all dirs FRC
	install -cs ${PROG} ${ETC}/${PROG}

lint: ${HDR} ${ONEC} FRC
	lint -h ${CDEFS} ${INCLUDE} ${ONEC}

mkcat: ${MAN} ${DOC} FRC
	mkcat -r${DOC} ${MAN}

print: source FRC
	lpr -J"${PROG} source" ${SOURCE}

source: ${SOURCE}

spotless: clean
	rcsclean ${SOURCE}

tags: ${HDR} ${ONEC}
	ctags -t ${HDR} ${ONEC}

/ ${ETC}:
	install -dr $@

${SOURCE}:
	co -q $@

FRC:

# DO NOT DELETE THIS LINE - maketd DEPENDS ON IT

console: $C/cons.h console.c

# *** Do not add anything here - It will go away. ***
