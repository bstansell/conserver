#	$Id: Make.host,v 4.3 92/07/10 15:57:32 dru Exp $
#
#	Makefile for conserver data base
#

# if you edit LIB below you have to change cons.hs default config define.
PROG=	conserver.cf
LIB=	${DESTDIR}/usr/local/lib
DOC=	${DESTDIR}/usr/man

SRCs=	conserver.cf
MAN=	conserver.cf.5l
OTHER=	README
SOURCE=	Makefile ${OTHER} ${MAN} ${SRCl} ${SRCs}

all: ${SRCl} ${PROG}

${PROG}: ${SRCs}

clean: FRC
	rm -f Makefile.bak a.out core errs lint.out tags

deinstall: ${MAN} ${DOC} FRC
	install -R ${LIB}/${PROG}
	mkcat -r${DOC} -D ${MAN}

depend: FRC

dirs: ${LIB} ${DOC}

install: all dirs FRC
	install -c ${PROG} ${LIB}/${PROG}

lint: FRC

mkcat: ${MAN} ${DOC} FRC
	mkcat -r${DOC} ${MAN}

print: source FRC
	lpr -J"${PROG} source" ${SOURCE}

source: ${SOURCE}

spotless: clean
	rcsclean ${SOURCE}

tags: FRC

/ ${LIB} ${LIB}:
	install -dr $@

${SOURCE}:
	co -q $@

FRC:

# DO NOT DELETE THIS LINE - make depend DEPENDS ON IT

# *** Do not add anything here - It will go away. ***
