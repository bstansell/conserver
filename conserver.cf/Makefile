#	$Id: Makefile,v 1.5 1999-01-25 15:38:20-08 bryan Exp $
#
#	Makefile for conserver.cf
#

PREFIX=/usr/local
BIN=${PREFIX}/bin
ETC=${PREFIX}/etc
MAN=${PREFIX}/man
MANSECT=8

all: 

clean: FRC
	rm -f Makefile.bak *.tbl core errs lint.out tags

depend:

dirs:

install:

${MAN}/man${MANSECT}:
	${INSTALL} -d $@

install.man: ${MAN}/man${MANSECT}
	tbl conserver.cf.man > conserver.cf.tbl
	${INSTALL} -c conserver.cf.tbl ${MAN}/man${MANSECT}/conserver.cf.${MANSECT}

FRC:
