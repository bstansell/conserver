#
#	$Id: Make.host,v 1.13 94/06/03 15:32:46 nuspl Exp $
#
#	Makefile for autologin
#
#	Jeff W. Stewart, Purdue University Computing Center
#

DESTDIR=
BINDIR=	${DESTDIR}/usr/local/etc

INCLUDE=
DEBUG=	-g
DEFS=	-DPUCC -DSUN5
CFLAGS=	${DEBUG} ${DEFS} ${INCLUDE}

GENC=	main.c
GENH=	main.h
GEN=	${GENC} ${GENH}
HDR=	
SRC=	autologin.c
OBJ=	autologin.o main.o
SOURCE= README autologin.man autologin.m Makefile ${SRC} ${HDR}



all:	autologin

autologin: ${OBJ}
	${CC} ${CFLAGS} -o autologin ${OBJ}

main.h: main.c

main.c: autologin.m
	mkcmd std_help.m std_version.m autologin.m
	-(cmp -s prog.c main.c || (cp prog.c main.c && echo main.c updated))
	-(cmp -s prog.h main.h || (cp prog.h main.h && echo main.h updated))
	rm -f prog.[ch]

# On keep (EPIX), putenv.o is extracted (ar x) from /usr/lib/libc.a
# and setgroups.o is extracted from libbsd.a
#
putenv.o:
	ar x /usr/lib/libc.a $@

setgroups.o:
	ar x /usr/lib/libbsd.a $@

getut.o:
	ar x /sysv/usr/lib/libc.a $@

clean: FRC
	rm -f autologin *.o errs core Makefile.bak a.out lint.errs ${GEN}

lint: ${HDR} ${SRC} ${GEN} FRC
	lint -h ${CDEFS} ${INCLUDE} ${GEN} ${SRC}

install: all
	install -c -s -m 755 autologin ${BINDIR}

distrib:
	distrib -c ${BINDIR}/autologin	

depend:	${HDR} ${SRC} ${GEN}
	maketd -a ${HDR} ${SRC} ${GEN}

spotless:	clean
	rcsclean Makefile ${HDR} ${SRC}

source: ${SOURCE}

${SOURCE}:
	co -q $@

FRC:

# DO NOT DELETE THIS LINE - maketd DEPENDS ON IT

main.o: main.c

autologin.o: autologin.c main.h

# *** Do not add anything here - It will go away. ***
