/*
 *  $Id: port.h,v 1.15 2000-03-06 18:16:24-08 bryan Exp $
 *
 *  Copyright GNAC, Inc., 1998
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@gnac.com)
 */

/*
 * Copyright 1992 Purdue Research Foundation, West Lafayette, Indiana
 * 47907.  All rights reserved.
 *
 * Written by Kevin S Braunsdorf, ksb@cc.purdue.edu, purdue!ksb
 *
 * This software is not subject to any license of the American Telephone
 * and Telegraph Company or the Regents of the University of California.
 *
 * Permission is granted to anyone to use this software for any purpose on
 * any computer system, and to alter it and redistribute it freely, subject
 * to the following restrictions:
 *
 * 1. Neither the authors nor Purdue University are responsible for any
 *    consequences of the use of this software.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Credit to the authors and Purdue
 *    University must appear in documentation and sources.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 *
 * 4. This notice may not be removed or altered.
 */

/*
 * this is the configuration file for the Ohio State/PUCC console
 * server.  Just define the macros below to somehting that looks good
 * and give it a go.  It'll complain (under conserver -V) if things
 * look really bad.
 *
 * all PTX, PTX2, and PTX4 code added by gregf@sequent.com		(gregf)
 */
#if !( defined(SUN5) || defined(BSDOS3) || defined(LINUX2) || defined(IRIX6) )
#error "Platform needs to be defined.  See port.h"
#endif

#if (defined(PTX2) || defined(PTX4))
#define PTX
#endif

/* some machine specific details
 */
#if !defined(USE_OLDSEL)
#if	defined(IBMR2)
#include <sys/select.h>
#endif
#endif
#if !defined(HAVE_UWAIT)
#define HAVE_UWAIT	!(defined(IBMR2)||defined(SUN5)||defined(HPUX8)||defined(HPUX9)||defined(PTX)||defined(IRIX5)||defined(BSDOS3)||defined(IRIX6))
#endif

#if !defined(HAVE_WAIT3)
#define HAVE_WAIT3	!(defined(SUN5)||defined(PTX))
#endif

/* This is the port number used in the connection.  It can use either
 * /etc/services or a hardcoded port (SERVICE name has precedence).
 * (You can -D one in the Makefile to override these.)
 */
/* #define PORT 782 /* only if you cannot put in /etc/services */
#if !defined(SERVICE)
#if !defined(PORT)
#define SERVICE		"conserver"
#endif
#endif

/* Wait for a part of a second before slapping console server.
 * Good for CISCO terminal servers that get upset when you
 * attack with intense socket connections
 */
#if !defined(USLEEP_FOR_SLOW_PORTS)
#define USLEEP_FOR_SLOW_PORTS 100000
#endif

/* The name of the host which will act as the console server
 */
#if !defined(HOST)
#define HOST		"console"
#endif

/* How long should we wait for a TCP socket to be created when talking
 * to network terminal servers?  30 second default
 */
#if !defined(CONNECTTIMEOUT)
#define CONNECTTIMEOUT	30
#endif

/* the default escape sequence used to give meta commands
 */
#if !defined(DEFATTN)
#define DEFATTN		'\005'
#endif
#if !defined(DEFESC)
#define DEFESC		'c'
#endif

/* Location of the configuration file
 */
#if !defined(CONFIG)
#define CONFIG		"/etc/conserver.cf"
#endif

/* Location of ANL designed passwd file */
#if !defined(PASSWD_FILE)
#define PASSWD_FILE	"/etc/conserver.passwd"
#endif

/* The maximum number of serial lines that can be handled by a child process
 */
#if !defined(MAXMEMB)
#define MAXMEMB		8
#endif


/* The maximum number of child processes spawned.
 */
#if !defined(MAXGRP)
#define MAXGRP		32
#endif

/* the max number of characters conserver will replay for you (the r command)
 */
#if !defined(MAXREPLAY)
#define MAXREPLAY	(80*25)
#endif

/* if the encrypted passwd is in a shadow file, define HAVE_SHADOW 	(gregf)
 */
#if !defined(HAVE_SHADOW)
#define HAVE_SHADOW	(defined(PTX)||defined(SUN5)||defined(IRIX6))
#endif

/* we'd like to line buffer our output, if we know how
 */
#if !defined(USE_SETLINEBUF)
#define USE_SETLINEBUF	(!(defined(HPUX7)||defined(HPUX8)||defined(HPUX9)||defined(PTX)))
#endif

/* we'd like to line buffer our output, if we know how; PTX uses setvbuf (gregf)
 */
#if !defined(USE_SETVBUF)
#define USE_SETVBUF	(defined(PTX))
#endif

/* hpux doesn't have getdtablesize() and they don't provide a macro
 * in non-KERNEL cpp mode
 */
#if defined(HPUX7)||defined(HPUX8)||defined(HPUX9)
#define getdtablesize()	64
#endif

/* the console server will provide a pseudo-device console which
 * allows operators to run backups and such without a hard wired
 * line (this is also good for testing the server to see if you
 * might wanna use it).  Turn this on only if you (might) need it.
 */
#if !defined(DO_VIRTUAL)
#define DO_VIRTUAL	1
#endif

#if DO_VIRTUAL
/* if the virtual console option is on we need a source to ptys,
 * the PUCC ptyd daemon is the best source be know, else fall back
 * on some emulation code?? (XXX)
 */
#if !defined(HAVE_PTYD)
#define HAVE_PTYD	(defined(S81)||defined(VAX8800))
#endif

#if !defined(HAVE_GETPSEUDO)
#define HAVE_GETPSEUDO	(defined(PTX2))
#endif

#if !defined(HAVE_PTSNAME)
#define	HAVE_PTSNAME 	(defined(PTX4))
#endif

#if !defined(HAVE_LDTERM)
#define HAVE_LDTERM	(defined(SUN5))
#endif

#if !defined(HAVE_STTY_LD)
#define HAVE_STTY_LD	(defined(IRIX5))
#endif

#endif /* virtual (process on a pseudo-tty) console support */

#if !defined(HAVE_SETSID)
#define HAVE_SETSID	(defined(IBMR2)||defined(SUN5)||defined(HPUX7)||defined(HPUX8)||defined(HPUX9)||defined(PTX)||defined(IRIX5)||defined(LINUX2)||defined(IRIX6)||defined(BSDOS3))
#endif

/* should we use flock to keep multiple conservers from hurting each other?
 * PTX has lockf... should probably port code to work with this (gregf)
 */
#if !defined(USE_FLOCK)
#define USE_FLOCK	(!(defined(IBMR2)||defined(SUN5)||defined(HPUX7)||defined(HPUX8)||defined(HPUX9)||defined(PTX)||defined(LINUX2)||defined(IRIX6)||defined(BSDOS3)))
#endif

/* should we try to pop streams modules off?
 */
#if !defined(USE_STREAMS)
#define USE_STREAMS	(defined(SUN4)||defined(SUN5)||defined(PTX)||defined(IRIX5)||defined(IRIX6))
#endif

/* if we do not have old style tty emulation use termios.h
 */
#if !defined(USE_TERMIO)
#define USE_TERMIO	(defined(ETA10)||defined(V386))
#endif
#if !defined(USE_TERMIOS)
#define USE_TERMIOS	(defined(HPUX7)||defined(HPUX8)||defined(HPUX9)||defined(SUN5)||defined(PTX)||defined(IRIX5)||defined(LINUX2)||defined(IRIX6)||defined(SUN4))
#endif
#if !defined(USE_TCBREAK)
#define USE_TCBREAK	(defined(PTX)||defined(BSDOS3)||defined(LINUX2)||defined(SUN5))
#endif

/* if we have <strings.h> define this to 1, else define to 0
 */
#if !defined(USE_STRINGS)
#define USE_STRINGS	(defined(SUN4)||defined(DYNIX)||defined(EPIX)||defined(IRIX5)||defined(IRIX6)||defined(BSDOS3))
#endif

#if !defined(NEED_UNISTD_H)
#define NEED_UNISTD_H	(defined(SUN5)||defined(PTX))
#endif

#if !defined(USE_SYS_TIME_H)
#define USE_SYS_TIME_H	(!defined(PTX))
#endif

#if USE_STRINGS
#if !defined(strchr)
#define	strchr	index
#endif
#if !defined(strrchr)
#define strrchr	rindex
#endif
#endif

/* used to force the server process to clear parity, which is for farmers
 */
#if !defined(CPARITY)
#define CPARITY		1
#endif


/* if you do not have fd_set's here is a possible emulation
 */
#if USE_OLDSEL
typedef long fd_set;

#define FD_ZERO(a) {*(a)=0;}
#define FD_SET(d,a) {*(a) |= (1 << (d));}
#define FD_CLR(d,a) {*(a) &= ~(1 << (d));}
#define FD_ISSET(d,a) (*(a) & (1 << (d)))
#endif

#if USE_TERMIOS
#if defined(LINUX2)
#include <sys/ioctl.h>
#endif
#if defined(HPUX7)||defined(HPUX8)||defined(HPUX9)
#define TCGETS  _IOR('T', 16, struct termios)
#define TCSETS  _IOW('T', 17, struct termios)
#endif
#if defined(PTX2)
#define TCGETS  TCGETP
#define TCSETS  TCSETP
#endif
#endif

/* which type does wait(2) take for status location
 */
#if HAVE_UWAIT
#define WAIT_T	union wait
#if ! defined WEXITSTATUS
#define WEXITSTATUS(x)	((x).w_retcode)
#endif
#else
#define WAIT_T	int
#endif

/* which type signal handlers return on this machine
 */
#if defined(sun) || defined(NEXT2) || defined(SUN5) || defined(PTX) || defined(IRIX5) || defined(BSDOS3) || defined(LINUX2) || defined(IRIX6)
#define SIGRETS	void
#else
#define SIGRETS	int
#endif

/* which type to use for global flags set by signal handlers */
#if defined(SUN5)
#define SIGFLAG volatile sig_atomic_t
#else
#define SIGFLAG int
#endif

#if !defined(USE_SIGACTION)
#define USE_SIGACTION (defined(SUN4)||defined(SUN5)||defined(LINUX2))
#endif

#if USE_SIGACTION
extern void Set_signal(int isg, SIGRETS (*disp)(int));
#else
#define Set_signal(sig, disp) (void)signal((sig), (disp))
#endif

/* do we have a (working) setsockopt call
 */
#if !defined(HAVE_SETSOCKOPT)
#define HAVE_SETSOCKOPT	(defined(sun)||defined(PTX)||defined(LINUX2)||defined(IRIX6)||defined(BSDOS3))
#endif

/* does this system have the ANSI strerror() function?
 */
#if !defined(HAVE_STRERROR)
#define HAVE_STRERROR	(defined(IBMR2)||defined(ETA10)||defined(V386)||defined(SUN5)||defined(NEXT2)||defined(HPUX8)||defined(HPUX9)||defined(PTX)||defined(IRIX5)||defined(LINUX2)||defined(IRIX6)||defined(BSDOS3))
#endif
#if ! HAVE_STRERROR
extern int errno;
extern char *sys_errlist[];
#define strerror(Me) (sys_errlist[Me])
#endif

#if !defined(HAVE_H_ERRLIST)
#define HAVE_H_ERRLIST  (defined(SUN4)||defined(SUN3)||defined(FREEBSD)|defined(NETBSD)||defined(PTX)||defined(IRIX5)||defined(LINUX2)||defined(IRIX6)||defined(BSDOS3))
#endif
#if HAVE_H_ERRLIST
extern int h_errno;
extern char *h_errlist[];
#define hstrerror(Me)   (h_errlist[Me])
#else
#define hstrerror(Me)   "host lookup error"
#endif

#if !defined(HAVE_RLIMIT)
#if (defined(SUN5)||defined(PTX4)||defined(LINUX2)||defined(BSDOS3)||defined(IRIX6))
#define HAVE_RLIMIT	1
#else
#define HAVE_RLIMIT	0
#endif
#endif

/* that's all.  just run
 *	make
 *	./conserver -V
 */

/* communication constants
 */
#define OB_SUSP		'Z'		/* suspended by server		*/
#define OB_DROP		'.'		/* dropped by server		*/

/* Due to C's poor man's macros the macro below would break if statements,
 * What we want
 *	macro()			{ stuff }
 * but the syntax gives us
 *	macro()			{ stuff };
 *
 * the extra semicolon breaks if statements!
 * Of course, the one we use makes lint scream:
 *	macro()			do { stuff } while (0)
 *
 * which is a statement and makes if statements safe
 */
#if defined(lint)
extern int shut_up_lint;
#else
#define shut_up_lint	0
#endif

/* this macro efficently outputs a constant string to a fd
 * of course it doesn't check the write :-(
 */
#define CSTROUT(Mfd, Mstr)	do {	\
	static char _ac[] = Mstr; \
	write(Mfd, _ac, sizeof(_ac)-1); \
	} while (shut_up_lint)

extern char *calloc(), *malloc(), *realloc();
