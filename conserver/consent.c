/*
 *  $Id: consent.c,v 5.36 2000-12-13 12:31:07-08 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
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
 * Network console modifications by Robert Olson, olson@mcs.anl.gov.
 */
#ifndef lint
static char copyright[] =
"@(#) Copyright 1992 Purdue Research Foundation.\nAll rights reserved.\n";
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>

#include "cons.h"
#include "port.h"
#include "consent.h"
#include "client.h"
#include "main.h"

#if USE_TERMIO
#include <termio.h>

#else
#if USE_TERMIOS
#include <termios.h>
#include <unistd.h>

#else	/* use ioctl stuff */
#include <sgtty.h>
#include <sys/ioctl.h>
#endif
#endif

#if USE_STREAMS
#include <stropts.h>
#endif

#if USE_STRINGS
#include <strings.h>
#else
#include <string.h>
#endif


struct hostcache *hostcachelist=NULL;

BAUD baud [] = {
	{ "Netwk", 0 },
#if defined(B38400)
	{ "38400", B38400 },
#endif
#if defined(B19200)
	{ "19200", B19200 },
#endif
	{ "9600", B9600 },
	{ "4800", B4800 },
	{ "2400", B2400 },
#if defined(B1800)
	{ "1800", B1800 },
#endif
	{ "1200", B1200 },
#if defined(B600)
	{ "600", B600 },
#endif
};


/* find a baud rate for the string "9600x" -> B9600			(ksb)
 */
BAUD *
FindBaud(pcMode)
char *pcMode;
{
	register int i;

	for (i = 0; i < sizeof(baud)/sizeof(struct baud); ++i) {
		if (0 != strncmp(pcMode, baud[i].acrate, strlen(baud[i].acrate)))
			continue;
		return baud+i;
	}
	return baud;
}


PARITY parity[] = {
#if USE_TERMIOS
#if !defined(PAREXT)
#define PAREXT	0
#endif
	{' ', 0, 0}, 	/* Blank for network */
	{'e', PARENB|CS7, 0},			/* even			*/
	{'m', PARENB|CS7|PARODD|PAREXT, 0},	/* mark			*/
	{'o', PARENB|CS7|PARODD, 0},		/* odd			*/
	{'p', CS8, 0},				/* pass 8 bits, no parity */
	{'s', PARENB|CS7|PAREXT, 0},		/* space		*/
#else
	{' ', 0, 0}, 	/* Blank for network */
	{'e', EVENP, ODDP},	/* even					*/
	{'m', EVENP|ODDP, 0},	/* mark					*/
	{'o', ODDP, EVENP},	/* odd					*/
#if defined(PASS8)
	{'p', PASS8,EVENP|ODDP},/* pass 8 bits, no parity		*/
#endif
	{'s', 0, EVENP|ODDP}	/* space				*/
#endif
};

/* find a parity on the end of a baud "9600even" -> EVEN		(ksb)
 */
PARITY *
FindParity(pcMode)
char *pcMode;
{
	register int i;
	auto char acFirst;

	while (isdigit(*pcMode)) {
		++pcMode;
	}
	acFirst = *pcMode;
	if (isupper(acFirst))
		acFirst = tolower(acFirst);
	for (i = 0; i < sizeof(parity)/sizeof(struct parity); ++i) {
		if (acFirst != parity[i].ckey)
			continue;
		return parity+i;
	}
	return parity;
}


#if USE_TERMIOS
/* setup a tty device							(ksb)
 */
static int
TtyDev(pCE)
CONSENT *pCE;
{
	struct termios termp;
	auto struct stat stPerm;

	/* here we should fstat for `read-only' checks
	 */
	if (-1 == fstat(pCE->fdtty, & stPerm)) {
		fprintf(stderr, "%s: fstat: %s: %s\n", progname, pCE->dfile, strerror(errno));
	} else if (0 == (stPerm.st_mode & 0222)) {
		/* any device that is read-only we won't write to
		 */
		pCE->fronly = 1;
	}

	/*
	 * Get terminal attributes
	 */
	if (-1 == tcgetattr(pCE->fdtty, &termp)) {
		fprintf(stderr, "%s: tcgetattr: %s(%d): %s\n", progname, pCE->dfile, pCE->fdtty, strerror(errno));
		return -1;
	}

	/*
	 * Turn off:	echo
	 *		icrnl
	 *		opost	No post processing
	 *		icanon	No line editing
	 *		isig	No signal generation
	 * Turn on:	ixoff
	 */
	termp.c_iflag = IXON|IXOFF|BRKINT;
	termp.c_oflag = 0;
	termp.c_cflag = CREAD;
	termp.c_cflag |= pCE->pparity->iset;
	termp.c_lflag = 0;
	/*
	 * Set the VMIN == 128
	 * Set the VTIME == 1 (0.1 sec)
	 * Don't bother with the control characters as they are not used
	 */
	termp.c_cc[VMIN] = 128;
	termp.c_cc[VTIME] = 1;

	if (-1 == cfsetospeed(&termp,pCE->pbaud->irate)) {
		fprintf(stderr, "%s: cfsetospeed: %s(%d): %s\n", progname, pCE->dfile, pCE->fdtty, strerror(errno));
		return -1;
	}
	if (-1 == cfsetispeed(&termp,pCE->pbaud->irate)) {
		fprintf(stderr, "%s: cfsetispeed: %s(%d): %s\n", progname, pCE->dfile, pCE->fdtty, strerror(errno));
		return -1;
	}

	/*
	 * Set terminal attributes
	 */
	if (-1 == tcsetattr(pCE->fdtty, TCSADRAIN, &termp)) {
		fprintf(stderr, "%s: tcsetattr: %s(%d): %s\n", progname, pCE->dfile, pCE->fdtty, strerror(errno));
		return -1;
	}

#if USE_STREAMS
	/*
	 * eat all the streams modules upto and including ttcompat
	 */
        while (ioctl(pCE->fdtty, I_FIND, "ttcompat") == 0) {
        	(void)ioctl(pCE->fdtty, I_POP, 0);
        }
#endif
	pCE->fup = 1;
	return 0;
}
#else

/* setup a tty device							(ksb)
 */
static int
TtyDev(pCE)
CONSENT *pCE;
{
	struct sgttyb sty;
	struct tchars m_tchars;
	struct ltchars m_ltchars;
	auto struct stat stPerm;

	/* here we should fstat for `read-only' checks
	 */
	if (-1 == fstat(pCE->fdtty, & stPerm)) {
		fprintf(stderr, "%s: fstat: %s: %s\n", progname, pCE->dfile, strerror(errno));
	} else if (0 == (stPerm.st_mode & 0222)) {
		/* any device that is read-only we won't write to
		 */
		pCE->fronly = 1;
	}

#if USE_SOFTCAR
#if defined(TIOCSSOFTCAR)
	if (-1 == ioctl(pCE->fdtty, TIOCSSOFTCAR, &fSoftcar)) {
		fprintf(stderr, "%s: softcar: %d: %s\n", progname, pCE->fdtty, strerror(errno));
		return -1;
	}
#endif
#endif

	/* stty 9600 raw cs7
	 */
	if (-1 == ioctl(pCE->fdtty, TIOCGETP, (char *)&sty)) {
		fprintf(stderr, "%s: ioctl1: %s(%d): %s\n", progname, pCE->dfile, pCE->fdtty, strerror(errno));
		return -1;
	}
	sty.sg_flags &= ~(ECHO|CRMOD|pCE->pparity->iclr);
	sty.sg_flags |= (CBREAK|TANDEM|pCE->pparity->iset);
	sty.sg_erase = -1;
	sty.sg_kill = -1;
	sty.sg_ispeed = pCE->pbaud->irate;
	sty.sg_ospeed = pCE->pbaud->irate;
	if (-1 == ioctl(pCE->fdtty, TIOCSETP, (char *)&sty)) {
		fprintf(stderr, "%s: ioctl2: %d: %s\n", progname, pCE->fdtty, strerror(errno));
		return -1;
	}

	/* stty undef all tty chars
	 * (in cbreak mode we may not need to this... but we do)
	 */
	if (-1 == ioctl(pCE->fdtty, TIOCGETC, (char *)&m_tchars)) {
		fprintf(stderr, "%s: ioctl3: %d: %s\n", progname, pCE->fdtty, strerror(errno));
		return -1;
	}
	m_tchars.t_intrc = -1;
	m_tchars.t_quitc = -1;
	m_tchars.t_startc = -1;
	m_tchars.t_stopc = -1;
	m_tchars.t_eofc = -1;
	m_tchars.t_brkc = -1;
	if (-1 == ioctl(pCE->fdtty, TIOCSETC, (char *)&m_tchars)) {
		fprintf(stderr, "%s: ioctl4: %d: %s\n", progname, pCE->fdtty, strerror(errno));
		return -1;
	}
	if (-1 == ioctl(pCE->fdtty, TIOCGLTC, (char *)&m_ltchars)) {
		fprintf(stderr, "%s: ioctl5: %d: %s\n", progname, pCE->fdtty, strerror(errno));
		return -1;
	}
	m_ltchars.t_werasc = -1;
	m_ltchars.t_flushc = -1;
	m_ltchars.t_lnextc = -1;
	m_ltchars.t_suspc = -1;
	m_ltchars.t_dsuspc = -1;
	if (-1 == ioctl(pCE->fdtty, TIOCSLTC, (char *)&m_ltchars)) {
		fprintf(stderr, "%s: ioctl6: %d: %s\n", progname, pCE->fdtty, strerror(errno));
		return -1;
	}
#if USE_STREAMS
	/* pop off the un-needed streams modules (on a sun3 machine esp.)
	 * (Idea by jrs@ecn.purdue.edu)
	 */
        while (ioctl(pCE->fdtty, I_POP, 0) == 0) {
		/* eat all the streams modules */;
        }
#endif
	pCE->fup = 1;
	return 0;
}
#endif

#if DO_VIRTUAL
/* setup a virtual device						(ksb)
 */
static int
VirtDev(pCE)
CONSENT *pCE;
{
#if USE_TERMIOS
	static struct termios n_tio;
#else
	auto struct sgttyb sty;
	auto struct tchars m_tchars;
	auto struct ltchars m_ltchars;
#endif
#if HAVE_RLIMIT
	auto struct rlimit rl;
#endif
	auto int i, iNewGrp;
	auto int fd;
	extern char **environ;
	register char *pcShell, **ppcArgv;

	(void)fflush(stdout);

	switch (pCE->ipid = fork()) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		fprintf(stderr, "%s: %d is the pid on %s\n", progname, pCE->ipid, pCE->acslave);
		(void)fflush(stderr);
		pCE->fup = 1;
		sleep(2);	/* chance to open line */
		return 0;
	}

	/* put the signals back that we trap
	 */
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGTSTP, SIG_DFL);

	/* setup new process with clean filew descriptors
	 */
#if HAVE_RLIMIT
	getrlimit(RLIMIT_NOFILE, &rl);
	i = rl.rlim_cur;
#else
	i = getdtablesize();
#endif
	for (/* i above */; i-- > 2; ) {
		close(i);
	}
	/* leave 2 until we *have to close it*
	 */
	close(1);
	close(0);
#if defined(TIOCNOTTY)
	if (-1 != (i = open("/dev/tty", 2, 0))) {
		ioctl(i, TIOCNOTTY, (char *)0);
		close(i);
	}
#endif

#if HAVE_SETSID
	iNewGrp = setsid();
	if (-1 == iNewGrp) {
		fprintf(stderr, "%s: %s: setsid: %s\n", progname, pCE->server, strerror(errno));
		iNewGrp = getpid();
	}
#else
	iNewGrp = getpid();
#endif

	if (0 != open(pCE->acslave, 2, 0) || 1 != dup(0)) {
		fprintf(stderr, "%s: %s: fd sync error\n", progname, pCE->server);
		exit(1);
	}
#if HAVE_PTSNAME
	/* SYSVr4 semantics for opening stream ptys			(gregf)
	 * under PTX (others?) we have to push the compatibility
	 * streams modules `ptem' and `ld'
	 */
	(void)ioctl(0, I_PUSH, "ptem");
	(void)ioctl(0, I_PUSH, "ld");
#endif
#if HAVE_LDTERM
	(void)ioctl(0, I_PUSH, "ptem");
	(void)ioctl(0, I_PUSH, "ldterm");
#endif
#if HAVE_STTY_LD
	(void)ioctl(0, I_PUSH, "stty_ld");
#endif

#if USE_TERMIOS
	if (0 != ioctl(0, TCGETS, & n_tio)) {
		fprintf(stderr, "%s: iotcl: getsw: %s\n", progname, strerror(errno));
		exit(1);
	}
	n_tio.c_iflag &= ~(IGNCR|IUCLC);
	n_tio.c_iflag |= ICRNL|IXON|IXANY;
	n_tio.c_oflag &= ~(OLCUC|ONOCR|ONLRET|OFILL|NLDLY|CRDLY|TABDLY|BSDLY);
	n_tio.c_oflag |= OPOST|ONLCR;
	n_tio.c_lflag &= ~(XCASE|NOFLSH|ECHOK|ECHONL);
	n_tio.c_lflag |= ISIG|ICANON|ECHO;
	n_tio.c_cc[VEOF] = '\004';
	n_tio.c_cc[VEOL] = '\000';
	n_tio.c_cc[VERASE] = '\010';
	n_tio.c_cc[VINTR] = '\003';
	n_tio.c_cc[VKILL] = '@';
	/* MIN */
	n_tio.c_cc[VQUIT] = '\034';
	n_tio.c_cc[VSTART] = '\021';
	n_tio.c_cc[VSTOP] = '\023';
	n_tio.c_cc[VSUSP] = '\032';
	if (0 != ioctl(0, TCSETS, & n_tio)) {
		fprintf(stderr, "%s: getarrt: %s\n", progname, strerror(errno));
		exit(1);
	}

	tcsetpgrp(0, iNewGrp);
#else
	/* stty 9600 raw cs7
	 */
	if (-1 == ioctl(0, TIOCGETP, (char *)&sty)) {
		fprintf(stderr, "%s: ioctl1: %s: %s\n", progname, pCE->fdtty, strerror(errno));
		exit(1);
	}
	sty.sg_flags &= ~(CBREAK|TANDEM|pCE->pparity->iclr);
	sty.sg_flags |= (ECHO|CRMOD|pCE->pparity->iset);
	sty.sg_erase = '\b';
	sty.sg_kill = '\025';
	sty.sg_ispeed = pCE->pbaud->irate;
	sty.sg_ospeed = pCE->pbaud->irate;
	if (-1 == ioctl(0, TIOCSETP, (char *)&sty)) {
		fprintf(stderr, "%s: ioctl2: %s\n", progname, strerror(errno));
		exit(1);
	}

	/* stty undef all tty chars
	 * (in cbreak mode we may not need to this... but we do)
	 */
	if (-1 == ioctl(0, TIOCGETC, (char *)&m_tchars)) {
		fprintf(stderr, "%s: ioctl3: %s\n", progname, strerror(errno));
		exit(1);
	}
	m_tchars.t_intrc = '\003';
	m_tchars.t_quitc = '\034';
	m_tchars.t_startc = '\021';
	m_tchars.t_stopc = '\023';
	m_tchars.t_eofc = '\004';
	m_tchars.t_brkc = '\033';
	if (-1 == ioctl(0, TIOCSETC, (char *)&m_tchars)) {
		fprintf(stderr, "%s: ioctl4: %s\n", progname, strerror(errno));
		exit(1);
	}
	if (-1 == ioctl(0, TIOCGLTC, (char *)&m_ltchars)) {
		fprintf(stderr, "%s: ioctl5: %s\n", progname, strerror(errno));
		exit(1);
	}
	m_ltchars.t_werasc = '\027';
	m_ltchars.t_flushc = '\017';
	m_ltchars.t_lnextc = '\026';
	m_ltchars.t_suspc = '\032';
	m_ltchars.t_dsuspc = '\031';
	if (-1 == ioctl(0, TIOCSLTC, (char *)&m_ltchars)) {
		fprintf(stderr, "%s: ioctl6: %s\n", progname, strerror(errno));
		exit(1);
	}

	/* give us a process group to work in
	 */
	ioctl(0, TIOCGPGRP, (char *)&i);
	setpgrp(0, i);
	ioctl(0, TIOCSPGRP, (char *)&iNewGrp);
	setpgrp(0, iNewGrp);
#endif

	close(2);
	(void)dup(1);		/* better be 2, but it is too late now */

	/* if the command is null we should run root's shell, directly
	 * if we can't find root's shell run /bin/sh
	 */
	pcShell = "/bin/sh";
	if ('\000' == pCE->pccmd[0]) {
		static char *apcArgv[] = {
			"-shell", "-i", (char *)0
		};
		register struct passwd *pwd;

		if ((struct passwd *)0 != (pwd = getpwuid(0)) && '\000' != pwd->pw_shell[0]) {
			pcShell = pwd->pw_shell;
		}
		ppcArgv = apcArgv;
	} else {
		static char *apcArgv[] = {
			"/bin/sh", "-ce", (char *)0, (char *)0
		};

		apcArgv[2] = pCE->pccmd;
		ppcArgv = apcArgv;
	}
	execve(pcShell, ppcArgv, environ);
	fprintf(stderr, "execve: %s\n", strerror(errno));
	exit(1);
	/*NOTREACHED*/
}
#endif

/* down a console, virtual or real					(ksb)
 */
void
ConsDown(pCE, pfdSet)
CONSENT *pCE;
fd_set *pfdSet;
{
#if DO_VIRTUAL
	if (-1 != pCE->ipid) {
		if (-1 != kill(pCE->ipid, SIGHUP))
			sleep(1);
		pCE->ipid = -1;
	}
#endif
	if (-1 != pCE->fdtty) {
		FD_CLR(pCE->fdtty, pfdSet);
#if DO_VIRTUAL
		if (0 == pCE->fvirtual)  {
			(void)close(pCE->fdtty);
			pCE->fdtty = -1;
		}
#else
		(void)close(pCE->fdtty);
		pCE->fdtty = -1;
#endif
	}
	if (-1 != pCE->fdlog) {
		if (pCE->nolog) {
		    CSTROUT(pCE->fdlog, "[Console logging restored]\r\n");
		}
		(void)close(pCE->fdlog);
		pCE->fdlog = -1;
	}
	pCE->fup = 0;
	pCE->nolog = 0;
}

int
CheckHostCache(hostname)
const char *hostname;
{
    struct hostcache *p;
    p = hostcachelist;
    while (p != NULL) {
	if ( 0 == strncmp( hostname, p->hostname, MAXSERVLEN ) ) {
	    return 1;
	}
	p = p->next;
    }
    return 0;
}

void
AddHostCache(hostname)
const char *hostname;
{
    struct hostcache *n;
    if ((struct hostcache *)0 == (n = (struct hostcache *)malloc(sizeof(struct hostcache)))) {
	fprintf(stderr, "%s: malloc failure: %s\n", progname, strerror(errno));
	return;
    }
    (void)strncpy(n->hostname, hostname, MAXSERVLEN);
    n->next = hostcachelist;
    hostcachelist = n;
}

void
ClearHostCache()
{
    struct hostcache *p, *n;
    p = hostcachelist;
    while (p != NULL) {
	n = p->next;
	free(p);
	p = n;
    }
    hostcachelist = NULL;
}

/* set up a console the way it should be for use to work with it	(ksb)
 * also, recover from silo over runs by dropping the line and re-opening
 * We also maintian the select set for the caller.
 */
void
ConsInit(pCE, pfdSet, useHostCache)
CONSENT *pCE;
fd_set *pfdSet;
int useHostCache;
{
	if ( ! useHostCache ) ClearHostCache();

	/* clean up old stuff
	 */
	ConsDown(pCE, pfdSet);

	pCE->fronly = 0;
	pCE->nolog = 0;
	(void)strcpy(pCE->acline, pCE->server);
	pCE->inamelen = strlen(pCE->server);
	pCE->acline[pCE->inamelen++] = ':';
	pCE->acline[pCE->inamelen++] = ' ';
	pCE->iend = pCE->inamelen;


	/* try to open them again
	 */
	if (-1 ==
	    (pCE->fdlog = open(pCE->lfile, O_RDWR|O_CREAT|O_APPEND, 0644)))
	{
		fprintf(stderr,
			"%s: open: %s: %s\n",
			progname, pCE->lfile, strerror(errno));
		return;
	}

#if DO_VIRTUAL
	if (0 != pCE->fvirtual)
	{
  		/* still open, never ever close it, but set the bit */
 		FD_SET(pCE->fdtty, pfdSet);
  	}
	else if (pCE->isNetworkConsole)
	{
	    struct sockaddr_in port;
	    struct hostent *hp;
	    int one = 1;
	    int flags;
	    fd_set fds;
	    struct timeval tv;
	    
	    if ( CheckHostCache( pCE->networkConsoleHost ) ) {
		  fprintf(stderr, "%s: cached previous timeout: %s (%d@%s): forcing down\n",
			    progname, pCE->server, ntohs(port.sin_port),
			    pCE->networkConsoleHost);
		  ConsDown(pCE, pfdSet);
		  return;
	    }

#if USLEEP_FOR_SLOW_PORTS
	    usleep( USLEEP_FOR_SLOW_PORTS );  /* Sleep for slow network ports */
#endif

	    bzero(&port, sizeof(port));

	    if ((hp = gethostbyname(pCE->networkConsoleHost)) == NULL)
	    {
		fprintf(stderr, "%s: gethostbyname %s failed\n",
			progname, pCE->networkConsoleHost);
		exit(1);
	    }

	    bcopy(hp->h_addr, &port.sin_addr, hp->h_length);
	    port.sin_family = hp->h_addrtype;
	    port.sin_port = htons(pCE->networkConsolePort);
	    
	    if ((pCE->fdtty = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	    {
		fprintf(stderr, "%s: socket: %s\n", progname, strerror(errno));
		exit(1);
	    }
	    if (setsockopt(pCE->fdtty, SOL_SOCKET, SO_KEEPALIVE,
			   (char *) &one, sizeof(one)) < 0)
	    {
		fprintf(stderr, "%s: setsockopt SO_KEEPALIVE: %s\n",
			progname, strerror(errno));
	    }

	    if ( (flags = fcntl(pCE->fdtty, F_GETFL)) >= 0 )
	    {
		flags |= O_NONBLOCK;
		if ( fcntl(pCE->fdtty, F_SETFL, flags) < 0 ) {
		    fprintf( stderr, "%s: fcntl O_NONBLOCK: %s\n",
			progname, strerror(errno));
		}
	    } else {
		fprintf( stderr, "%s: fcntl: %s\n", progname, strerror(errno));
	    }

	    if (connect(pCE->fdtty,
			(struct sockaddr *)&port, sizeof(port)) < 0)
	    {
		if (errno != EINPROGRESS ) {
		  fprintf(stderr, "%s: connect: %s (%d@%s): %s: forcing down\n",
			    progname, pCE->server, ntohs(port.sin_port),
			    pCE->networkConsoleHost, strerror(errno));
		  ConsDown(pCE, pfdSet);
		  return;
		}
	    }

	    tv.tv_sec = CONNECTTIMEOUT;
	    tv.tv_usec = 0;
	    FD_ZERO(&fds);
	    FD_SET(pCE->fdtty, &fds);

	    if ( (one=select( pCE->fdtty+1, NULL, &fds, NULL, &tv )) < 0 ) {
		fprintf(stderr, "%s: select: %s (%d@%s): %s: forcing down\n",
			progname, pCE->server, ntohs(port.sin_port),
			pCE->networkConsoleHost, strerror(errno));
		ConsDown(pCE, pfdSet);
		return;
	    }

	    if (one == 0) {	/* Timeout */
		AddHostCache(pCE->networkConsoleHost);
		fprintf(stderr, "%s: timeout: %s (%d@%s): forcing down\n",
			progname, pCE->server, ntohs(port.sin_port),
			pCE->networkConsoleHost);
		ConsDown(pCE, pfdSet);
		return;
	    } else {		/* Response */
		flags = 0;
		one = sizeof(flags);
		/* So, getsockopt seems to return -1 if there is something
		   interesting in SO_ERROR under solaris...sheesh.  So,
		   the error message has the small change it's not accurate. */
		if (getsockopt(pCE->fdtty, SOL_SOCKET, SO_ERROR,
		    (char*)&flags, &one) < 0)
		{
#if defined(SUN5)
		    fprintf(stderr, "%s: connect: %s (%d@%s): %s: forcing down\n",
#else
		    fprintf(stderr, "%s: getsockopt SO_ERROR: %s (%d@%s): %s: forcing down\n",
#endif
			    progname, pCE->server, ntohs(port.sin_port),
			    pCE->networkConsoleHost, strerror(errno));
		    ConsDown(pCE, pfdSet);
		    return;
		}
		if (flags != 0)
		{
		    fprintf(stderr, "%s: connect: %s (%d@%s): %s: forcing down\n",
			    progname, pCE->server, ntohs(port.sin_port),
			    pCE->networkConsoleHost, strerror(errno));
		    ConsDown(pCE, pfdSet);
		    return;
		}
	    }

	    /*
	     * Poke the connection to get the annex to wake up and
	     * register this connection.
	     */
#ifdef POKE_ANNEX
	    write(pCE->fdtty, "\r\n", 2);
#endif
	} else if (-1 == (pCE->fdtty = open(pCE->dfile, O_RDWR|O_NDELAY, 0600))) {
		fprintf(stderr, "%s: open: %s: %s\n", progname, pCE->dfile, strerror(errno));
		(void)close(pCE->fdlog);
		pCE->fdlog = -1;
		return;
	}
	FD_SET(pCE->fdtty, pfdSet);

	/* ok, now setup the device
	 */
	if (pCE->fvirtual) {
		VirtDev(pCE);
	}
	else if (pCE->isNetworkConsole)
	{
		pCE->fup = 1;
	}
	else
	{
		TtyDev(pCE);
	}
#else
	if (-1 == (pCE->fdtty = open(pCE->dfile, O_RDWR|O_NDELAY, 0600))) {
		fprintf(stderr, "%s: open: %s: %s\n", progname, pCE->dfile, strerror(errno));
		(void)close(pCE->fdlog);
		pCE->fdlog = -1;
		return;
	}
	FD_SET(pCE->fdtty, pfdSet);

	/* ok, now setup the device
	 */
	TtyDev(pCE);
#endif
}
