/*
 *  $Id: consent.c,v 5.103 2003-04-06 05:32:20-07 bryan Exp $
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

#include <config.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>

#include <compat.h>
#include <util.h>

#include <consent.h>
#include <client.h>
#include <group.h>
#include <main.h>


struct hostcache *hostcachelist = NULL;

BAUD baud[] = {
    {"Netwk", 0},
    {"Local", 0},
#if defined(B115200)
    {"115200", B115200},
#endif
#if defined(B57600)
    {"57600", B57600},
#endif
#if defined(B38400)
    {"38400", B38400},
#endif
#if defined(B19200)
    {"19200", B19200},
#endif
    {"9600", B9600},
    {"4800", B4800},
    {"2400", B2400},
#if defined(B1800)
    {"1800", B1800},
#endif
    {"1200", B1200},
#if defined(B600)
    {"600", B600},
#endif
};


/* find a baud rate for the string "9600x" -> B9600			(ksb)
 */
BAUD *
#if PROTOTYPES
FindBaud(char *pcMode)
#else
FindBaud(pcMode)
    char *pcMode;
#endif
{
    int i;

    for (i = 0; i < sizeof(baud) / sizeof(struct baud); ++i) {
	if (0 != strncmp(pcMode, baud[i].acrate, strlen(baud[i].acrate)))
	    continue;
	return baud + i;
    }
    return baud;
}


PARITY parity[] = {
#if HAVE_TERMIOS_H
    {' ', 0, 0}
    ,				/* Blank for network */
# if !defined(PAREXT)
#  define PAREXT	0
# endif
    {'e', PARENB | CS7, 0}
    ,				/* even                 */
    {'m', PARENB | CS7 | PARODD | PAREXT, 0}
    ,				/* mark                 */
    {'n', CS8, 0}
    ,				/* pass 8 bits, no parity */
    {'o', PARENB | CS7 | PARODD, 0}
    ,				/* odd                  */
    {'p', CS8, 0}
    ,				/* pass 8 bits, no parity */
    {'s', PARENB | CS7 | PAREXT, 0}
    ,				/* space                */
#else				/* ! HAVE_TERMIOS_H */
    {'e', EVENP, ODDP}
    ,				/* even                                 */
    {'m', EVENP | ODDP, 0}
    ,				/* mark                                 */
    {'o', ODDP, EVENP}
    ,				/* odd                                  */
# if defined(PASS8)
    {'n', PASS8, EVENP | ODDP}
    ,				/* pass 8 bits, no parity               */
    {'p', PASS8, EVENP | ODDP}
    ,				/* pass 8 bits, no parity               */
# endif
    {'s', 0, EVENP | ODDP}	/* space                                */
#endif
};

/* find a parity on the end of a baud "9600even" -> EVEN		(ksb)
 */
PARITY *
#if PROTOTYPES
FindParity(char *pcMode)
#else
FindParity(pcMode)
    char *pcMode;
#endif
{
    int i;
    char acFirst;

    while (isdigit((int)(*pcMode))) {
	++pcMode;
    }
    acFirst = *pcMode;
    if (isupper((int)(acFirst)))
	acFirst = tolower(acFirst);
    for (i = 0; i < sizeof(parity) / sizeof(struct parity); ++i) {
	if (acFirst != parity[i].ckey)
	    continue;
	return parity + i;
    }
    return parity;
}


#if HAVE_TERMIOS_H
/* setup a tty device							(ksb)
 */
static int
#if PROTOTYPES
TtyDev(CONSENT * pCE, fd_set * pfdSet)
#else
TtyDev(pCE, pfdSet)
    CONSENT *pCE;
    fd_set *pfdSet;
#endif
{
    struct termios termp;
    struct stat stPerm;

    /* here we should fstat for `read-only' checks
     */
    if (-1 == fstat(pCE->fdtty, &stPerm)) {
	Error("[%s] fstat(%s(%d)): %s: forcing down", pCE->server.string,
	      pCE->dfile.string, pCE->fdtty, strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    } else if (0 == (stPerm.st_mode & 0222)) {
	/* any device that is read-only we won't write to
	 */
	pCE->fronly = 1;
    }

    /*
     * Get terminal attributes
     */
    if (-1 == tcgetattr(pCE->fdtty, &termp)) {
	Error("[%s] tcgetattr(%s(%d)): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }

    /*
     * Turn off:    echo
     *              icrnl
     *              opost   No post processing
     *              icanon  No line editing
     *              isig    No signal generation
     * Turn on:     ixoff
     */
    termp.c_iflag = IXON | IXOFF | BRKINT;
    termp.c_oflag = 0;
    /* CLOCAL suggested by egan@us.ibm.com
     * carrier transitions result in dropped consoles otherwise
     */
    termp.c_cflag = CREAD | CLOCAL;
    termp.c_cflag |= pCE->pparity->iset;
    termp.c_lflag = 0;
    /*
     * Set the VMIN == 1
     * Set the VTIME == 1 (0.1 sec)
     * Don't bother with the control characters as they are not used
     */
    termp.c_cc[VMIN] = 1;
    termp.c_cc[VTIME] = 1;

    if (-1 == cfsetospeed(&termp, pCE->pbaud->irate)) {
	Error("[%s] cfsetospeed(%s(%d)): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }
    if (-1 == cfsetispeed(&termp, pCE->pbaud->irate)) {
	Error("[%s] cfsetispeed(%s(%d)): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }

    /*
     * Set terminal attributes
     */
    if (-1 == tcsetattr(pCE->fdtty, TCSADRAIN, &termp)) {
	Error("[%s] tcsetattr(%s(%d),TCSADRAIN): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }
# if HAVE_STROPTS_H
    /*
     * eat all the streams modules upto and including ttcompat
     */
    while (ioctl(pCE->fdtty, I_FIND, "ttcompat") == 1) {
	ioctl(pCE->fdtty, I_POP, 0);
    }
# endif
    pCE->fup = 1;
    return 0;
}

#else /* ! HAVE_TERMIOS_H */

# if HAVE_SGTTY_H

/* setup a tty device							(ksb)
 */
static int
#if PROTOTYPES
TtyDev(CONSENT * pCE, fd_set * pfdSet)
#else
TtyDev(pCE)
    CONSENT *pCE;
    fd_set *pfdSet;
#endif
{
    struct sgttyb sty;
    struct tchars m_tchars;
    struct ltchars m_ltchars;
    struct stat stPerm;

    /* here we should fstat for `read-only' checks
     */
    if (-1 == fstat(pCE->fdtty, &stPerm)) {
	Error("[%s] fstat(%s(%d)): %s: forcing down", pCE->server.string,
	      pCE->dfile.string, pCE->fdtty, strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    } else if (0 == (stPerm.st_mode & 0222)) {
	/* any device that is read-only we won't write to
	 */
	pCE->fronly = 1;
    }
#  if defined(TIOCSSOFTCAR)
    if (-1 == ioctl(pCE->fdtty, TIOCSSOFTCAR, &fSoftcar)) {
	Error("[%s] ioctl(%s(%d),TIOCSSOFTCAR): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }
#  endif

    /* stty 9600 raw cs7
     */
    if (-1 == ioctl(pCE->fdtty, TIOCGETP, (char *)&sty)) {
	Error("[%s] ioctl(%s(%d),TIOCGETP): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }
    sty.sg_flags &= ~(ECHO | CRMOD | pCE->pparity->iclr);
    sty.sg_flags |= (CBREAK | TANDEM | pCE->pparity->iset);
    sty.sg_erase = -1;
    sty.sg_kill = -1;
    sty.sg_ispeed = pCE->pbaud->irate;
    sty.sg_ospeed = pCE->pbaud->irate;
    if (-1 == ioctl(pCE->fdtty, TIOCSETP, (char *)&sty)) {
	Error("[%s] ioctl(%s(%d),TIOCSETP): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }

    /* stty undef all tty chars
     * (in cbreak mode we may not need to this... but we do)
     */
    if (-1 == ioctl(pCE->fdtty, TIOCGETC, (char *)&m_tchars)) {
	Error("[%s] ioctl(%s(%d),TIOCGETC): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }
    m_tchars.t_intrc = -1;
    m_tchars.t_quitc = -1;
    m_tchars.t_startc = -1;
    m_tchars.t_stopc = -1;
    m_tchars.t_eofc = -1;
    m_tchars.t_brkc = -1;
    if (-1 == ioctl(pCE->fdtty, TIOCSETC, (char *)&m_tchars)) {
	Error("[%s] ioctl(%s(%d),TIOCSETC): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }
    if (-1 == ioctl(pCE->fdtty, TIOCGLTC, (char *)&m_ltchars)) {
	Error("[%s] ioctl(%s(%d),TIOCGLTC): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }
    m_ltchars.t_werasc = -1;
    m_ltchars.t_flushc = -1;
    m_ltchars.t_lnextc = -1;
    m_ltchars.t_suspc = -1;
    m_ltchars.t_dsuspc = -1;
    if (-1 == ioctl(pCE->fdtty, TIOCSLTC, (char *)&m_ltchars)) {
	Error("[%s] ioctl(%s(%d),TIOCSLTC): %s: forcing down",
	      pCE->server.string, pCE->dfile.string, pCE->fdtty,
	      strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return -1;
    }
#  if HAVE_STROPTS_H
    /* pop off the un-needed streams modules (on a sun3 machine esp.)
     * (Idea by jrs@ecn.purdue.edu)
     */
    while (ioctl(pCE->fdtty, I_POP, 0) == 0) {
	/* eat all the streams modules */ ;
    }
#  endif
    pCE->fup = 1;
    return 0;
}
# endif	/* HAVE_SGTTY_H */

#endif /* HAVE_TERMIOS_H */

/* setup a virtual device						(ksb)
 */
static int
#if PROTOTYPES
VirtDev(CONSENT * pCE)
#else
VirtDev(pCE)
    CONSENT *pCE;
#endif
{
# if HAVE_TERMIOS_H
    static struct termios n_tio;
# else
#  if HAVE_SGTTY_H
    struct sgttyb sty;
    struct tchars m_tchars;
    struct ltchars m_ltchars;
#  endif
# endif
    int i;
    pid_t iNewGrp;
    extern char **environ;
    char *pcShell, **ppcArgv;

    fflush(stdout);
    fflush(stderr);

    switch (pCE->ipid = fork()) {
	case -1:
	    return -1;
	case 0:
	    thepid = getpid();
	    break;
	default:
	    Verbose("[%s] pid %lu on %s", pCE->server.string, pCE->ipid,
		    pCE->acslave.string);
	    fflush(stderr);
	    pCE->fup = 1;
	    return 0;
    }

    /* put the signals back that we ignore (trapped auto-reset to default)
     */
    SimpleSignal(SIGQUIT, SIG_DFL);
    SimpleSignal(SIGINT, SIG_DFL);
    SimpleSignal(SIGPIPE, SIG_DFL);
#if defined(SIGTTOU)
    SimpleSignal(SIGTTOU, SIG_DFL);
#endif
#if defined(SIGTTIN)
    SimpleSignal(SIGTTIN, SIG_DFL);
#endif
#if defined(SIGTSTP)
    SimpleSignal(SIGTSTP, SIG_DFL);
#endif
#if defined(SIGPOLL)
    SimpleSignal(SIGPOLL, SIG_DFL);
#endif

    /* setup new process with clean filew descriptors
     */
    i = GetMaxFiles();
    for ( /* i above */ ; --i > 2;) {
	close(i);
    }
    /* leave 2 until we *have to close it*
     */
    close(1);
    close(0);

# if HAVE_SETSID
    iNewGrp = setsid();
    if (-1 == iNewGrp) {
	Error("[%s] setsid(): %s", pCE->server.string, strerror(errno));
	iNewGrp = getpid();
    }
# else
    iNewGrp = getpid();
# endif

    if (0 != open(pCE->acslave.string, O_RDWR, 0) || 1 != dup(0)) {
	Error("[%s] fd sync error", pCE->server.string);
	Bye(EX_OSERR);
    }
# if HAVE_STROPTS_H  && !defined(_AIX)
    /* SYSVr4 semantics for opening stream ptys                     (gregf)
     * under PTX (others?) we have to push the compatibility
     * streams modules `ptem', `ld', and `ttcompat'
     */
    Debug(1, "VirtDev(): pushing ptemp onto pseudo-terminal");
    ioctl(0, I_PUSH, "ptem");
    Debug(1, "VirtDev(): pushing ldterm onto pseudo-terminal");
    ioctl(0, I_PUSH, "ldterm");
    Debug(1, "VirtDev(): pushing ttcompat onto pseudo-terminal");
    ioctl(0, I_PUSH, "ttcompat");
    Debug(1, "VirtDev(): done pushing modules onto pseudo-terminal");
# endif

# if HAVE_TERMIOS_H
#  if HAVE_TCGETATTR
    if (0 != tcgetattr(0, &n_tio))
#  else
    if (0 != ioctl(0, TCGETS, &n_tio))
#  endif
    {
	Error("[%s] ioctl(0,TCGETS): %s", pCE->server.string,
	      strerror(errno));
	Bye(EX_OSERR);
    }
    n_tio.c_iflag &= ~(IGNCR | IUCLC);
    n_tio.c_iflag |= ICRNL | IXON | IXANY;
    n_tio.c_oflag &=
	~(OLCUC | ONOCR | ONLRET | OFILL | NLDLY | CRDLY | TABDLY | BSDLY);
    n_tio.c_oflag |= OPOST | ONLCR;
    n_tio.c_lflag &= ~(XCASE | NOFLSH | ECHOK | ECHONL);
    n_tio.c_lflag |= ISIG | ICANON | ECHO;
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
#  if HAVE_TCSETATTR
    if (0 != tcsetattr(0, TCSANOW, &n_tio))
#  else
    if (0 != ioctl(0, TCSETS, &n_tio))
#  endif
    {
	Error("[%s] ioctl(0,TCSETS): %s", pCE->server.string,
	      strerror(errno));
	Bye(EX_OSERR);
    }

    tcsetpgrp(0, iNewGrp);
# else /* ! HAVE_TERMIOS_H */
    /* stty 9600 raw cs7
     */
    if (-1 == ioctl(0, TIOCGETP, (char *)&sty)) {
	Error("[%s] ioctl(0,TIOCGETP): %s", pCE->server.string,
	      strerror(errno));
	Bye(EX_OSERR);
    }
    sty.sg_flags &= ~(CBREAK | TANDEM | pCE->pparity->iclr);
    sty.sg_flags |= (ECHO | CRMOD | pCE->pparity->iset);
    sty.sg_erase = '\b';
    sty.sg_kill = '\025';
    sty.sg_ispeed = pCE->pbaud->irate;
    sty.sg_ospeed = pCE->pbaud->irate;
    if (-1 == ioctl(0, TIOCSETP, (char *)&sty)) {
	Error("[%s] ioctl(0,TIOCSETP): %s", pCE->server.string,
	      strerror(errno));
	Bye(EX_OSERR);
    }

    /* stty undef all tty chars
     * (in cbreak mode we may not need to this... but we do)
     */
    if (-1 == ioctl(0, TIOCGETC, (char *)&m_tchars)) {
	Error("[%s] ioctl(0,TIOCGETC): %s", pCE->server.string,
	      strerror(errno));
	Bye(EX_OSERR);
    }
    m_tchars.t_intrc = '\003';
    m_tchars.t_quitc = '\034';
    m_tchars.t_startc = '\021';
    m_tchars.t_stopc = '\023';
    m_tchars.t_eofc = '\004';
    m_tchars.t_brkc = '\033';
    if (-1 == ioctl(0, TIOCSETC, (char *)&m_tchars)) {
	Error("[%s] ioctl(0,TIOCSETC): %s", pCE->server.string,
	      strerror(errno));
	Bye(EX_OSERR);
    }
    if (-1 == ioctl(0, TIOCGLTC, (char *)&m_ltchars)) {
	Error("[%s] ioctl(0,TIOCGLTC): %s", pCE->server.string,
	      strerror(errno));
	Bye(EX_OSERR);
    }
    m_ltchars.t_werasc = '\027';
    m_ltchars.t_flushc = '\017';
    m_ltchars.t_lnextc = '\026';
    m_ltchars.t_suspc = '\032';
    m_ltchars.t_dsuspc = '\031';
    if (-1 == ioctl(0, TIOCSLTC, (char *)&m_ltchars)) {
	Error("[%s] ioctl(0,TIOCSLTC): %s", pCE->server.string,
	      strerror(errno));
	Bye(EX_OSERR);
    }

    /* give us a process group to work in
     */
    ioctl(0, TIOCGPGRP, (char *)&i);
#  ifndef SETPGRP_VOID
    setpgrp(0, i);
#  endif
    ioctl(0, TIOCSPGRP, (char *)&iNewGrp);
#  ifndef SETPGRP_VOID
    setpgrp(0, iNewGrp);
#  endif
# endif	/* HAVE_TERMIOS_H */

    close(2);
    dup(1);			/* better be 2, but it is too late now */

    /* if the command is null we should run root's shell, directly
     * if we can't find root's shell run /bin/sh
     */
    pcShell = "/bin/sh";
    if (pCE->pccmd.used <= 1) {
	static char *apcArgv[] = {
	    "-shell", "-i", (char *)0
	};
	struct passwd *pwd;

	if ((struct passwd *)0 != (pwd = getpwuid(0)) &&
	    '\000' != pwd->pw_shell[0]) {
	    pcShell = pwd->pw_shell;
	}
	ppcArgv = apcArgv;
    } else {
	static char *apcArgv[] = {
	    "/bin/sh", "-ce", (char *)0, (char *)0
	};

	apcArgv[2] = pCE->pccmd.string;
	ppcArgv = apcArgv;
    }
    execve(pcShell, ppcArgv, environ);
    Error("[%s] execve(): %s", pCE->server.string, strerror(errno));
    Bye(EX_OSERR);
    return -1;
}

/* down a console, virtual or real					(ksb)
 */
void
#if PROTOTYPES
ConsDown(CONSENT * pCE, fd_set * pfdSet, short downHard)
#else
ConsDown(pCE, pfdSet, downHard)
    CONSENT *pCE;
    fd_set *pfdSet;
    short downHard;
#endif
{
    if (-1 != pCE->ipid) {
	Debug(1, "ConsDown(): sending pid %lu signal %d",
	      (unsigned long)pCE->ipid, SIGHUP);
	kill(pCE->ipid, SIGHUP);
	pCE->ipid = -1;
    }
    if (-1 != pCE->fdtty) {
	if ((fd_set *) 0 != pfdSet)
	    FD_CLR(pCE->fdtty, pfdSet);
	close(pCE->fdtty);
	pCE->fdtty = -1;
    }
    if ((CONSFILE *) 0 != pCE->fdlog) {
	if (pCE->nolog) {
	    TagLogfile(pCE, "Console logging restored");
	}
	TagLogfile(pCE, "Console down");
	FileClose(&pCE->fdlog);
	pCE->fdlog = (CONSFILE *) 0;
    }
    pCE->fup = 0;
    pCE->nolog = 0;
    pCE->autoReUp = 0;
    pCE->downHard = downHard;
}

int
#if PROTOTYPES
CheckHostCache(const char *hostname)
#else
CheckHostCache(hostname)
    const char *hostname;
#endif
{
    struct hostcache *p;
    p = hostcachelist;
    while (p != NULL) {
	if (0 == strcasecmp(hostname, p->hostname.string)) {
	    return 1;
	}
	p = p->next;
    }
    return 0;
}

void
#if PROTOTYPES
AddHostCache(const char *hostname)
#else
AddHostCache(hostname)
    const char *hostname;
#endif
{
    struct hostcache *n;
    if ((struct hostcache *)0 ==
	(n = (struct hostcache *)calloc(1, sizeof(struct hostcache)))) {
	Error("AddHostCache(): calloc(): %s", strerror(errno));
	return;
    }
    BuildString(hostname, &n->hostname);
    n->next = hostcachelist;
    hostcachelist = n;
}

void
#if PROTOTYPES
ClearHostCache(void)
#else
ClearHostCache()
#endif
{
    struct hostcache *p, *n;
    p = hostcachelist;
    while (p != NULL) {
	n = p->next;
	if (p->hostname.allocated)
	    free(p->hostname.string);
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
#if PROTOTYPES
ConsInit(CONSENT * pCE, fd_set * pfdSet, short useHostCache)
#else
ConsInit(pCE, pfdSet, useHostCache)
    CONSENT *pCE;
    fd_set *pfdSet;
    short useHostCache;
#endif
{
    time_t tyme;
    extern int FallBack PARAMS((STRING *, STRING *));

    if (!useHostCache)
	ClearHostCache();

    /* clean up old stuff
     */
    if (pCE->fup) {
	ConsDown(pCE, pfdSet, 0);
	usleep(500000);		/* pause 0.50 sec to let things settle a bit */
	ResetMark();
    }

    pCE->autoReUp = 0;
    pCE->fronly = 0;
    pCE->nolog = 0;
    pCE->iend = 0;


    /* try to open them again
     */
    if ((CONSFILE *) 0 ==
	(pCE->fdlog =
	 FileOpen(pCE->lfile.string, O_RDWR | O_CREAT | O_APPEND, 0644))) {
	Error("[%s] FileOpen(%s): %s: forcing down", pCE->server.string,
	      pCE->lfile.string, strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return;
    }

    TagLogfile(pCE, "Console up");

    if (0 != pCE->fvirtual) {
	if (-1 == (pCE->fdtty = FallBack(&pCE->acslave, &pCE->dfile))) {
	    Error("[%s] failed to allocate pseudo-tty: %s: forcing down",
		  pCE->server.string, strerror(errno));
	    ConsDown(pCE, pfdSet, 1);
	    return;
	}
    } else if (pCE->isNetworkConsole) {
	struct sockaddr_in port;
	struct hostent *hp;
	size_t one = 1;
	int flags;
	fd_set fds;
	struct timeval tv;

	if (CheckHostCache(pCE->networkConsoleHost.string)) {
	    Error("[%s] cached previous timeout: %s: forcing down",
		  pCE->server.string, pCE->networkConsoleHost.string);
	    ConsDown(pCE, pfdSet, 1);
	    return;
	}
	usleep(100000);		/* Not all terminal servers can keep up */
	ResetMark();

#if HAVE_MEMSET
	memset((void *)&port, 0, sizeof(port));
#else
	bzero((char *)&port, sizeof(port));
#endif

	if ((hp = gethostbyname(pCE->networkConsoleHost.string)) == NULL) {
	    Error("[%s] gethostbyname(%s): %s: forcing down",
		  pCE->server.string, pCE->networkConsoleHost.string,
		  hstrerror(h_errno));
	    ConsDown(pCE, pfdSet, 1);
	    return;
	}
#if HAVE_MEMCPY
	memcpy(&port.sin_addr.s_addr, hp->h_addr, hp->h_length);
#else
	bcopy(hp->h_addr, &port.sin_addr.s_addr, hp->h_length);
#endif
	port.sin_family = hp->h_addrtype;
	port.sin_port = htons(pCE->networkConsolePort);

	if ((pCE->fdtty = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	    Error("[%s] socket(AF_INET,SOCK_STREAM): %s: forcing down",
		  pCE->server.string, strerror(errno));
	    ConsDown(pCE, pfdSet, 1);
	    return;
	}
	if (setsockopt
	    (pCE->fdtty, SOL_SOCKET, SO_KEEPALIVE, (char *)&one,
	     sizeof(one)) < 0) {
	    Error("[%s] setsockopt(%u,SO_KEEPALIVE): %s: forcing down",
		  pCE->server.string, pCE->fdtty, strerror(errno));
	    ConsDown(pCE, pfdSet, 1);
	    return;
	}

	if ((flags = fcntl(pCE->fdtty, F_GETFL)) >= 0) {
	    flags |= O_NONBLOCK;
	    if (fcntl(pCE->fdtty, F_SETFL, flags) < 0) {
		Error("[%s] fcntl(%u,F_SETFL): %s: forcing down",
		      pCE->server.string, pCE->fdtty, strerror(errno));
		ConsDown(pCE, pfdSet, 1);
		return;
	    }
	} else {
	    Error("[%s] fcntl(%u,F_GETFL): %s: forcing down",
		  pCE->server.string, pCE->fdtty, strerror(errno));
	    ConsDown(pCE, pfdSet, 1);
	    return;
	}

	if (connect(pCE->fdtty, (struct sockaddr *)&port, sizeof(port)) <
	    0) {
	    if (errno != EINPROGRESS) {
		Error("[%s] connect(%u): %s: forcing down",
		      pCE->server.string, pCE->fdtty, strerror(errno));
		ConsDown(pCE, pfdSet, 1);
		return;
	    }
	}

	tv.tv_sec = CONNECTTIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(pCE->fdtty, &fds);

	if ((one = select(pCE->fdtty + 1, NULL, &fds, NULL, &tv)) < 0) {
	    Error("[%s] select(%u): %s: forcing down", pCE->server.string,
		  pCE->fdtty, strerror(errno));
	    ConsDown(pCE, pfdSet, 1);
	    return;
	}

	if (one == 0) {		/* Timeout */
	    AddHostCache(pCE->networkConsoleHost.string);
	    Error("[%s] connect timeout: forcing down", pCE->server.string,
		  strerror(errno));
	    ConsDown(pCE, pfdSet, 1);
	    return;
	} else {		/* Response */
	    socklen_t slen;
	    flags = 0;
	    slen = sizeof(flags);
	    /* So, getsockopt seems to return -1 if there is something
	       interesting in SO_ERROR under solaris...sheesh.  So,
	       the error message has the small change it's not accurate. */
	    if (getsockopt
		(pCE->fdtty, SOL_SOCKET, SO_ERROR, (char *)&flags,
		 &slen) < 0) {
		Error("[%s] getsockopt(%u,SO_ERROR): %s: forcing down",
		      pCE->server.string, pCE->fdtty, strerror(errno));
		ConsDown(pCE, pfdSet, 1);
		return;
	    }
	    if (flags != 0) {
		Error("[%s] connect(%u): %s: forcing down",
		      pCE->server.string, pCE->fdtty, strerror(flags));
		ConsDown(pCE, pfdSet, 1);
		return;
	    }
	}

# if POKE_ANNEX
	/*
	 * Poke the connection to get the annex to wake up and
	 * register this connection.
	 */
	write(pCE->fdtty, "\r\n", 2);
# endif
    } else if (-1 ==
	       (pCE->fdtty =
		open(pCE->dfile.string, O_RDWR | O_NDELAY, 0600))) {
	Error("[%s] open(%s): %s: forcing down", pCE->server.string,
	      pCE->dfile.string, strerror(errno));
	ConsDown(pCE, pfdSet, 1);
	return;
    }
    FD_SET(pCE->fdtty, pfdSet);

    /* ok, now setup the device
     */
    if (pCE->fvirtual) {
	VirtDev(pCE);
    } else if (pCE->isNetworkConsole) {
	pCE->fup = 1;
    } else {
	TtyDev(pCE, pfdSet);
    }

    /* If we have marks, adjust the next one so that it's in the future */
    if (pCE->nextMark > 0) {
	tyme = time((time_t *) 0);
	if (tyme >= pCE->nextMark) {
	    /* Add as many pCE->mark values as necessary so that we move
	     * beyond the current time.
	     */
	    pCE->nextMark +=
		(((tyme - pCE->nextMark) / pCE->mark) + 1) * pCE->mark;
	}
    }

    if (pCE->downHard && pCE->fup) {
	Msg("[%s] console up", pCE->server.string);
	pCE->downHard = 0;
    }
}
