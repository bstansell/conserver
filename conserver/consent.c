/*
 *  $Id: consent.c,v 5.145 2005/06/08 18:09:40 bryan Exp $
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

#include <compat.h>

#include <pwd.h>

#include <cutil.h>
#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <readcfg.h>
#include <main.h>


BAUD baud[] = {
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
#if defined(B9600)
    {"9600", B9600},
#endif
#if defined(B4800)
    {"4800", B4800},
#endif
#if defined(B2400)
    {"2400", B2400},
#endif
#if defined(B1800)
    {"1800", B1800},
#endif
    {"1200", B1200},
#if defined(B600)
    {"600", B600},
#endif
#if defined(B300)
    {"300", B300},
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
	if (strcmp(pcMode, baud[i].acrate) == 0)
	    return baud + i;
    }
    return (BAUD *)0;
}


# if !defined(PAREXT)
#  define PAREXT	0
# endif
struct parity parity[] = {
    {"even", PARENB | CS7, 0},
    {"mark", PARENB | CS7 | PARODD | PAREXT, 0},
    {"none", CS8, 0},
    {"odd", PARENB | CS7 | PARODD, 0},
    {"space", PARENB | CS7 | PAREXT, 0},
};

/* find a parity "even" or "E" or "ev" -> EVEN
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

    for (i = 0; i < sizeof(parity) / sizeof(struct parity); ++i) {
	if (strcasecmp(pcMode, parity[i].key) == 0)
	    return parity + i;
    }
    return (PARITY *)0;
}


/* setup a tty device							(ksb)
 */
static int
#if PROTOTYPES
TtyDev(CONSENT *pCE)
#else
TtyDev(pCE)
    CONSENT *pCE;
#endif
{
    struct termios termp;
    struct stat stPerm;
    int cofile;

    cofile = FileFDNum(pCE->cofile);

    /* here we should fstat for `read-only' checks
     */
    if (-1 == fstat(cofile, &stPerm)) {
	Error("[%s] fstat(%s(%d)): %s: forcing down", pCE->server,
	      pCE->device, cofile, strerror(errno));
	ConsDown(pCE, FLAGTRUE, FLAGTRUE);
	return -1;
    } else if (0 == (stPerm.st_mode & 0222)) {
	/* any device that is read-only we won't write to
	 */
	pCE->fronly = 1;
    }

    /*
     * Get terminal attributes
     */
    if (-1 == tcgetattr(cofile, &termp)) {
	Error("[%s] tcgetattr(%s(%d)): %s: forcing down", pCE->server,
	      pCE->device, cofile, strerror(errno));
	ConsDown(pCE, FLAGTRUE, FLAGTRUE);
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
    termp.c_iflag = BRKINT;
    if (pCE->ixon == FLAGTRUE)
	termp.c_iflag |= IXON;
    if (pCE->ixany == FLAGTRUE)
	termp.c_iflag |= IXANY;
    if (pCE->ixoff == FLAGTRUE)
	termp.c_iflag |= IXOFF;
    termp.c_oflag = 0;
    /* CLOCAL suggested by egan@us.ibm.com
     * carrier transitions result in dropped consoles otherwise
     */
    termp.c_cflag = CREAD | CLOCAL;
    if (pCE->hupcl == FLAGTRUE)
	termp.c_cflag |= HUPCL;
    if (pCE->cstopb == FLAGTRUE)
	termp.c_cflag |= CSTOPB;
#if defined(CRTSCTS)
    if (pCE->crtscts == FLAGTRUE)
	termp.c_cflag |= CRTSCTS;
#endif
    termp.c_cflag |= pCE->parity->iset;
    termp.c_lflag = 0;
    /*
     * Set the VMIN == 1
     * Set the VTIME == 1 (0.1 sec)
     * Don't bother with the control characters as they are not used
     */
    termp.c_cc[VMIN] = 1;
    termp.c_cc[VTIME] = 1;

    if (-1 == cfsetospeed(&termp, pCE->baud->irate)) {
	Error("[%s] cfsetospeed(%s(%d)): %s: forcing down", pCE->server,
	      pCE->device, cofile, strerror(errno));
	ConsDown(pCE, FLAGTRUE, FLAGTRUE);
	return -1;
    }
    if (-1 == cfsetispeed(&termp, pCE->baud->irate)) {
	Error("[%s] cfsetispeed(%s(%d)): %s: forcing down", pCE->server,
	      pCE->device, cofile, strerror(errno));
	ConsDown(pCE, FLAGTRUE, FLAGTRUE);
	return -1;
    }

    /*
     * Set terminal attributes
     */
    if (-1 == tcsetattr(cofile, TCSADRAIN, &termp)) {
	Error("[%s] tcsetattr(%s(%d),TCSADRAIN): %s: forcing down",
	      pCE->server, pCE->device, cofile, strerror(errno));
	ConsDown(pCE, FLAGTRUE, FLAGTRUE);
	return -1;
    }
    if (fDebug >= 2) {
	int i;
	Debug(2, "TtyDev(): [%s] termp.c_iflag=%lu", pCE->server,
	      (unsigned long)termp.c_iflag);
	Debug(2, "TtyDev(): [%s] termp.c_oflag=%lu", pCE->server,
	      (unsigned long)termp.c_oflag);
	Debug(2, "TtyDev(): [%s] termp.c_cflag=%lu", pCE->server,
	      (unsigned long)termp.c_cflag);
	Debug(2, "TtyDev(): [%s] termp.c_lflag=%lu", pCE->server,
	      (unsigned long)termp.c_lflag);
#if defined(NCCS)
	for (i = 0; i < NCCS; i++) {
	    Debug(2, "TtyDev(): [%s] termp.c_cc[%d]=%lu", pCE->server, i,
		  (unsigned long)termp.c_cc[i]);
	}
#endif
    }
# if HAVE_STROPTS_H
    /*
     * eat all the streams modules upto and including ttcompat
     */
    while (ioctl(cofile, I_FIND, "ttcompat") == 1) {
	ioctl(cofile, I_POP, 0);
    }
# endif
    pCE->fup = 1;
    return 0;
}

void
#if PROTOTYPES
StopInit(CONSENT *pCE)
#else
StopInit(pCE)
    CONSENT *pCE;
#endif
{
    if (pCE->initcmd == (char *)0)
	return;

    if (pCE->initpid != 0) {
	kill(pCE->initpid, SIGHUP);
	CONDDEBUG((1, "StopInit(): sending initcmd pid %lu signal %d",
		   (unsigned long)pCE->initpid, SIGHUP));
	Msg("[%s] initcmd terminated: pid %lu", pCE->server,
	    (unsigned long)pCE->initpid);
	TagLogfileAct(pCE, "initcmd terminated");
	pCE->initpid = 0;
    }

    if (pCE->initfile != (CONSFILE *)0) {
	int initfile = FileFDNum(pCE->initfile);
	FD_CLR(initfile, &rinit);
	initfile = FileFDOutNum(pCE->initfile);
	FD_CLR(initfile, &winit);
	FileClose(&pCE->initfile);
	pCE->initfile = (CONSFILE *)0;
    }
}

/* invoke the initcmd command */
void
#if PROTOTYPES
StartInit(CONSENT *pCE)
#else
StartInit(pCE)
    CONSENT *pCE;
#endif
{
    int i;
    pid_t iNewGrp;
    extern char **environ;
    int pin[2];
    int pout[2];
    static char *apcArgv[] = {
	"/bin/sh", "-ce", (char *)0, (char *)0
    };

    if (pCE->initcmd == (char *)0)
	return;

    /* this should never happen, but hey, just in case */
    if (pCE->initfile != (CONSFILE *)0 || pCE->initpid != 0) {
	Error("[%s] StartInit(): initpid/initfile sync error",
	      pCE->server);
	StopInit(pCE);
    }

    /* pin[0] = parent read, pin[1] = child write */
    if (pipe(pin) != 0) {
	Error("[%s] StartInit(): pipe(): %s", pCE->server,
	      strerror(errno));
	return;
    }
    /* pout[0] = child read, pout[l] = parent write */
    if (pipe(pout) != 0) {
	close(pin[0]);
	close(pin[1]);
	Error("[%s] StartInit(): pipe(): %s", pCE->server,
	      strerror(errno));
	return;
    }

    fflush(stdout);
    fflush(stderr);

    switch (pCE->initpid = fork()) {
	case -1:
	    pCE->initpid = 0;
	    return;
	case 0:
	    thepid = getpid();
	    break;
	default:
	    close(pout[0]);
	    close(pin[1]);
	    if ((pCE->initfile =
		 FileOpenPipe(pin[0], pout[1])) == (CONSFILE *)0) {
		Error("[%s] FileOpenPipe(%d,%d) failed: forcing down",
		      pCE->server, pin[0], pout[1]);
		close(pin[0]);
		close(pout[1]);
		kill(pCE->initpid, SIGHUP);
		pCE->initpid = 0;
		return;
	    }
	    Msg("[%s] initcmd started: pid %lu", pCE->server,
		(unsigned long)pCE->initpid);
	    TagLogfileAct(pCE, "initcmd started");
	    FD_SET(pin[0], &rinit);
	    if (maxfd < pin[0] + 1)
		maxfd = pin[0] + 1;
	    fflush(stderr);
	    return;
    }

    close(pin[0]);
    close(pout[1]);

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

    /* setup new process with clean file descriptors
     */
    i = GetMaxFiles();
    for ( /* i above */ ; --i > 2;) {
	if (i != pout[0] && i != pin[1])
	    close(i);
    }
    /* leave 2 until we have to close it */
    close(1);
    close(0);

# if HAVE_SETSID
    iNewGrp = setsid();
    if (-1 == iNewGrp) {
	Error("[%s] setsid(): %s", pCE->server, strerror(errno));
	iNewGrp = getpid();
    }
# else
    iNewGrp = getpid();
# endif

    if (dup(pout[0]) != 0 || dup(pin[1]) != 1) {
	Error("[%s] StartInit(): fd sync error", pCE->server);
	Bye(EX_OSERR);
    }
    close(pout[0]);
    close(pin[1]);

    if (geteuid() == 0) {
	if (pCE->initgid != 0)
	    setgid(pCE->initgid);
	if (pCE->inituid != 0)
	    setuid(pCE->inituid);
    }

    tcsetpgrp(0, iNewGrp);

    apcArgv[2] = pCE->initcmd;

    close(2);
    dup(1);			/* better be 2, but it is too late now */

    execve(apcArgv[0], apcArgv, environ);
    Error("[%s] execve(%s): %s", pCE->server, apcArgv[2], strerror(errno));
    Bye(EX_OSERR);
    return;
}

/* setup a virtual device						(ksb)
 */
static int
#if PROTOTYPES
VirtDev(CONSENT *pCE)
#else
VirtDev(pCE)
    CONSENT *pCE;
#endif
{
    static struct termios n_tio;
    int i;
    pid_t iNewGrp;
    extern char **environ;
    char *pcShell, **ppcArgv;

    fflush(stdout);
    fflush(stderr);

    switch (pCE->ipid = fork()) {
	case -1:
	    pCE->ipid = 0;
	    return -1;
	case 0:
	    thepid = getpid();
	    break;
	default:
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
	if (i != pCE->execSlaveFD)
	    close(i);
    }
    /* leave 2 until we *have to close it*
     */
    close(1);
    close(0);

# if HAVE_SETSID
    iNewGrp = setsid();
    if (-1 == iNewGrp) {
	Error("[%s] setsid(): %s", pCE->server, strerror(errno));
	iNewGrp = getpid();
    }
# else
    iNewGrp = getpid();
# endif

    if (dup(pCE->execSlaveFD) != 0 || dup(pCE->execSlaveFD) != 1) {
	Error("[%s] fd sync error", pCE->server);
	Bye(EX_OSERR);
    }

    if (geteuid() == 0) {
	if (pCE->execgid != 0)
	    setgid(pCE->execgid);
	if (pCE->execuid != 0) {
	    fchown(0, pCE->execuid, -1);
	    setuid(pCE->execuid);
	}
    }
# if HAVE_STROPTS_H  && !defined(_AIX)
    /* SYSVr4 semantics for opening stream ptys                     (gregf)
     * under PTX (others?) we have to push the compatibility
     * streams modules `ptem', `ld', and `ttcompat'
     */
    CONDDEBUG((1, "VirtDev(): pushing ptemp onto pseudo-terminal"));
    ioctl(0, I_PUSH, "ptem");
    CONDDEBUG((1, "VirtDev(): pushing ldterm onto pseudo-terminal"));
    ioctl(0, I_PUSH, "ldterm");
    CONDDEBUG((1, "VirtDev(): pushing ttcompat onto pseudo-terminal"));
    ioctl(0, I_PUSH, "ttcompat");
    CONDDEBUG((1, "VirtDev(): done pushing modules onto pseudo-terminal"));
# endif

    if (0 != tcgetattr(0, &n_tio)) {
	Error("[%s] tcgetattr(0): %s", pCE->server, strerror(errno));
	Bye(EX_OSERR);
    }
    n_tio.c_iflag &= ~(IGNCR | IUCLC);
    n_tio.c_iflag |= ICRNL;
    if (pCE->ixon == FLAGTRUE)
	n_tio.c_iflag |= IXON;
    if (pCE->ixany == FLAGTRUE)
	n_tio.c_iflag |= IXANY;
    if (pCE->ixoff == FLAGTRUE)
	n_tio.c_iflag |= IXOFF;
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
    if (0 != tcsetattr(0, TCSANOW, &n_tio)) {
	Error("[%s] tcsetattr(0,TCSANOW): %s", pCE->server,
	      strerror(errno));
	Bye(EX_OSERR);
    }

    tcsetpgrp(0, iNewGrp);

    /* if the command is null we should run root's shell, directly
     * if we can't find root's shell run /bin/sh
     */
    pcShell = "/bin/sh";
    if (pCE->exec == (char *)0) {
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

	apcArgv[2] = pCE->exec;
	ppcArgv = apcArgv;
    }

    close(2);
    dup(1);			/* better be 2, but it is too late now */

    execve(pcShell, ppcArgv, environ);
    Error("[%s] execve(): %s", pCE->server, strerror(errno));
    Bye(EX_OSERR);
    return -1;
}

char *
#if PROTOTYPES
ConsState(CONSENT *pCE)
#else
ConsState(pCE)
    CONSENT *pCE;
#endif
{
    if (!pCE->fup)
	return "down";

    if (pCE->initfile != (CONSFILE *)0)
	return "initializing";

    switch (pCE->ioState) {
	case ISNORMAL:
	    return "up";
	case INCONNECT:
	    return "connecting";
	case ISDISCONNECTED:
	    return "disconnected";
#if HAVE_OPENSSL
	case INSSLACCEPT:
	    return "SSL_accept";
	case INSSLSHUTDOWN:
	    return "SSL_shutdown";
#endif
	case ISFLUSHING:
	    return "flushing";
    }
    return "in unknown state";
}

/* down a console, virtual or real					(ksb)
 *
 * this should be kept pretty simple, 'cause the config file reading code
 * can come along and reconfigure a console out from under this - and it
 * expects to be able to call ConsDown() to shut it down.  so, only mess
 * with the "runtime" members of the structure here.
 */
void
#if PROTOTYPES
ConsDown(CONSENT *pCE, FLAG downHard, FLAG force)
#else
ConsDown(pCE, downHard, force)
    CONSENT *pCE;
    FLAG downHard;
    FLAG force;
#endif
{
    if (force != FLAGTRUE &&
	!(FileBufEmpty(pCE->fdlog) && FileBufEmpty(pCE->cofile) &&
	  FileBufEmpty(pCE->initfile))) {
	pCE->ioState = ISFLUSHING;
	return;
    }

    StopInit(pCE);
    if (pCE->ipid != 0) {
	CONDDEBUG((1, "ConsDown(): sending pid %lu signal %d",
		   (unsigned long)pCE->ipid, SIGHUP));
	kill(pCE->ipid, SIGHUP);
	pCE->ipid = 0;
    }
    if (pCE->cofile != (CONSFILE *)0) {
	int cofile = FileFDNum(pCE->cofile);
	FD_CLR(cofile, &rinit);
	FD_CLR(cofile, &winit);
	FileClose(&pCE->cofile);
    }
    if (pCE->fdlog != (CONSFILE *)0) {
	if (pCE->nolog) {
	    TagLogfile(pCE, "Console logging restored");
	}
	TagLogfile(pCE, "Console down");
	FD_CLR(FileFDNum(pCE->fdlog), &winit);
	FileClose(&pCE->fdlog);
    }
    if (pCE->type == EXEC && pCE->execSlaveFD != 0) {
	close(pCE->execSlaveFD);
	pCE->execSlaveFD = 0;
    }
    pCE->fup = 0;
    pCE->nolog = 0;
    pCE->autoReUp = 0;
    pCE->downHard = downHard;
    pCE->ioState = ISDISCONNECTED;
}

/* set up a console the way it should be for use to work with it	(ksb)
 * also, recover from silo over runs by dropping the line and re-opening
 * We also maintian the select set for the caller.
 */
void
#if PROTOTYPES
ConsInit(CONSENT *pCE)
#else
ConsInit(pCE)
    CONSENT *pCE;
#endif
{
    time_t tyme;
    extern int FallBack PARAMS((char **, int *));
    int cofile = -1;
    int ret;
#if HAVE_GETTIMEOFDAY
    struct timeval tv;
#else
    time_t tv;
#endif

    if (pCE->spintimer > 0 && pCE->spinmax > 0) {
#if HAVE_GETTIMEOFDAY
	if (gettimeofday(&tv, (void *)0) == 0) {
	    /* less than pCE->spintimer seconds gone by? */
	    if ((tv.tv_sec <= pCE->lastInit.tv_sec + pCE->spintimer - 1)
		|| (tv.tv_sec == pCE->lastInit.tv_sec + 1 &&
		    tv.tv_usec <= pCE->lastInit.tv_usec)) {
#else
	if ((tv = time((time_t *)0)) != (time_t)-1) {
	    /* less than pCE->spintimer seconds gone by? (approx) */
	    if (tv <= pCE->lastInit + pCE->spintimer) {
#endif
		pCE->spincount++;
		if (pCE->spincount >= pCE->spinmax) {
		    pCE->spincount = 0;
		    pCE->lastInit = tv;
		    Error
			("[%s] initialization rate exceeded: forcing down",
			 pCE->server);
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}
	    } else
		pCE->spincount = 0;
	    pCE->lastInit = tv;
	} else
	    pCE->spincount = 0;
    }

    /* clean up old stuff
     */
    if (pCE->fup) {
	ConsDown(pCE, FLAGFALSE, FLAGTRUE);
	usleep(250000);		/* pause 0.25 sec to let things settle a bit */
    }

    pCE->autoReUp = 0;
    pCE->fronly = 0;
    pCE->nolog = 0;
    pCE->iend = 0;


    /* try to open them again
     */
    if (pCE->logfile != (char *)0) {
	if ((CONSFILE *)0 ==
	    (pCE->fdlog =
	     FileOpen(pCE->logfile, O_RDWR | O_CREAT | O_APPEND, 0644))) {
	    Error("[%s] FileOpen(%s): %s: forcing down", pCE->server,
		  pCE->logfile, strerror(errno));
	    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
	    return;
	}
    }

    TagLogfile(pCE, "Console up");

    switch (pCE->type) {
	case UNKNOWNTYPE:	/* shut up gcc */
	    break;
	case EXEC:
	    if ((cofile =
		 FallBack(&pCE->execSlave, &pCE->execSlaveFD)) == -1) {
		Error
		    ("[%s] failed to allocate pseudo-tty: %s: forcing down",
		     pCE->server, strerror(errno));
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	    }
	    if ((pCE->cofile =
		 FileOpenFD(cofile, simpleFile)) == (CONSFILE *)0) {
		Error
		    ("[%s] FileOpenFD(%d,simpleFile) failed: forcing down",
		     pCE->server, cofile);
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	    }
	    VirtDev(pCE);
	    pCE->ioState = ISNORMAL;
	    break;
	case HOST:
	    {
		struct sockaddr_in port;
		struct hostent *hp;
#if HAVE_SETSOCKOPT
		int one = 1;
#endif

		usleep(100000);	/* Not all terminal servers can keep up */

#if HAVE_MEMSET
		memset((void *)&port, 0, sizeof(port));
#else
		bzero((char *)&port, sizeof(port));
#endif

		if ((hp = gethostbyname(pCE->host)) == NULL) {
		    Error("[%s] gethostbyname(%s): %s: forcing down",
			  pCE->server, pCE->host, hstrerror(h_errno));
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}
#if HAVE_MEMCPY
		memcpy(&port.sin_addr.s_addr, hp->h_addr_list[0],
		       hp->h_length);
#else
		bcopy(hp->h_addr_list[0], &port.sin_addr.s_addr,
		      hp->h_length);
#endif
		port.sin_family = hp->h_addrtype;
		port.sin_port = htons(pCE->netport);

		if ((cofile = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		    Error
			("[%s] socket(AF_INET,SOCK_STREAM): %s: forcing down",
			 pCE->server, strerror(errno));
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}
#if HAVE_SETSOCKOPT
		if (setsockopt
		    (cofile, SOL_SOCKET, SO_KEEPALIVE, (char *)&one,
		     sizeof(one)) < 0) {
		    Error
			("[%s] setsockopt(%u,SO_KEEPALIVE): %s: forcing down",
			 pCE->server, cofile, strerror(errno));
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}
#endif

		if (!SetFlags(cofile, O_NONBLOCK, 0)) {
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}

		if ((ret =
		     connect(cofile, (struct sockaddr *)&port,
			     sizeof(port)))
		    < 0) {
		    if (errno != EINPROGRESS) {
			Error("[%s] connect(%u): %s: forcing down",
			      pCE->server, cofile, strerror(errno));
			ConsDown(pCE, FLAGTRUE, FLAGTRUE);
			return;
		    }
		}
	    }
	    if ((pCE->cofile =
		 FileOpenFD(cofile, simpleSocket)) == (CONSFILE *)0) {
		Error
		    ("[%s] FileOpenFD(%d,simpleSocket) failed: forcing down",
		     pCE->server, cofile);
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	    }
	    if (ret == 0) {
		pCE->ioState = ISNORMAL;
		pCE->stateTimer = 0;
	    } else {
		pCE->ioState = INCONNECT;
		pCE->stateTimer = time((time_t *)0) + CONNECTTIMEOUT;
		if (timers[T_STATE] == (time_t)0 ||
		    timers[T_STATE] > pCE->stateTimer)
		    timers[T_STATE] = pCE->stateTimer;
	    }
	    pCE->fup = 1;
	    break;
	case DEVICE:
	    if (-1 ==
		(cofile = open(pCE->device, O_RDWR | O_NONBLOCK, 0600))) {

		Error("[%s] open(%s): %s: forcing down", pCE->server,
		      pCE->device, strerror(errno));
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	    }
	    if ((pCE->cofile =
		 FileOpenFD(cofile, simpleFile)) == (CONSFILE *)0) {
		Error
		    ("[%s] FileOpenFD(%d,simpleFile) failed: forcing down",
		     pCE->server, cofile);
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	    }
	    TtyDev(pCE);
	    pCE->ioState = ISNORMAL;
	    break;
    }

    if (!pCE->fup) {
	pCE->ioState = ISDISCONNECTED;
	return;
    }

    switch (pCE->type) {
	case UNKNOWNTYPE:	/* shut up gcc */
	    break;
	case EXEC:
	    Verbose("[%s] pid %lu on %s", pCE->server, pCE->ipid,
		    pCE->execSlave);
	    break;
	case HOST:
	    Verbose("[%s] port %hu on %s", pCE->server, pCE->netport,
		    pCE->host);
	    break;
	case DEVICE:
	    Verbose("[%s] at %s%c on %s", pCE->server, pCE->baud->acrate,
		    pCE->parity->key[0], pCE->device);
	    break;
    }

    /* if we're waiting for connect() to finish, watch the
     * write bit, otherwise watch for the read bit
     */
    if (pCE->ioState == INCONNECT)
	FD_SET(cofile, &winit);
    else
	FD_SET(cofile, &rinit);
    if (maxfd < cofile + 1)
	maxfd = cofile + 1;

    tyme = time((time_t *)0);

    if (pCE->ioState == ISNORMAL) {
	pCE->lastWrite = tyme;
	if (pCE->idletimeout != (time_t)0 &&
	    (timers[T_CIDLE] == (time_t)0 ||
	     timers[T_CIDLE] > pCE->lastWrite + pCE->idletimeout))
	    timers[T_CIDLE] = pCE->lastWrite + pCE->idletimeout;
    }

    /* If we have marks, adjust the next one so that it's in the future */
    if (pCE->nextMark > 0) {
	if (tyme >= pCE->nextMark) {
	    /* Add as many pCE->mark values as necessary so that we move
	     * beyond the current time.
	     */
	    pCE->nextMark +=
		(((tyme - pCE->nextMark) / pCE->mark) + 1) * pCE->mark;
	}
    }

    if (pCE->downHard == FLAGTRUE) {
	if (pCE->ioState == ISNORMAL) {
	    Msg("[%s] console up", pCE->server);
	    pCE->downHard = FLAGFALSE;
	} else
	    Msg("[%s] console initializing", pCE->server);
    }
#if HAVE_GETTIMEOFDAY
    if (gettimeofday(&tv, (void *)0) == 0)
	pCE->lastInit = tv;
#else
    if ((tv = time((time_t *)0)) != (time_t)-1)
	pCE->lastInit = tv;
#endif

    if (pCE->ioState == ISNORMAL)
	StartInit(pCE);
}

int
#if PROTOTYPES
AddrsMatch(char *addr1, char *addr2)
#else
AddrsMatch(addr1, addr2)
    char *addr1;
    char *addr2;
#endif
{
    /* so, since we might use inet_addr, we're going to use
     * (in_addr_t)(-1) as a sign of an invalid ip address.
     * sad, but true.
     */
    in_addr_t inAddr1 = (in_addr_t) (-1);
    in_addr_t inAddr2 = (in_addr_t) (-1);
#if HAVE_INET_ATON
    struct in_addr inetAddr1;
    struct in_addr inetAddr2;
#endif

    /* first try simple character string match */
    if (strcasecmp(addr1, addr2) == 0)
	return 1;

    /* now try ip address match (could have leading zeros or something) */
#if HAVE_INET_ATON
    if (inet_aton(addr1, &inetAddr1) != 0)
	inAddr1 = inetAddr1.s_addr;
    if (inet_aton(addr2, &inetAddr2) != 0)
	inAddr2 = inetAddr2.s_addr;
#else
    inAddr1 = inet_addr(addr1);
    inAddr2 = inet_addr(addr2);
#endif

    /* if both are ip addresses, we just match */
    if (inAddr1 != (in_addr_t) (-1) && inAddr2 != (in_addr_t) (-1))
	return !
#if HAVE_MEMCMP
	    memcmp(&inAddr1, &inAddr2, sizeof(inAddr1))
#else
	    bcmp(&inAddr1, &inAddr2, sizeof(inAddr1))
#endif
	    ;

    /* both are hostnames...this sucks 'cause we have to copy one
     * list and compare it to the other
     */
    if (inAddr1 == (in_addr_t) (-1) && inAddr2 == (in_addr_t) (-1)) {
	struct hostent *he;
	int i, j, c;
	in_addr_t *addrs;

	if ((he = gethostbyname(addr1)) == (struct hostent *)0) {
	    Error("AddrsMatch(): gethostbyname(%s): %s", addr1,
		  hstrerror(h_errno));
	    return 0;
	}
	if (4 != he->h_length || AF_INET != he->h_addrtype) {
	    Error
		("AddrsMatch(): gethostbyname(%s): wrong address size (4 != %d) or address family (%d != %d)",
		 addr1, he->h_length, AF_INET, he->h_addrtype);
	    return 0;
	}
	for (i = 0; he->h_addr_list[i] != (char *)0; i++);
	c = i;
	addrs = (in_addr_t *) calloc(i, sizeof(in_addr_t));
	if (addrs == (in_addr_t *) 0)
	    OutOfMem();
	for (i = 0; i < c; i++) {
#if HAVE_MEMCPY
	    memcpy(&(addrs[i]), he->h_addr_list[i], he->h_length);
#else
	    bcopy(he->h_addr_list[i], &(addrs[i]), he->h_length);
#endif
	}

	/* now process the second hostname */
	if ((he = gethostbyname(addr2)) == (struct hostent *)0) {
	    Error("AddrsMatch(): gethostbyname(%s): %s", addr2,
		  hstrerror(h_errno));
	    free(addrs);
	    return 0;
	}
	if (4 != he->h_length || AF_INET != he->h_addrtype) {
	    Error
		("AddrsMatch(): gethostbyname(%s): wrong address size (4 != %d) or address family (%d != %d)",
		 addr2, he->h_length, AF_INET, he->h_addrtype);
	    free(addrs);
	    return 0;
	}
	for (j = 0; he->h_addr_list[j] != (char *)0; j++) {
	    for (i = 0; i < c; i++) {
		if (
#if HAVE_MEMCMP
		       memcmp(&(addrs[i]), he->h_addr_list[j],
			      he->h_length)
#else
		       bcmp(&(addrs[i]), he->h_addr_list[j], he->h_length)
#endif
		       == 0) {
		    free(addrs);
		    return 1;
		}
	    }
	}
	free(addrs);
    } else {			/* one hostname, one ip addr */
	in_addr_t *iaddr;
	char *addr;
	struct hostent *he;
	int i;

	if (inAddr1 == (in_addr_t) (-1)) {
	    addr = addr1;
	    iaddr = &inAddr2;
	} else {
	    addr = addr2;
	    iaddr = &inAddr1;
	}
	if ((he = gethostbyname(addr)) == (struct hostent *)0) {
	    Error("AddrsMatch(): gethostbyname(%s): %s", addr,
		  hstrerror(h_errno));
	    return 0;
	}
	if (4 != he->h_length || AF_INET != he->h_addrtype) {
	    Error
		("AddrsMatch(): wrong address size (4 != %d) or address family (%d != %d)",
		 he->h_length, AF_INET, he->h_addrtype);
	    return 0;
	}
	for (i = 0; he->h_addr_list[i] != (char *)0; i++) {
	    if (
#if HAVE_MEMCMP
		   memcmp(iaddr, he->h_addr_list[i], he->h_length)
#else
		   bcmp(iaddr, he->h_addr_list[i], he->h_length)
#endif
		   == 0)
		return 1;
	}
    }
    return 0;
}

/* thread ther list of uniq console server machines, aliases for	(ksb)
 * machines will screw us up
 */
REMOTE *
#if PROTOTYPES
FindUniq(REMOTE *pRCAll)
#else
FindUniq(pRCAll)
    REMOTE *pRCAll;
#endif
{
    REMOTE *pRC;

    /* INV: tail of the list we are building always contains only
     * uniq hosts, or the empty list.
     */
    if (pRCAll == (REMOTE *)0)
	return (REMOTE *)0;

    pRCAll->pRCuniq = FindUniq(pRCAll->pRCnext);

    /* if it is in the returned list of uniq hosts, return that list
     * else add us by returning our node
     */
    for (pRC = pRCAll->pRCuniq; (REMOTE *)0 != pRC; pRC = pRC->pRCuniq) {
	if (AddrsMatch(pRC->rhost, pRCAll->rhost))
	    return pRCAll->pRCuniq;
    }
    return pRCAll;
}

void
#if PROTOTYPES
DestroyRemoteConsole(REMOTE *pRCList)
#else
DestroyRemoteConsole(pRCList)
    REMOTE *pRCList;
#endif
{
    NAMES *name = (NAMES *)0;

    if (pRCList == (REMOTE *)0)
	return;
    if (pRCList->rserver != (char *)0)
	free(pRCList->rserver);
    if (pRCList->rhost != (char *)0)
	free(pRCList->rhost);
    while (pRCList->aliases != (NAMES *)0) {
	name = pRCList->aliases->next;
	if (pRCList->aliases->name != (char *)0)
	    free(pRCList->aliases->name);
	free(pRCList->aliases);
	pRCList->aliases = name;
    }
    free(pRCList);
}
