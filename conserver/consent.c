/*
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
#include <time.h>


BAUD baud[] = {
#if defined(FOR_CYCLADES_TS)
    {"0", 0},
    {"50", 1},
    {"75", 2},
    {"110", 3},
    {"134", 4},
    {"150", 5},
    {"200", 6},
    {"300", 7},
    {"600", 8},
    {"1200", 9},
    {"1800", 10},
    {"2400", 11},
    {"4800", 12},
    {"9600", 13},
    {"14400", 14},
    {"19200", 15},
    {"28800", 16},
    {"38400", 17},
    {"57600", 18},
    {"76800", 19},
    {"115200", 20},
    {"230400", 21},
    {"460800", 22},
    {"500000", 23},
    {"576000", 24},
    {"921600", 25},
    {"1000000", 26},
    {"1152000", 27},
    {"1500000", 28},
    {"2000000", 29},
    {"2500000", 30},
    {"3000000", 31},
    {"3500000", 32},
    {"4000000", 33},
#else /* FOR_CYCLADES_TS */
# if defined(B4000000)
    {"4000000", B4000000},
# endif
# if defined(B3500000)
    {"3500000", B3500000},
# endif
# if defined(B3000000)
    {"3000000", B3000000},
# endif
# if defined(B2500000)
    {"2500000", B2500000},
# endif
# if defined(B2000000)
    {"2000000", B2000000},
# endif
# if defined(B1500000)
    {"1500000", B1500000},
# endif
# if defined(B1152000)
    {"1152000", B1152000},
# endif
# if defined(B1000000)
    {"1000000", B1000000},
# endif
# if defined(B921600)
    {"921600", B921600},
# endif
# if defined(B576000)
    {"576000", B576000},
# endif
# if defined(B500000)
    {"500000", B500000},
# endif
# if defined(B460800)
    {"460800", B460800},
# endif
# if defined(B230400)
    {"230400", B230400},
# endif
# if defined(B115200)
    {"115200", B115200},
# endif
# if defined(B57600)
    {"57600", B57600},
# endif
# if defined(B38400)
    {"38400", B38400},
# endif
# if defined(B19200)
    {"19200", B19200},
# endif
# if defined(B9600)
    {"9600", B9600},
# endif
# if defined(B4800)
    {"4800", B4800},
# endif
# if defined(B2400)
    {"2400", B2400},
# endif
# if defined(B1800)
    {"1800", B1800},
# endif
    {"1200", B1200},
# if defined(B600)
    {"600", B600},
# endif
# if defined(B300)
    {"300", B300},
# endif
#endif /* FOR_CYCLADES_TS */
};


/* find a baud rate for the string "9600x" -> B9600			(ksb)
 */
BAUD *
FindBaud(char *pcMode)
{
    int i;

    for (i = 0; i < sizeof(baud) / sizeof(struct baud); ++i) {
	if (strcmp(pcMode, baud[i].acrate) == 0)
	    return baud + i;
    }
    return (BAUD *)0;
}


#if !defined(PAREXT)
# define PAREXT	0
#endif
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
FindParity(char *pcMode)
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
TtyDev(CONSENT *pCE)
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
#if HAVE_STROPTS_H
    /*
     * eat all the streams modules upto and including ttcompat
     */
    while (ioctl(cofile, I_FIND, "ttcompat") == 1) {
	ioctl(cofile, I_POP, 0);
    }
#endif
    pCE->fup = 1;
    return 0;
}

void
StopInit(CONSENT *pCE)
{
    if (pCE->initcmd == (char *)0)
	return;

    if (pCE->initpid != 0 || pCE->initfile != (CONSFILE *)0)
	SendIWaitClientsMsg(pCE,
			    (pCE->fup &&
			     pCE->ioState ==
			     ISNORMAL) ? "up]\r\n" : "down]\r\n");

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

#if HAVE_FREEIPMI
ipmiconsole_ctx_t
IpmiSOLCreate(CONSENT *pCE)
{
    ipmiconsole_ctx_t ctx;
    struct ipmiconsole_ipmi_config ipmi;
    struct ipmiconsole_protocol_config protocol;
    struct ipmiconsole_engine_config engine;

    if (ipmiconsole_engine_init(1, 0) < 0)
	return 0;

    ipmi.username = pCE->username;
    ipmi.password = pCE->password;
    if (pCE->ipmikg->used <= 1) {	/* 1 == NULL only */
	ipmi.k_g = NULL;
	ipmi.k_g_len = 0;
    } else {
	ipmi.k_g = (unsigned char *)pCE->ipmikg->string;
	ipmi.k_g_len = pCE->ipmikg->used - 1;
    }
    ipmi.privilege_level = pCE->ipmiprivlevel;
    ipmi.cipher_suite_id = pCE->ipmiciphersuite;
    ipmi.workaround_flags = pCE->ipmiworkaround;

    protocol.session_timeout_len = -1;
    protocol.retransmission_timeout_len = -1;
    protocol.retransmission_backoff_count = -1;
    protocol.keepalive_timeout_len = -1;
    protocol.retransmission_keepalive_timeout_len = -1;
    protocol.acceptable_packet_errors_count = -1;
    protocol.maximum_retransmission_count = -1;

    engine.engine_flags = IPMICONSOLE_ENGINE_OUTPUT_ON_SOL_ESTABLISHED;
    engine.behavior_flags = 0;
    engine.debug_flags = 0;

    ctx = ipmiconsole_ctx_create(pCE->host, &ipmi, &protocol, &engine);

    return ctx;
}
#endif

/* invoke the initcmd command */
void
StartInit(CONSENT *pCE)
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
#if HAVE_CLOSEFROM
    for (i = 3; i <= pout[0] || i <= pin[1]; i++) {
	if (i != pout[0] && i != pin[1])
	    close(i);
    }
    closefrom(i);
#else
    i = GetMaxFiles();
    for ( /* i above */ ; --i > 2;) {
	if (i != pout[0] && i != pin[1])
	    close(i);
    }
#endif
    /* leave 2 until we have to close it */
    close(1);
    close(0);

#if HAVE_SETSID
    iNewGrp = setsid();
    if (-1 == iNewGrp) {
	Error("[%s] setsid(): %s", pCE->server, strerror(errno));
	iNewGrp = getpid();
    }
#else
    iNewGrp = getpid();
#endif

    if (dup(pout[0]) != 0 || dup(pin[1]) != 1) {
	Error("[%s] StartInit(): fd sync error", pCE->server);
	exit(EX_OSERR);
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
    exit(EX_OSERR);
    return;
}

/* We exit() here, so only call this in a child process before an exec() */
void
SetupTty(CONSENT *pCE, int fd)
{
    struct termios n_tio;

#if HAVE_STROPTS_H  && !defined(_AIX)
    /* SYSVr4 semantics for opening stream ptys                     (gregf)
     * under PTX (others?) we have to push the compatibility
     * streams modules `ptem', `ld', and `ttcompat'
     */
    ioctl(1, I_PUSH, "ptem");
    ioctl(1, I_PUSH, "ldterm");
    ioctl(1, I_PUSH, "ttcompat");
#endif

    if (0 != tcgetattr(1, &n_tio)) {
	exit(EX_OSERR);
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
    if (0 != tcsetattr(1, TCSANOW, &n_tio))
	exit(EX_OSERR);
}

/* setup a virtual device						(ksb)
 */
static int
VirtDev(CONSENT *pCE)
{
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
#if HAVE_CLOSEFROM
    for (i = 3; i < pCE->execSlaveFD; i++)
	close(i);
    i++;
    closefrom(i);
#else
    i = GetMaxFiles();
    for ( /* i above */ ; --i > 2;) {
	if (i != pCE->execSlaveFD)
	    close(i);
    }
#endif
    /* leave 2 until we *have to close it*
     */
    close(1);
    close(0);

#if HAVE_SETSID
    iNewGrp = setsid();
    if (-1 == iNewGrp) {
	Error("[%s] setsid(): %s", pCE->server, strerror(errno));
	iNewGrp = getpid();
    }
#else
    iNewGrp = getpid();
#endif

    if (dup(pCE->execSlaveFD) != 0 || dup(pCE->execSlaveFD) != 1) {
	Error("[%s] fd sync error", pCE->server);
	exit(EX_OSERR);
    }

    if (geteuid() == 0) {
	if (pCE->execgid != 0)
	    setgid(pCE->execgid);
	if (pCE->execuid != 0) {
	    fchown(0, pCE->execuid, -1);
	    setuid(pCE->execuid);
	}
    }

    SetupTty(pCE, 0);

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
    exit(EX_OSERR);
    return -1;
}

char *
ConsState(CONSENT *pCE)
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
#if HAVE_GSSAPI
	case INGSSACCEPT:
	    return "GSSAPI_accept";
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
ConsDown(CONSENT *pCE, FLAG downHard, FLAG force)
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
#if HAVE_FREEIPMI
    /* need to do this after cofile close above as
     * ipmiconsole_ctx_destroy will close the fd */
    if (pCE->ipmictx != (ipmiconsole_ctx_t) 0) {
	ipmiconsole_ctx_destroy(pCE->ipmictx);
	pCE->ipmictx = (ipmiconsole_ctx_t) 0;
    }
#endif
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
	free(pCE->execSlave);
	pCE->execSlave = NULL;
    }
    pCE->fup = 0;
    pCE->nolog = 0;
    pCE->autoReUp = 0;
    pCE->downHard = downHard;
    pCE->ioState = ISDISCONNECTED;
    pCE->telnetState = 0;
    pCE->sentDoEcho = FLAGFALSE;
    pCE->sentDoSGA = FLAGFALSE;
}

/* set up a console the way it should be for use to work with it	(ksb)
 * also, recover from silo over runs by dropping the line and re-opening
 * We also maintian the select set for the caller.
 */
void
ConsInit(CONSENT *pCE)
{
    time_t tyme;
    extern int FallBack(char **, int *);
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
	Sleep(250000);
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
	case NOOP:
	    pCE->fup = 1;
	    pCE->ioState = ISNORMAL;
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
#if USE_IPV6
		/* XXX IPv4 should use getaddrinfo() and getnameinfo() as well,
		 * (if available, they are in IEEE Std 1003.1g-2000)
		 */
		int error;
		char host[NI_MAXHOST];
		char serv[NI_MAXSERV];
		struct addrinfo *ai, *rp, hints;
#else
		struct sockaddr_in port;
		struct hostent *hp;
#endif /* USE_IPV6 */
#if HAVE_SETSOCKOPT
		int one = 1;
#endif
		Sleep(100000);	/* Not all terminal servers can keep up */

#if USE_IPV6
# if HAVE_MEMSET		/* XXX memset() is C89!!! */
		memset(&hints, 0, sizeof(hints));
# else
		bzero(&hints, sizeof(hints));
# endif

		hints.ai_flags = AI_ADDRCONFIG;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(serv, sizeof(serv), "%hu", pCE->netport);

		error = getaddrinfo(pCE->host, serv, &hints, &ai);
		if (error) {
		    Error("[%s] getaddrinfo(%s): %s: forcing down",
			  pCE->server, pCE->host, gai_strerror(error));
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}

		rp = ai;
		while (rp) {
		    error =
			getnameinfo(rp->ai_addr, rp->ai_addrlen, host,
				    sizeof(host), serv, sizeof(serv),
				    NI_NUMERICHOST | NI_NUMERICSERV);
		    if (error)
			continue;
		    CONDDEBUG((1,
			       "[%s]: trying hostname=%s, ip=%s, port=%s",
			       pCE->server, pCE->host, host, serv));

		    cofile =
			socket(rp->ai_family, rp->ai_socktype,
			       rp->ai_protocol);
		    if (cofile != -1) {
# if HAVE_SETSOCKOPT
			if (setsockopt
			    (cofile, SOL_SOCKET, SO_KEEPALIVE,
			     (char *)&one, sizeof(one)) < 0) {
			    Error
				("[%s] %s:%s setsockopt(%u,SO_KEEPALIVE): %s",
				 pCE->server, host, serv, cofile, strerror(errno));
			    goto fail;
			}
# endif
			if (!SetFlags(cofile, O_NONBLOCK, 0))
			    goto fail;

			ret = connect(cofile, rp->ai_addr, rp->ai_addrlen);
			if (ret == 0 || errno == EINPROGRESS)
			    goto success;
			Error("[%s] %s:%s connect(%u): %s",
			      pCE->server, host, serv, cofile, strerror(errno));
		      fail:
			close(cofile);
		    } else {
			Error
			    ("[%s] %s:%s socket(AF_INET,SOCK_STREAM): %s",
			     pCE->server, host, serv, strerror(errno));
		    }
		    rp = rp->ai_next;
		}

		Error("[%s] Unable to connect to %s:%s, forcing down", pCE->server,
		      pCE->host, serv);
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	      success:
		freeaddrinfo(ai);
#else  /* !USE_IPV6 */
# if HAVE_MEMSET
		memset((void *)&port, 0, sizeof(port));
# else
		bzero((char *)&port, sizeof(port));
# endif

		if ((hp = gethostbyname(pCE->host)) == NULL) {
		    Error("[%s] gethostbyname(%s): %s: forcing down",
			  pCE->server, pCE->host, hstrerror(h_errno));
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}
# if HAVE_MEMCPY
		memcpy(&port.sin_addr.s_addr, hp->h_addr_list[0],
		       hp->h_length);
# else
		bcopy(hp->h_addr_list[0], &port.sin_addr.s_addr,
		      hp->h_length);
# endif
		port.sin_family = hp->h_addrtype;
		port.sin_port = htons(pCE->netport);

		if ((cofile = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		    Error
			("[%s] socket(AF_INET,SOCK_STREAM): %s: forcing down",
			 pCE->server, strerror(errno));
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}
# if HAVE_SETSOCKOPT
		if (setsockopt
		    (cofile, SOL_SOCKET, SO_KEEPALIVE, (char *)&one,
		     sizeof(one)) < 0) {
		    Error
			("[%s] setsockopt(%u,SO_KEEPALIVE): %s: forcing down",
			 pCE->server, cofile, strerror(errno));
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    close(cofile);
		    return;
		}
# endif

		if (!SetFlags(cofile, O_NONBLOCK, 0)) {
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    close(cofile);
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
			close(cofile);
			return;
		    }
		}
#endif /* USE_IPV6 */
	    }
	    if ((pCE->cofile =
		 FileOpenFD(cofile, simpleSocket)) == (CONSFILE *)0) {
		Error
		    ("[%s] FileOpenFD(%d,simpleSocket) failed: forcing down",
		     pCE->server, cofile);
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		close(cofile);
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
	case UDS:
	    {
		struct sockaddr_un port;

#if HAVE_MEMSET
		memset((void *)&port, 0, sizeof(port));
#else
		bzero((char *)&port, sizeof(port));
#endif

		/* we ensure that pCE->uds exists and fits inside port.sun_path
		 * in readcfg.c, so we can just defend ourselves here (which
		 * should never trigger).
		 */
		if (strlen(pCE->uds) >= sizeof(port.sun_path)) {
		    Error
			("[%s] strlen(uds path) > sizeof(port.sun_path): forcing down",
			 pCE->server);
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}
		StrCpy(port.sun_path, pCE->uds, sizeof(port.sun_path));
		port.sun_family = AF_UNIX;

		if ((cofile = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		    Error
			("[%s] socket(AF_UNIX,SOCK_STREAM): %s: forcing down",
			 pCE->server, strerror(errno));
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    return;
		}

		if (!SetFlags(cofile, O_NONBLOCK, 0)) {
		    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		    close(cofile);
		    return;
		}

		if ((ret =
		     connect(cofile, (struct sockaddr *)&port,
			     sizeof(port))) < 0) {
		    if (errno != EINPROGRESS) {
			Error("[%s] connect(%u): %s: forcing down",
			      pCE->server, cofile, strerror(errno));
			ConsDown(pCE, FLAGTRUE, FLAGTRUE);
			close(cofile);
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
		close(cofile);
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

#if HAVE_FREEIPMI
	case IPMI:
	    if (!(pCE->ipmictx = IpmiSOLCreate(pCE))) {
		Error("[%s] Could not create IPMI context: forcing down",
		      pCE->server);
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	    }

	    if (ipmiconsole_engine_submit(pCE->ipmictx, NULL, NULL) < 0) {
		Error
		    ("[%s] Could not connect to IPMI host `%s': forcing down",
		     pCE->server, pCE->host);
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	    }

	    cofile = ipmiconsole_ctx_fd(pCE->ipmictx);
	    if (!SetFlags(cofile, O_NONBLOCK, 0)) {
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	    }

	    if ((pCE->cofile =
		 FileOpenFD(cofile, simpleFile)) == (CONSFILE *)0) {
		Error("[%s] FileOpenFD(simpleFile) failed: forcing down",
		      pCE->server);
		ConsDown(pCE, FLAGTRUE, FLAGTRUE);
		return;
	    }

	    if (ipmiconsole_ctx_status(pCE->ipmictx) ==
		IPMICONSOLE_CTX_STATUS_SOL_ESTABLISHED) {
		/* Read in the NULL from OUTPUT_ON_SOL_ESTABLISHED flag */
		char b[1];
		FileRead(pCE->cofile, b, 1);	/* trust it's NULL */
		pCE->ioState = ISNORMAL;
		pCE->stateTimer = 0;
	    } else {
		/* Error status cases will be handled in Kiddie() */
		pCE->ioState = INCONNECT;
		pCE->stateTimer = time((time_t *)0) + CONNECTTIMEOUT;
		if (timers[T_STATE] == (time_t)0 ||
		    timers[T_STATE] > pCE->stateTimer)
		    timers[T_STATE] = pCE->stateTimer;
	    }
	    pCE->fup = 1;
	    break;
#endif
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
#if HAVE_FREEIPMI
	case IPMI:
	    Verbose("[%s] on %s", pCE->server);
	    break;
#endif
	case NOOP:
	    Verbose("[%s] noop", pCE->server);
	    break;
	case UDS:
	    Verbose("[%s] uds %s", pCE->server, pCE->uds);
	    break;
	case DEVICE:
	    Verbose("[%s] at %s%c on %s", pCE->server, pCE->baud->acrate,
		    pCE->parity->key[0], pCE->device);
	    break;
    }

    if (cofile != -1) {
	/* if we're waiting for connect() to finish, watch the
	 * write bit, otherwise watch for the read bit
	 */
	if (pCE->ioState == INCONNECT
#if HAVE_FREEIPMI
	    /* We wait for read() with the libipmiconsole */
	    && pCE->type != IPMI
#endif
	    )
	    FD_SET(cofile, &winit);
	else
	    FD_SET(cofile, &rinit);
	if (maxfd < cofile + 1)
	    maxfd = cofile + 1;
    }

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
AddrsMatch(char *addr1, char *addr2)
{
#if USE_IPV6
    int error, ret = 0;
    struct addrinfo *ai1, *ai2, *rp1, *rp2, hints;
#else
    /* so, since we might use inet_addr, we're going to use
     * (in_addr_t)(-1) as a sign of an invalid ip address.
     * sad, but true.
     */
    in_addr_t inAddr1 = (in_addr_t) (-1);
    in_addr_t inAddr2 = (in_addr_t) (-1);
# if HAVE_INET_ATON
    struct in_addr inetAddr1;
    struct in_addr inetAddr2;
# endif
#endif /* USE_IPV6 */

    /* first try simple character string match */
    if (strcasecmp(addr1, addr2) == 0)
	return 1;

#if USE_IPV6
# if HAVE_MEMSET
    memset(&hints, 0, sizeof(hints));
# else
    bzero(&hints, sizeof(hints));
# endif
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;

    error = getaddrinfo(addr1, NULL, &hints, &ai1);
    if (error) {
	Error("getaddrinfo(%s): %s", addr1, gai_strerror(error));
	goto done;
    }
    error = getaddrinfo(addr2, NULL, &hints, &ai2);
    if (error) {
	Error("getaddrinfo(%s): %s", addr2, gai_strerror(error));
	goto done;
    }

    rp1 = ai1;
    rp2 = ai2;
    for (; rp1 != NULL; rp1 = rp1->ai_next) {
	for (; rp2 != NULL; rp2 = rp2->ai_next) {
	    if (rp1->ai_addr->sa_family != rp2->ai_addr->sa_family)
		continue;

	    if (
# if HAVE_MEMCMP
		   memcmp(&rp1->ai_addr, &rp2->ai_addr,
			  sizeof(struct sockaddr_storage))
# else
		   bcmp(&rp1->ai_addr, &rp2->ai_addr,
			sizeof(struct sockaddr_storage))
# endif
		   == 0) {
		ret = 1;
		goto done;
	    }
	}
    }

  done:
    freeaddrinfo(ai1);
    freeaddrinfo(ai2);
    Msg("compare %s and %s returns %d", addr1, addr2, ret);
    return ret;
#else
    /* now try ip address match (could have leading zeros or something) */
# if HAVE_INET_ATON
    if (inet_aton(addr1, &inetAddr1) != 0)
	inAddr1 = inetAddr1.s_addr;
    if (inet_aton(addr2, &inetAddr2) != 0)
	inAddr2 = inetAddr2.s_addr;
# else
    inAddr1 = inet_addr(addr1);
    inAddr2 = inet_addr(addr2);
# endif

    /* if both are ip addresses, we just match */
    if (inAddr1 != (in_addr_t) (-1) && inAddr2 != (in_addr_t) (-1))
	return !
# if HAVE_MEMCMP
	    memcmp(&inAddr1, &inAddr2, sizeof(inAddr1))
# else
	    bcmp(&inAddr1, &inAddr2, sizeof(inAddr1))
# endif
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
# if HAVE_MEMCPY
	    memcpy(&(addrs[i]), he->h_addr_list[i], he->h_length);
# else
	    bcopy(he->h_addr_list[i], &(addrs[i]), he->h_length);
# endif
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
# if HAVE_MEMCMP
		       memcmp(&(addrs[i]), he->h_addr_list[j],
			      he->h_length)
# else
		       bcmp(&(addrs[i]), he->h_addr_list[j], he->h_length)
# endif
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
# if HAVE_MEMCMP
		   memcmp(iaddr, he->h_addr_list[i], he->h_length)
# else
		   bcmp(iaddr, he->h_addr_list[i], he->h_length)
# endif
		   == 0)
		return 1;
	}
    }
    return 0;
#endif /* USE_IPV6 */
}

/* thread ther list of uniq console server machines, aliases for	(ksb)
 * machines will screw us up
 */
REMOTE *
FindUniq(REMOTE *pRCAll)
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
DestroyRemoteConsole(REMOTE *pRCList)
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
