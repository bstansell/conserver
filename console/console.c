/*
 *  $Id: console.c,v 5.84 2002-03-11 18:10:27-08 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
 */

/*
 * Copyright (c) 1990 The Ohio State University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by The Ohio State University and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <config.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <netdb.h>
#include <pwd.h>
#include <ctype.h>
#include <sys/stat.h>

#include <compat.h>
#include <port.h>
#include <util.h>

#include <version.h>


int fVerbose = 0, fReplay = 0, fRaw = 0, fVersion = 0, fStrip = 0;
int chAttn = -1, chEsc = -1;
char *pcInMaster =		/* which machine is current */
    MASTERHOST;
char *pcPort = DEFPORT;
unsigned short bindPort;

static char acMesg[8192];	/* the buffer for startup negotiation   */

/* output a control (or plain) character as a UNIX user would expect it	(ksb)
 */
static void
#if USE_ANSI_PROTO
putCtlc(int c, FILE * fp)
#else
putCtlc(c, fp)
    int c;
    FILE *fp;
#endif
{
    if (0 != (0200 & c)) {
	(void)putc('M', fp);
	(void)putc('-', fp);
	c &= ~0200;
    }
    if (isprint(c)) {
	(void)putc(c, fp);
	return;
    }
    (void)putc('^', fp);
    if (c == 0177) {
	(void)putc('?', fp);
	return;
    }
    (void)putc(c + 0100, fp);
}

static char *apcLong[] = {
    "7       strip the high bit of all console data",
    "a(A)    attach politely (and replay last 20 lines)",
    "b       send broadcast message",
    "D       enable debug output, sent to stderr",
    "e esc   set the initial escape characters",
    "f(F)    force read/write connection (and replay)",
    "G       connect to the console group only",
    "i       display information in machine-parseable form",
    "h       output this message",
    "l user  use username instead of current username",
    "M mach  master server to poll first",
    "p port  port to connect to",
    "P       display pids of daemon(s)",
    "q(Q)    send a quit command to the (master) server",
    "r(R)    display (master) daemon version (think 'r'emote version)",
    "s(S)    spy on a console (and replay)",
    "u       show users on the various consoles",
    "v       be more verbose",
    "V       show version information",
    "w(W)    show who is on which console (on master)",
    "x       examine ports and baud rates",
    (char *)0
};

/* output a long message to the user
 */
static void
#if USE_ANSI_PROTO
Usage(char **ppc)
#else
Usage(ppc)
    char **ppc;
#endif
{
    for ( /* passed */ ; (char *)0 != *ppc; ++ppc)
	fprintf(stderr, "\t%s\n", *ppc);
}

/* expain who we are and which revision we are				(ksb)
 */
static void
#if USE_ANSI_PROTO
Version()
#else
Version()
#endif
{
    int i;

    Info("%s", THIS_VERSION);
    Info("initial master server `%s\'", pcInMaster);
    printf("%s: default escape sequence `", progname);
    putCtlc(DEFATTN, stdout);
    putCtlc(DEFESC, stdout);
    printf("\'\n");
    /* Look for non-numeric characters */
    for (i = 0; pcPort[i] != '\000'; i++)
	if (!isdigit((int)pcPort[i]))
	    break;

    if (pcPort[i] == '\000') {
	/* numeric only */
	bindPort = atoi(pcPort);
	Info("on port %u (referenced as `%s')", bindPort, pcPort);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 == (pSE = getservbyname(pcPort, "tcp"))) {
	    Error("getservbyname: %s: %s", pcPort, strerror(errno));
	} else {
	    bindPort = ntohs((u_short) pSE->s_port);
	    Info("on port %u (referenced as `%s')", bindPort, pcPort);
	}
    }
    Info("built with `%s'", CONFIGINVOCATION);
    if (fVerbose)
	printf(COPYRIGHT);
}


/* convert text to control chars, we take `cat -v' style		(ksb)
 *	^X (or ^x)		contro-x
 *	M-x			x plus 8th bit
 *	c			a plain character
 */
static int
#if USE_ANSI_PROTO
ParseChar(char **ppcSrc, char *pcOut)
#else
ParseChar(ppcSrc, pcOut)
    char **ppcSrc, *pcOut;
#endif
{
    int cvt, n;
    char *pcScan = *ppcSrc;

    if ('M' == pcScan[0] && '-' == pcScan[1] && '\000' != pcScan[2]) {
	cvt = 0x80;
	pcScan += 2;
    } else {
	cvt = 0;
    }

    if ('\000' == *pcScan) {
	return 1;
    }

    if ('^' == (n = *pcScan++)) {
	if ('\000' == (n = *pcScan++)) {
	    return 1;
	}
	if (islower(n)) {
	    n = toupper(n);
	}
	if ('@' <= n && n <= '_') {
	    cvt |= n - '@';
	} else if ('?' == *pcScan) {
	    cvt |= '\177';
	} else {
	    return 1;
	}
    } else {
	cvt |= n;
    }

    if ((char *)0 != pcOut) {
	*pcOut = cvt;
    }
    *ppcSrc = pcScan;
    return 0;
}

/*
 */
static void
#if USE_ANSI_PROTO
ValidateEsc()
#else
ValidateEsc()
#endif
{
    unsigned char c1, c2;

    if (!fStrip)
	return;

    if (chAttn == -1 || chEsc == -1) {
	c1 = DEFATTN;
	c2 = DEFESC;
    } else {
	c1 = chAttn;
	c2 = chEsc;
    }
    if (c1 > 127 || c2 > 127) {
	Error("High-bit set in escape sequence: not allowed with -7");
	exit(EX_UNAVAILABLE);
    }
}

/* find the two characters that makeup the users escape sequence	(ksb)
 */
static void
#if USE_ANSI_PROTO
ParseEsc(char *pcText)
#else
ParseEsc(pcText)
    char *pcText;
#endif
{
    char *pcTemp;
    char c1, c2;

    pcTemp = pcText;
    if (ParseChar(&pcTemp, &c1) || ParseChar(&pcTemp, &c2)) {
	Error("poorly formed escape sequence `%s\'", pcText);
	exit(EX_UNAVAILABLE);
    }
    if ('\000' != *pcTemp) {
	Error("too many characters in new escape sequence at ...`%s\'",
	      pcTemp);
	exit(EX_UNAVAILABLE);
    }
    chAttn = c1;
    chEsc = c2;
}


/* set the port for socket connection					(ksb)
 * return the fd for the new connection; if we can use the loopback, do
 * as a side effect we set ThisHost to a short name for this host
 */
int
#if USE_ANSI_PROTO
GetPort(char *pcToHost, struct sockaddr_in *pPort, unsigned short sPort)
#else
GetPort(pcToHost, pPort, sPort)
    char *pcToHost;
    struct sockaddr_in *pPort;
    unsigned short sPort;
#endif
{
    int s;
    struct hostent *hp = (struct hostent *)0;

#if HAVE_MEMSET
    memset((void *)pPort, '\000', sizeof(*pPort));
#else
    (void)bzero((char *)pPort, sizeof(*pPort));
#endif

    pPort->sin_addr.s_addr = inet_addr(pcToHost);
    if ((in_addr_t) (-1) == pPort->sin_addr.s_addr) {
	if ((struct hostent *)0 != (hp = gethostbyname(pcToHost))) {
#if HAVE_MEMCPY
	    memcpy((char *)&pPort->sin_addr.s_addr, (char *)hp->h_addr,
		   hp->h_length);
#else
	    (void)bcopy((char *)hp->h_addr,
			(char *)&pPort->sin_addr.s_addr, hp->h_length);
#endif
	} else {
	    Error("gethostbyname: %s: %s", pcToHost, hstrerror(h_errno));
	    exit(EX_UNAVAILABLE);
	}
    }
    pPort->sin_port = sPort;
    pPort->sin_family = AF_INET;

    if (fDebug) {
	if ((struct hostent *)0 != hp && (char *)0 != hp->h_name)
	    Debug(1, "GetPort: hostname=%s (%s), ip=%s, port=%u",
		  hp->h_name, pcToHost, inet_ntoa(pPort->sin_addr),
		  ntohs(sPort));
	else
	    Debug(1, "GetPort: hostname=<unresolved> (%s), ip=%s, port=%u",
		  pcToHost, inet_ntoa(pPort->sin_addr), ntohs(sPort));
    }

    /* set up the socket to talk to the server for all consoles
     * (it will tell us who to talk to to get a real connection)
     */
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	Error("socket: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    if (connect(s, (struct sockaddr *)pPort, sizeof(*pPort)) < 0) {
	Error("connect: %d@%s: %s", ntohs(pPort->sin_port), pcToHost,
	      strerror(errno));
	exit(EX_UNAVAILABLE);
    }

    return s;
}


/* the next two routines assure that the users tty is in the
 * correct mode for us to do our thing
 */
static int screwy = 0;
#if HAVE_TERMIOS_H
static struct termios o_tios;
#else
# if HAVE_TERMIO_H
static struct termio o_tio;
# else
static struct sgttyb o_sty;
static struct tchars o_tchars;
static struct ltchars o_ltchars;
# endif
#endif


/*
 * show characters that are already tty processed,
 * and read characters before cononical processing
 * we really use cbreak at PUCC because we need even parity...
 */
static void
#if USE_ANSI_PROTO
c2raw()
#else
c2raw()
#endif
{
#if HAVE_TERMIOS_H
    struct termios n_tios;
#else
# if HAVE_TERMIO_H
    struct termio n_tio;
# else
    struct sgttyb n_sty;
    struct tchars n_tchars;
    struct ltchars n_ltchars;
# endif
#endif

    if (!isatty(0) || 0 != screwy)
	return;

#if HAVE_TERMIOS_H
# if HAVE_TCGETATTR
    if (0 != tcgetattr(0, &o_tios))
# else
    if (0 != ioctl(0, TCGETS, &o_tios))
# endif
    {
	Error("iotcl: getsw: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    n_tios = o_tios;
    n_tios.c_iflag &= ~(INLCR | IGNCR | ICRNL | IUCLC | IXON);
    n_tios.c_oflag &= ~OPOST;
    n_tios.c_lflag &= ~(ICANON | ISIG | ECHO | IEXTEN);
    n_tios.c_cc[VMIN] = 1;
    n_tios.c_cc[VTIME] = 0;
# if HAVE_TCSETATTR
    if (0 != tcsetattr(0, TCSANOW, &n_tios))
# else
    if (0 != ioctl(0, TCSETS, &n_tios))
# endif
    {
	Error("getarrt: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
#else
# if HAVE_TERMIO_H
    if (0 != ioctl(0, TCGETA, &o_tio)) {
	Error("iotcl: geta: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    n_tio = o_tio;
    n_tio.c_iflag &= ~(INLCR | IGNCR | ICRNL | IUCLC | IXON);
    n_tio.c_oflag &= ~OPOST;
    n_tio.c_lflag &=
	~(ICANON | ISIG | ECHO | ECHOE | ECHOK | ECHONL | IEXTEN);
    n_tio.c_cc[VMIN] = 1;
    n_tio.c_cc[VTIME] = 0;
    if (0 != ioctl(0, TCSETAF, &n_tio)) {
	Error("iotcl: seta: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
# else
    if (0 != ioctl(0, TIOCGETP, (char *)&o_sty)) {
	Error("iotcl: getp: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    n_sty = o_sty;

    n_sty.sg_flags |= CBREAK;
    n_sty.sg_flags &= ~(CRMOD | ECHO);
    n_sty.sg_kill = -1;
    n_sty.sg_erase = -1;
    if (0 != ioctl(0, TIOCSETP, (char *)&n_sty)) {
	Error("iotcl: setp: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }

    /* stty undef all tty chars
     */
    if (-1 == ioctl(0, TIOCGETC, (char *)&n_tchars)) {
	Error("ioctl: getc: %s", strerror(errno));
	return;
    }
    o_tchars = n_tchars;
    n_tchars.t_intrc = -1;
    n_tchars.t_quitc = -1;
    if (-1 == ioctl(0, TIOCSETC, (char *)&n_tchars)) {
	Error("ioctl: setc: %s", strerror(errno));
	return;
    }
    if (-1 == ioctl(0, TIOCGLTC, (char *)&n_ltchars)) {
	Error("ioctl: gltc: %s", strerror(errno));
	return;
    }
    o_ltchars = n_ltchars;
    n_ltchars.t_suspc = -1;
    n_ltchars.t_dsuspc = -1;
    n_ltchars.t_flushc = -1;
    n_ltchars.t_lnextc = -1;
    if (-1 == ioctl(0, TIOCSLTC, (char *)&n_ltchars)) {
	Error("ioctl: sltc: %s", strerror(errno));
	return;
    }
# endif
#endif
    screwy = 1;
}

/*
 * put the tty back as it was, however that was
 */
static void
#if USE_ANSI_PROTO
c2cooked()
#else
c2cooked()
#endif
{
    if (!screwy)
	return;
#if HAVE_TERMIOS_H
# if HAVE_TCSETATTR
    tcsetattr(0, TCSANOW, &o_tios);
# else
    (void)ioctl(0, TCSETS, (char *)&o_tios);
# endif
#else
# if HAVE_TERMIO_H
    (void)ioctl(0, TCSETA, (char *)&o_tio);
# else
    (void)ioctl(0, TIOCSETP, (char *)&o_sty);
    (void)ioctl(0, TIOCSETC, (char *)&o_tchars);
    (void)ioctl(0, TIOCSLTC, (char *)&o_ltchars);
# endif
#endif
    screwy = 0;
}



/* send out some data along the connection				(ksb)
 */
static void
#if USE_ANSI_PROTO
SendOut(int fd, char *pcBuf, int iLen)
#else
SendOut(fd, pcBuf, iLen)
    int fd, iLen;
    char *pcBuf;
#endif
{
    int nr;

    if (fDebug) {
	static STRING buf = { (char *)0, 0, 0 };
	FmtCtlStr(pcBuf, &buf);
	Debug(1, "SendOut: `%s'", buf.string);
    }
    while (0 != iLen) {
	if (-1 == (nr = write(fd, pcBuf, iLen))) {
	    c2cooked();
	    Error("lost connection");
	    exit(EX_UNAVAILABLE);
	}
	iLen -= nr;
	pcBuf += nr;
    }
}

/* read a reply from the console server					(ksb)
 * if pcWnat == (char *)0 we strip \r\n from the end and return strlen
 */
static int
#if USE_ANSI_PROTO
ReadReply(int fd, char *pcBuf, int iLen, char *pcWant)
#else
ReadReply(fd, pcBuf, iLen, pcWant)
    int fd, iLen;
    char *pcBuf, *pcWant;
#endif
{
    int nr, j, iKeep;

    iKeep = iLen;
    for (j = 0; j < iLen; /* j+=nr */ ) {
	switch (nr = read(fd, &pcBuf[j], iLen - 1)) {
	    case 0:
		if (iKeep != iLen) {
		    break;
		}
		/* fall through */
	    case -1:
		c2cooked();
		Error("lost connection");
		exit(EX_UNAVAILABLE);
	    default:
		j += nr;
		iLen -= nr;
		if ('\n' == pcBuf[j - 1]) {
		    pcBuf[j] = '\000';
		    break;
		}
		if (0 == iLen) {
		    c2cooked();
		    Error("reply too long");
		    exit(EX_UNAVAILABLE);
		}
		continue;
	}
	break;
    }
    /* in this case the called wants a line of text
     * remove the cr/lf sequence and any trtailing spaces
     * (s/[ \t\r\n]*$//)
     */
    if ((char *)0 == pcWant) {
	while (0 != j && isspace((int)(pcBuf[j - 1]))) {
	    pcBuf[--j] = '\000';
	}
	Debug(1, "ReadReply: %s", pcBuf);
	return j;
    }
    if (fDebug) {
	static STRING buf = { (char *)0, 0, 0 };
	FmtCtlStr(pcWant, &buf);
	if (strcmp(pcBuf, pcWant))
	    Debug(1, "ReadReply: didn't match `%s'", buf.string);
	else
	    Debug(1, "ReadReply: matched `%s'", buf.string);
    }
    return strcmp(pcBuf, pcWant);
}

/* call a machine master for group master ports and machine master ports
 * take a list like "1782@localhost:@mentor.cc.purdue.edu:@pop.stat.purdue.edu"
 * and send the given command to the group leader at 1782
 * and ask the machine master at mentor for more group leaders
 * and ask the machine master at pop.stat for more group leaders
 */
static int
#if USE_ANSI_PROTO
Gather(int (*pfi) (), char *pcPorts, char *pcMaster, char *pcTo,
       char *pcCmd, char *pcWho)
#else
Gather(pfi, pcPorts, pcMaster, pcTo, pcCmd, pcWho)
    int (*pfi) ();
    char *pcPorts, *pcMaster, *pcTo, *pcCmd, *pcWho;
#endif
{
    int s;
    unsigned short j;
    char *pcNext, *pcServer;
    STRING acExcg = { (char *)0, 0, 0 };
    struct sockaddr_in client_port;
    int iRet = 0;
#if defined(__CYGWIN__)
    int client_sock_flags;
    struct linger lingeropt;
#endif

    for ( /* param */ ; '\000' != *pcPorts; pcPorts = pcNext) {
	if ((char *)0 == (pcNext = strchr(pcPorts, ':')))
	    pcNext = "";
	else
	    *pcNext++ = '\000';

	buildMyString((char *)0, &acExcg);
	buildMyString(pcMaster, &acExcg);
	if ((char *)0 != (pcServer = strchr(pcPorts, '@'))) {
	    *pcServer++ = '\000';
	    if ('\000' != *pcServer) {
		buildMyString((char *)0, &acExcg);
		buildMyString(pcServer, &acExcg);
	    }
	}

	if ('\000' == *pcPorts) {
	    j = htons(bindPort);
	} else if (!isdigit((int)(pcPorts[0]))) {
	    Error("%s: %s", pcMaster, pcPorts);
	    exit(EX_UNAVAILABLE);
	} else {
	    j = htons((short)atoi(pcPorts));
	}

	s = GetPort(acExcg.string, &client_port, j);

	if (0 != ReadReply(s, acMesg, sizeof(acMesg), "ok\r\n")) {
	    int s = strlen(acMesg);
	    if ((s > 0) && ('\n' == acMesg[s - 1]))
		acMesg[s - 1] = '\000';
	    Error("%s: %s", acExcg.string, acMesg);
	    exit(EX_UNAVAILABLE);
	}

	iRet += (*pfi) (s, acExcg.string, pcTo, pcCmd, pcWho);

#if defined(__CYGWIN__)
	/* flush out the client socket - set it to blocking,
	 * then write to it
	 */
	client_sock_flags = fcntl(s, F_GETFL, 0);
	if (client_sock_flags != -1)
	    /* enable blocking */
	    fcntl(s, F_SETFL, client_sock_flags & ~O_NONBLOCK);

	/* sent it a byte - guaranteed to block - ensure delivery of
	 * prior data yeah - this is a bit paranoid - try without this
	 * at first
	 */
	/* write(s, "\n", 1); */

	/* this is the guts of the workaround for Winsock close bug */
	shutdown(s, 1);

	/* enable lingering */
	lingeropt.l_onoff = 1;
	lingeropt.l_linger = 15;
	setsockopt(s, SOL_SOCKET, SO_LINGER, &lingeropt,
		   sizeof(lingeropt));
	/* Winsock bug averted - now we're safe to close the socket */
#endif

	(void)close(s);
	if ((char *)0 != pcServer) {
	    *pcServer = '@';
	}
    }
    destroyString(&acExcg);
    return iRet;
}


static int SawUrg = 0;

/* when the conserver program gets the suspend sequence it will send us
 * an out of band command to suspend ourself.  We just tell the reader
 * routine we saw one
 */
RETSIGTYPE
#if USE_ANSI_PROTO
oob(int sig)
#else
oob(sig)
    int sig;
#endif
{
    ++SawUrg;
#if !HAVE_SIGACTION
#if defined(SIGURG)
    simpleSignal(SIGURG, oob);
#endif
#endif
}

void
#if USE_ANSI_PROTO
processUrgentData(int s)
#else
processUrgentData(s)
    int s;
#endif
{
    static char acCmd;

    SawUrg = 0;

    /* get the pending urgent message
     */
    while (recv(s, &acCmd, 1, MSG_OOB) < 0) {
	switch (errno) {
	    case EWOULDBLOCK:
		/* clear any pending input to make room */
		(void)read(s, &acCmd, 1);
		write(1, ".", 1);
		continue;
	    case EINVAL:
	    default:
		Error("recv: %d: %s\r", s, strerror(errno));
		sleep(1);
		continue;
	}
    }
    switch (acCmd) {
	case OB_SUSP:
#if defined(SIGSTOP)
	    write(1, "stop]", 5);
	    c2cooked();
	    (void)kill(getpid(), SIGSTOP);
	    c2raw();
	    write(1, "[press any character to continue", 32);
#else
	    write(1,
		  "stop not supported -- press any character to continue",
		  53);
#endif
	    break;
	case OB_DROP:
	    write(1, "dropped by server]\r\n", 20);
	    c2cooked();
	    exit(EX_UNAVAILABLE);
	 /*NOTREACHED*/ default:
	    Error("unknown out of band command `%c\'\r", acCmd);
	    (void)fflush(stderr);
	    break;
    }
}

/* interact with a group server					(ksb)
 */
static int
#if USE_ANSI_PROTO
CallUp(int s, char *pcMaster, char *pcMach, char *pcHow, char *pcUser)
#else
CallUp(s, pcMaster, pcMach, pcHow, pcUser)
    int s;
    char *pcMaster, *pcMach, *pcHow, *pcUser;
#endif
{
    int nc;
    int fIn = '-';
    fd_set rmask, rinit;
    int i;
    int justProcessedUrg = 0;

    if (fVerbose) {
	Info("%s to %s (%son %s)", pcHow, pcMach, fRaw ? "raw " : "",
	     pcMaster);
    }
#if !defined(__CYGWIN__)
# if defined(F_SETOWN)
    if (-1 == fcntl(s, F_SETOWN, getpid())) {
	Error("fcntl(F_SETOWN,%d): %d: %s", getpid(), s, strerror(errno));
    }
# else
#  if defined(SIOCSPGRP)
    {
	int iTemp;
	/* on the HP-UX systems if different
	 */
	iTemp = -getpid();
	if (-1 == ioctl(s, SIOCSPGRP, &iTemp)) {
	    Error("ioctl: %d: %s", s, strerror(errno));
	}
    }
#  endif
# endif
#endif
#if defined(SIGURG)
    simpleSignal(SIGURG, oob);
#endif

    /* change escape sequence (if set on the command line)
     * and replay the log for the user, if asked
     */
    if (chAttn == -1 || chEsc == -1) {
	chAttn = DEFATTN;
	chEsc = DEFESC;
    } else {
	/* tell the conserver to change escape sequences, assume OK
	 * (we'll find out soon enough)
	 */
	(void)sprintf(acMesg, "%c%ce%c%c", DEFATTN, DEFESC, chAttn, chEsc);
	SendOut(s, acMesg, 5);
	if (0 == ReadReply(s, acMesg, sizeof(acMesg), (char *)0)) {
	    Error("protocol botch on redef of escape sequence");
	    exit(EX_UNAVAILABLE);
	}
    }
    if (fVerbose) {
	printf("Enter `");
	putCtlc(chAttn, stdout);
	putCtlc(chEsc, stdout);
	printf("?\' for help.\n");
    }


    /* if we are going for a particular console
     * send sign-on stuff, then wait for some indication of what mode
     * we got from the server (if we are the only people on we get write
     * access by default, which is fine for most people).
     */
    if (!fRaw) {
	/* begin connect with who we are
	 */
	(void)sprintf(acMesg, "%c%c;", chAttn, chEsc);
	SendOut(s, acMesg, 3);
	if (0 != ReadReply(s, acMesg, sizeof(acMesg), "[login:\r\n") &&
	    0 != strcmp(acMesg, "\r\n[login:\r\n")) {
	    int s = strlen(acMesg);
	    if ((s > 0) && ('\n' == acMesg[s - 1]))
		acMesg[s - 1] = '\000';
	    Error("call: %s", acMesg);
	    exit(EX_UNAVAILABLE);
	}

	(void)sprintf(acMesg, "%s\r\n", pcUser);
	SendOut(s, acMesg, strlen(acMesg));
	if (0 != ReadReply(s, acMesg, sizeof(acMesg), "host:\r\n")) {
	    int s = strlen(acMesg);
	    if ((s > 0) && ('\n' == acMesg[s - 1]))
		acMesg[s - 1] = '\000';
	    Error("%s", acMesg);
	    exit(EX_UNAVAILABLE);
	}

	/* which host we want, and a passwd if asked for one
	 */
	(void)sprintf(acMesg, "%s\r\n", pcMach);
	SendOut(s, acMesg, strlen(acMesg));
	(void)ReadReply(s, acMesg, sizeof(acMesg), (char *)0);
	if (0 == strcmp(acMesg, "passwd:")) {
	    static STRING pass = {(char *)0,0,0};
	    buildMyString((char *)0, &pass);
	    (void)sprintf(acMesg, "Enter %s@%s's password:", pcUser,
			  pcMaster);
#if defined(HAVE_GETPASSPHRASE)
	    buildMyString(getpassphrase(acMesg), &pass);
#else
	    buildMyString(getpass(acMesg), &pass);
#endif
	    buildMyString("\r\n", &pass);
	    SendOut(s, pass.string, strlen(pass.string));
	    (void)ReadReply(s, acMesg, sizeof(acMesg), (char *)0);
	}

	/* how did we do, did we get a read-only or read-write?
	 */
	if (0 == strcmp(acMesg, "attached]")) {
	    /* OK -- we are good as gold */
	    fIn = 'a';
	} else if (0 == strcmp(acMesg, "spy]") ||
		   0 == strcmp(acMesg, "ok]")) {
	    /* Humph, someone else is on
	     * or we have an old version of the server (4.X)
	     */
	    fIn = 's';
	} else if (0 == strcmp(acMesg, "host is read-only]")) {
	    fIn = 'r';
	} else if (0 == strcmp(acMesg, "line to host is down]")) {
	    /* ouch, the machine is down on the server */
	    fIn = '-';
	    Error("%s is down", pcMach);
	    if (fVerbose) {
		printf("[use `");
		putCtlc(chAttn, stdout);
		putCtlc(chEsc, stdout);
		printf("o\' to open console line]\n");
	    }
	} else if (0 == strcmp(acMesg, "no -- on ctl]")) {
	    fIn = '-';
	    Error("%s is a control port", pcMach);
	    if (fVerbose) {
		printf("[use `");
		putCtlc(chAttn, stdout);
		putCtlc(chEsc, stdout);
		printf(";\' to open a console line]\n");
	    }
	} else {
	    Error("%s: %s", pcMach, acMesg);
	    exit(EX_UNAVAILABLE);
	}
    }

    printf("[Enter `");
    putCtlc(chAttn, stdout);
    putCtlc(chEsc, stdout);
    printf("?\' for help]\n");

    /* if the host is not down, finish the connection, and force
     * the correct attachment for the user
     */
    if ('-' != fIn) {
	if (fIn == 'r') {
	    if ('s' != *pcHow) {
		Error("%s is read-only", pcMach);
	    }
	} else if (fIn != ('f' == *pcHow ? 'a' : *pcHow)) {
	    (void)sprintf(acMesg, "%c%c%c", chAttn, chEsc, *pcHow);
	    SendOut(s, acMesg, 3);
	}
	if (fReplay) {
	    (void)sprintf(acMesg, "%c%cr", chAttn, chEsc);
	    SendOut(s, acMesg, 3);
	} else if (fVerbose) {
	    (void)sprintf(acMesg, "%c%c\022", chAttn, chEsc);
	    SendOut(s, acMesg, 3);
	}
    }
    (void)fflush(stdout);
    (void)fflush(stderr);

    c2raw();

    /* read from stdin and the socket (non-blocking!).
     * rmask indicates which descriptors to read from,
     * the others are not used, nor is the result from
     * select, read, or write.
     */
    FD_ZERO(&rinit);
    FD_SET(s, &rinit);
    FD_SET(0, &rinit);
    for (;;) {
	justProcessedUrg = 0;
	if (SawUrg) {
	    processUrgentData(s);
	    justProcessedUrg = 1;
	}
	/* reset read mask and select on it
	 */
	rmask = rinit;
	while (-1 ==
	       select(sizeof(rmask) * 8, &rmask, (fd_set *) 0,
		      (fd_set *) 0, (struct timeval *)0)) {
	    rmask = rinit;
	    if (SawUrg) {
		processUrgentData(s);
		justProcessedUrg = 1;
	    }
	}

	/* anything from socket? */
	if (FD_ISSET(s, &rmask)) {
	    if ((nc = read(s, acMesg, sizeof(acMesg))) == 0) {
		if (justProcessedUrg) {
		    printf("\n");
		    Error("lost connection");
		}
		break;
	    }
	    if (fStrip) {
		for (i = 0; i < nc; ++i)
		    acMesg[i] &= 127;
	    }
	    SendOut(1, acMesg, nc);
	}

	/* anything from stdin? */
	if (FD_ISSET(0, &rmask)) {
	    if ((nc = read(0, acMesg, sizeof(acMesg))) == 0)
		break;
	    if (fStrip) {
		for (i = 0; i < nc; ++i)
		    acMesg[i] &= 127;
	    }
	    SendOut(s, acMesg, nc);
	}
    }
    c2cooked();
    if (fVerbose)
	printf("Console %s closed.\n", pcMach);
    return 0;
}


/* the group leader tells is the server to connect to			(ksb)
 * we use CallUp to start a session with each target, or forward it
 */
static int
#if USE_ANSI_PROTO
Indir(int s, char *pcMaster, char *pcMach, char *pcCmd, char *pcWho)
#else
Indir(s, pcMaster, pcMach, pcCmd, pcWho)
    int s;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    (void)sprintf(acPorts, "call:%s\r\n", pcMach);
    SendOut(s, acPorts, strlen(acPorts));

    /* get the ports number */
    if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
	Error("master forward broken");
	exit(EX_UNAVAILABLE);
    }

    if ('@' == acPorts[0]) {
	static int iLimit = 0;
	if (iLimit++ > 10) {
	    Error("forwarding level too deep!");
	    return 1;
	}
	return Gather(Indir, acPorts, pcMaster, pcMach, pcCmd, pcWho);
    }
    /* to the command to each master
     */
    return Gather(CallUp, acPorts, pcMaster, pcMach, pcCmd, pcWho);
}

#define BUF_G1		1024
#define BUF_MIN		80
#define BUF_CHUNK	(2*132)

/* Cmd is implemented separately from above because of the need buffer	(ksb)
 * the ports' output.  It's about the same as what's above otherwise.
 * We trick lint because we have to be call compatible (prototype'd)
 * the same as all the other Gather functions.
 */
static int
#if USE_ANSI_PROTO
Cmd(int s, char *pcMaster, char *pcMach, char *pcCmd, char *pcWho)
#else
Cmd(s, pcMaster, pcMach, pcCmd, pcWho)
    int s;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    static int iMax = 0;
    static char *pcBuf = (char *)0;
    int nr, iRem, i, fBrace;

    /* setup the big buffer for the server output
     */
    if ((char *)0 == pcBuf) {
	iMax = BUF_G1;
	if ((char *)0 == (pcBuf = calloc(BUF_G1, sizeof(char)))) {
	    OutOfMem();
	}
    }

    /* send sign-on stuff, then wait for a reply, like "ok\r\n"
     * before allowing a write
     */
    if (*pcCmd == 'b') {
	(void)sprintf(acMesg, "%c%c%c%s:%s\r%c%c.", DEFATTN, DEFESC,
		      *pcCmd, pcWho, pcMach, DEFATTN, DEFESC);
	SendOut(s, acMesg, strlen(acMesg));
    } else {
	(void)sprintf(acMesg, "%c%c%c%c%c.", DEFATTN, DEFESC, *pcCmd,
		      DEFATTN, DEFESC);
	SendOut(s, acMesg, 6);
    }

    /* read the server's reply,
     * We buffer until we close the connection because it
     * wouldn't be fair to ask the server to keep up with
     * itself :-)  {if we are inside a console connection}.
     */
    iRem = iMax;
    i = 0;
    while (0 < (nr = read(s, pcBuf + i, iRem))) {
	i += nr;
	iRem -= nr;
	if (iRem >= BUF_MIN) {
	    continue;
	}
	iMax += BUF_CHUNK;
	if ((char *)0 == (pcBuf = realloc(pcBuf, iMax))) {
	    OutOfMem();
	}
	iRem += BUF_CHUNK;
    }
    /* edit out the command lines [...]
     */
    iRem = fBrace = 0;
    for (nr = 0; nr < i; ++nr) {
	if (0 != fBrace) {
	    if (']' == pcBuf[nr]) {
		fBrace = 0;
	    }
	    continue;
	}
	switch (pcBuf[nr]) {
	    case '\r':
		if (0 == iRem)
		    continue;
		break;
	    case '\n':
		if (0 == iRem)
		    continue;
		(void)putchar('\n');
		iRem = 0;
		continue;
	    case '[':
		fBrace = 1;
		continue;
	}
	(void)putchar(pcBuf[nr]);
	iRem = 1;
    }
    /* (void)SendOut(1, pcBuf, i); */
    (void)fflush(stdout);

    return 0;
}

/* the masters tell us the group masters with a "groups" command	(ksb)
 */
static int
#if USE_ANSI_PROTO
CmdGroup(int s, char *pcMaster, char *pcMach, char *pcCmd, char *pcWho)
#else
CmdGroup(s, pcMaster, pcMach, pcCmd, pcWho)
    int s;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    (void)sprintf(acPorts, "groups\r\n");
    SendOut(s, acPorts, strlen(acPorts));

    /* get the ports number */
    if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
	Error("master forward broken");
	exit(EX_UNAVAILABLE);
    }
    if (fVerbose) {
	printf("%s:\r\n", pcMaster);
    }
    /* to the command to each master
     */
    return Gather(Cmd, acPorts, pcMaster, pcMach, pcCmd, pcWho);
}


/* the master tells us the machine masters with a "master" command	(ksb)
 * we ask each of those for the group members
 */
static int
#if USE_ANSI_PROTO
CmdMaster(int s, char *pcMaster, char *pcMach, char *pcCmd, char *pcWho)
#else
CmdMaster(s, pcMaster, pcMach, pcCmd, pcWho)
    int s;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    SendOut(s, "master\r\n", 8);

    /* get the ports number */
    if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
	Error("master forward broken");
	exit(EX_UNAVAILABLE);
    }
    /* to the command to each master
     */
    return Gather(CmdGroup, acPorts, pcMaster, pcMach, pcCmd, pcWho);
}


/* The masters tell us the group masters with a "groups" command.	(ksb)
 * We trick lint because we have to be call compatible (prototype'd)
 * the same as all the other Gather functions.
 */
static int
#if USE_ANSI_PROTO
Ctl(int s, char *pcMaster, char *pcMach, char *pcCmd, char *pcWho)
#else
Ctl(s, pcMaster, pcMach, pcCmd, pcWho)
    int s;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    (void)sprintf(acPorts, "%s:%s\r\n", pcCmd, pcMach);
    SendOut(s, acPorts, strlen(acPorts));

    /* get the ports number */
    if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
	Error("group leader died?");
	return 1;
    }
    if (fVerbose) {
	printf("%s:\r\n", pcMaster);
    }
    printf("%s: %s\r\n", pcMaster, acPorts);

    /* to the command to each master
     */
    return 0;
}


/* the master tells us the machine masters with a "master" command	(ksb)
 * we tell each of those the command we want them to do
 */
static int
#if USE_ANSI_PROTO
CtlMaster(int s, char *pcMaster, char *pcMach, char *pcCmd, char *pcWho)
#else
CtlMaster(s, pcMaster, pcMach, pcCmd, pcWho)
    int s;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    SendOut(s, "master\r\n", 8);

    /* get the ports number */
    if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
	Error("master forward broken");
	exit(EX_UNAVAILABLE);
    }
    /* to the command to each master
     */
    return Gather(Ctl, acPorts, pcMaster, pcMach, pcCmd, pcWho);
}


/* mainline for console client program					(ksb)
 * setup who we are, and what our loopback addr is
 * parse the cmd line,
 * (optionally) get a shutdown passwd
 * Gather results
 * exit happy or sad
 */
int
#if USE_ANSI_PROTO
main(int argc, char **argv)
#else
main(argc, argv)
    int argc;
    char **argv;
#endif
{
    char *ptr, *pcCmd, *pcTo;
    struct passwd *pwdMe;
    int opt;
    int fLocal;
    STRING acPorts = { (char *)0, 0, 0 };
    char *pcUser = (char *)0;
    char *pcMsg = (char *)0;
    int (*pfiCall) ();
    static char acOpts[] = "7aAb:De:fFGhil:M:p:PqQrRsSuvVwWx";
    extern int optind;
    extern int optopt;
    extern char *optarg;
    int i;

    outputPid = 0;		/* make sure stuff DOESN'T have the pid */

    if ((char *)0 == (progname = strrchr(argv[0], '/'))) {
	progname = argv[0];
    } else {
	++progname;
    }

    /* command line parsing
     */
    pcCmd = (char *)0;
    fLocal = 0;
    while (EOF != (opt = getopt(argc, argv, acOpts))) {
	switch (opt) {
	    case '7':		/* strip high-bit */
		fStrip = 1;
		break;

	    case 'A':		/* attach with log replay */
		fReplay = 1;
		/* fall through */
	    case 'a':		/* attach */
		pcCmd = "attach";
		break;

	    case 'b':
		pcCmd = "broadcast";
		pcMsg = optarg;
		break;

	    case 'D':
		fDebug++;
		break;

	    case 'e':		/* set escape chars */
		ParseEsc(optarg);
		break;

	    case 'F':		/* force attach with log replay */
		fReplay = 1;
		/* fall through */
	    case 'f':		/* force attach */
		pcCmd = "force";
		break;

	    case 'G':
		fRaw = 1;
		if ((char *)0 == pcCmd) {
		    pcCmd = "spy";
		}
		break;

	    case 'i':
		pcCmd = "info";
		break;

	    case 'l':
		pcUser = optarg;
		break;

	    case 'M':
		pcInMaster = optarg;
		break;

	    case 'p':
		pcPort = optarg;
		break;

	    case 'P':		/* send a pid command to the server     */
		pcCmd = "pid";
		break;

	    case 'Q':		/* only quit this host          */
		fLocal = 1;
		/*fallthough */
	    case 'q':		/* send quit command to server  */
		pcCmd = "quit";
		break;

	    case 'R':
		fLocal = 1;
		/*fallthrough */
	    case 'r':		/* display daemon version */
		pcCmd = "version";
		break;

	    case 'S':		/* spy with log replay */
		fReplay = 1;
		/* fall through */
	    case 's':		/* spy */
		pcCmd = "spy";
		break;

	    case 'u':
		pcCmd = "users";
		break;

	    case 'W':
		fLocal = 1;
		/*fallthrough */
	    case 'w':		/* who */
		pcCmd = "groups";
		break;

	    case 'x':
		pcCmd = "xamine";
		break;

	    case 'v':
		fVerbose = 1;
		break;

	    case 'V':
		fVersion = 1;
		break;

	    default:		/* huh? */
		Error
		    ("usage [-aAfFGsS] [-7Dv] [-M mach] [-p port] [-e esc] [-l username] console");
		Error
		    ("usage [-hPrRuVwWx] [-7Dv] [-M mach] [-p port] [-b message]");
		Error("usage [-qQ] [-7Dv] [-M mach] [-p port]");
		Usage(apcLong);
		exit(EX_OK);
	}
    }

    if (fVersion) {
	Version();
	exit(EX_OK);
    }

    if (pcPort == NULL) {
	Error("Severe error: pcPort is NULL????  How can that be?");
	exit(EX_UNAVAILABLE);
    }

    /* Look for non-numeric characters */
    for (i = 0; pcPort[i] != '\000'; i++)
	if (!isdigit((int)pcPort[i]))
	    break;

    if (pcPort[i] == '\000') {
	/* numeric only */
	bindPort = atoi(pcPort);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 == (pSE = getservbyname(pcPort, "tcp"))) {
	    Error("getservbyname: %s: %s", pcPort, strerror(errno));
	    exit(EX_UNAVAILABLE);
	} else {
	    bindPort = ntohs((u_short) pSE->s_port);
	}
    }

    if ((char *)0 == pcUser) {
	if (((char *)0 != (ptr = getenv("USER")) ||
	     (char *)0 != (ptr = getenv("LOGNAME"))) &&
	    (struct passwd *)0 != (pwdMe = getpwnam(ptr)) &&
	    getuid() == pwdMe->pw_uid) {
	    /* use the login $USER is set to, if it is our (real) uid */ ;
	} else if ((struct passwd *)0 == (pwdMe = getpwuid(getuid()))) {
	    Error("getpwuid: %d: %s", (int)(getuid()), strerror(errno));
	    exit(EX_UNAVAILABLE);
	}
	pcUser = pwdMe->pw_name;
    }

    /* finish resolving the command to do, call Gather
     */
    if ((char *)0 == pcCmd) {
	pcCmd = "attach";
    }

    if ('a' == *pcCmd || 'f' == *pcCmd || 's' == *pcCmd) {
	if (optind >= argc) {
	    Error("missing console name");
	    exit(EX_UNAVAILABLE);
	}
	pcTo = argv[optind++];
    } else if ('b' == *pcCmd) {
	pcTo = pcMsg;
    } else {
	pcTo = "*";
    }

    if (optind < argc) {
	Error("extra garbage on command line? (%s...)", argv[optind]);
	exit(EX_UNAVAILABLE);
    }

    buildMyString((char *)0, &acPorts);
    buildMyStringChar('@', &acPorts);
    buildMyString(pcInMaster, &acPorts);

    if ('q' == *pcCmd) {
	static STRING acPass = { (char *)0, 0, 0 };
	buildMyString((char *)0, &acPass);
#if defined(HAVE_GETPASSPHRASE)
	buildMyString(getpassphrase("Enter root password:"), &acPass);
#else
	buildMyString(getpass("Enter root password:"), &acPass);
#endif
	pfiCall = fLocal ? Ctl : CtlMaster;
	if (acPass.string == (char *)0)
	    pcTo = "";
	else
	    pcTo = acPass.string;
    } else if ('v' == *pcCmd) {
	pfiCall = fLocal ? Ctl : CtlMaster;
    } else if ('p' == *pcCmd) {
	pfiCall = CtlMaster;
    } else if ('a' == *pcCmd || 'f' == *pcCmd || 's' == *pcCmd) {
	ValidateEsc();
	pfiCall = Indir;
    } else if ('g' == *pcCmd) {
	pfiCall = fLocal ? CmdGroup : CmdMaster;
    } else {
	pfiCall = CmdMaster;
    }
    exit(Gather(pfiCall, acPorts.string, pcInMaster, pcTo, pcCmd, pcUser));
}
