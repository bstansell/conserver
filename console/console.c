/*
 *  $Id: console.c,v 5.35 2001-02-18 22:00:47-08 bryan Exp $
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <netdb.h>
#include <pwd.h>
#include <ctype.h>

#include <compat.h>

#include <port.h>
#include <version.h>


static char rcsid[] =
	"$Id: console.c,v 5.35 2001-02-18 22:00:47-08 bryan Exp $";
static char *progname =
	rcsid;
int fVerbose = 0, fReplay = 0, fRaw = 0;
int chAttn = -1, chEsc = -1;
char *pcInMaster =	/* which machine is current */
	MASTERHOST;

/* panic -- we have no more momory
 */
static void
OutOfMem()
{
	static char acNoMem[] = ": out of memory\n";
	
	write(2, progname, strlen(progname));
	write(2, acNoMem, sizeof(acNoMem)-1);
	exit(1);
}

/*
 * remove from "host1" those domains common to "host1" and "host2"
 */
static char *
whittle(host1, host2)
char *host1, *host2;
{
	char *p1, *p2;

	p1 = strchr(host1, '.');
	p2 = strchr(host2, '.');
	while (p1 != (char*)0 && p2 != (char*)0) {
		if (strcmp(p1+1, p2+1) == 0) {
			*p1 = '\000';
			break;
		}
		p1 = strchr(p1+1, '.');
		p2 = strchr(p2+1, '.');
	}
	return host1;
}

static char
	acMesg[8192+2],		/* the buffer for startup negotiation	*/
	acLocalhost[] =		/* the loopback device			*/
		"localhost",
	acThisHost[256],	/* what the remote host would call us	*/
	acMyName[256];		/* what we call ourselves		*/
static struct sockaddr_in
	local_port;		/* the looback address, if local use it	*/

/* output a control (or plain) character as a UNIX user would expect it	(ksb)
 */
static void
putCtlc(c, fp)
int c;
FILE *fp;
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
	(void)putc(c+0100, fp);
}

static char *apcLong[] = {
	"a(A)	attach politely (and replay last 20 lines)",
	"b	broadcast message",
	"d(D)	display (local) daemon version",
	"e esc	set the initial escape characters",
	"f(F)	force read/write connection (and replay)",
	"h	output this message",
	"l user	use username instead of current username",
	"M mach	master server to poll first",
	"q(Q)	send a quit command to the (local) server",
	"r	connect to the console group only",
	"s(S)	spy on a console (and replay)",
	"u	show users on the various consoles",
	"v	be more verbose",
	"V	show version information",
	"w	show who is on which console",
	"x	examine ports and baud rates",
	(char *)0
};

/* output a long message to the user
 */
static void
Usage(fp, ppc)
FILE *fp;
char **ppc;
{
	for (/* passed */; (char *)0 != *ppc; ++ppc)
		(void)fprintf(fp, "%s\n", *ppc);
}

/* expain who we are and which revision we are				(ksb)
 */
static void
Version()
{
/*	register unsigned char *puc; */

	printf("%s: %s\n", progname, THIS_VERSION);
	printf("%s: initial master server `%s\'\n", progname, pcInMaster);
	printf("%s: default escape sequence `", progname);
	putCtlc(DEFATTN, stdout);
	putCtlc(DEFESC, stdout);
	printf("\'\n");
/*	puc = (unsigned char *)&local_port.sin_addr;
	printf("%s: loopback address for %s is %d.%d.%d.%d\n", progname, acMyName, puc[0], puc[1], puc[2], puc[3]); */
}


/* convert text to control chars, we take `cat -v' style		(ksb)
 *	^X (or ^x)		contro-x
 *	M-x			x plus 8th bit
 *	c			a plain character
 */
static int
ParseChar(ppcSrc, pcOut)
char **ppcSrc, *pcOut;
{
	register int cvt, n;
	register char *pcScan = *ppcSrc;

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
		if ('@' <= n &&  n <= '_') {
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

/* find the two characters that makeup the users escape sequence	(ksb)
 */
static void
ParseEsc(pcText)
char *pcText;
{
	auto char *pcTemp;
	auto char c1, c2;

	pcTemp = pcText;
	if (ParseChar(&pcTemp, &c1) || ParseChar(&pcTemp, &c2)) {
		fprintf(stderr, "%s: poorly formed escape sequence `%s\'\n", progname, pcText);
		exit(3);
	}
	if ('\000' != *pcTemp) {
		fprintf(stderr, "%s: too many characters in new escape sequence at ...`%s\'\n", progname, pcTemp);
		exit(3);
	}
	chAttn = c1;
	chEsc = c2;
}


/* set the port for socket connection					(ksb)
 * return the fd for the new connection; if we can use the loopback, do
 * as a side effect we set ThisHost to a short name for this host
 */
int
GetPort(pcToHost, pPort, sPort)
char *pcToHost;
struct sockaddr_in *pPort;
short sPort;
{
	register int s;
	register struct hostent *hp;

#if HAVE_MEMSET
	memset((void *)pPort, '\000', sizeof(*pPort));
#else
	(void)bzero((char *)pPort, sizeof(*pPort));
#endif
/*
	if (0 == strcmp(pcToHost, strcpy(acThisHost, acMyName))) {
		(void)strcpy(pcToHost, acLocalhost);
#if HAVE_MEMCPY
		memcpy((char *)&pPort->sin_addr, (char *)&local_port.sin_addr, sizeof(local_port.sin_addr));
#else
		(void)bcopy((char *)&local_port.sin_addr, (char *)&pPort->sin_addr, sizeof(local_port.sin_addr));
#endif
	} else */
	if ((struct hostent *)0 != (hp = gethostbyname(pcToHost))) {
#if HAVE_MEMCPY
		memcpy((char *)&pPort->sin_addr, (char *)hp->h_addr, hp->h_length);
#else
		(void)bcopy((char *)hp->h_addr, (char *)&pPort->sin_addr, hp->h_length);
#endif
	} else {
		fprintf(stderr, "%s: gethostbyname: %s: %s\n", progname, pcToHost, hstrerror(h_errno));
		exit(9);
	}
	pPort->sin_port = sPort;
	pPort->sin_family = AF_INET;

	/* make hostname short, if we are calling ourself, chop at first dot
	if (0 == strcmp(pcToHost, acLocalhost)) {
		register char *pcChop;
		if ((char *)0 != (pcChop = strchr(acThisHost, '.'))) {
			*pcChop = '\000';
		}
	} else {
		(void)whittle(acThisHost, pcToHost);
	}
	*/

	/* set up the socket to talk to the server for all consoles
	 * (it will tell us who to talk to to get a real connection)
	 */
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "%s: socket: %s\n", progname, strerror(errno));
		exit(1);
	}
	if (connect(s, (struct sockaddr *)pPort, sizeof(*pPort)) < 0) {
		fprintf(stderr, "%s: connect: %d@%s: %s\n", progname, ntohs(pPort->sin_port), pcToHost, strerror(errno));
		exit(1);
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
c2raw()
{
#if HAVE_TERMIOS_H
	auto struct termios n_tios;
#else
# if HAVE_TERMIO_H
	auto struct termio n_tio;
# else
	auto struct sgttyb n_sty;
	auto struct tchars n_tchars;
	auto struct ltchars n_ltchars;
# endif
#endif

	if (!isatty(0) || 0 != screwy)
		return;

#ifdef HAVE_TERMIOS_H
# ifdef HAVE_TCGETATTR
	if (0 != tcgetattr(0, & o_tios))
# else
	if (0 != ioctl(0, TCGETS, & o_tios))
# endif
	{
		fprintf(stderr, "%s: iotcl: getsw: %s\n", progname, strerror(errno));
		exit(10);
	}
	n_tios = o_tios;
	n_tios.c_iflag &= ~(INLCR|IGNCR|ICRNL|IUCLC|IXON);
	n_tios.c_oflag &= ~OPOST;
	n_tios.c_lflag &= ~(ICANON|ISIG|ECHO);
	n_tios.c_cc[VMIN] = 1;
	n_tios.c_cc[VTIME] = 0;
# ifdef HAVE_TCSETATTR
	if (0 != tcsetattr(0, TCSANOW, & n_tios))
# else
	if (0 != ioctl(0, TCSETS, & n_tios))
# endif
	{
		fprintf(stderr, "%s: getarrt: %s\n", progname, strerror(errno));
		exit(10);
	}
#else
# ifdef HAVE_TERMIO_H
	if (0 != ioctl(0, TCGETA, & o_tio)) {
		fprintf(stderr, "%s: iotcl: geta: %s\n", progname, strerror(errno));
		exit(10);
	}
	n_tio = o_tio;	
	n_tio.c_iflag &= ~(INLCR|IGNCR|ICRNL|IUCLC|IXON);
	n_tio.c_oflag &= ~OPOST;
	n_tio.c_lflag &= ~(ICANON|ISIG|ECHO|ECHOE|ECHOK|ECHONL);
	n_tio.c_cc[VMIN] = 1;
	n_tio.c_cc[VTIME] = 0;
	if (0 != ioctl(0, TCSETAF, & n_tio)) {
		fprintf(stderr, "%s: iotcl: seta: %s\n", progname, strerror(errno));
		exit(10);
	}
# else
	if (0 != ioctl(0, TIOCGETP, (char *)&o_sty)) {
		fprintf(stderr, "%s: iotcl: getp: %s\n", progname, strerror(errno));
		exit(10);
	}
	n_sty = o_sty;

	n_sty.sg_flags |= CBREAK;
	n_sty.sg_flags &= ~(CRMOD|ECHO);
	n_sty.sg_kill = -1;
	n_sty.sg_erase = -1;
	if (0 != ioctl(0, TIOCSETP, (char *)&n_sty)) {
		fprintf(stderr, "%s: iotcl: setp: %s\n", progname, strerror(errno));
		exit(10);
	}

	/* stty undef all tty chars
	 */
	if (-1 == ioctl(0, TIOCGETC, (char *)&n_tchars)) {
		fprintf(stderr, "%s: ioctl: getc: %s\n", progname, strerror(errno));
		return;
	}
	o_tchars = n_tchars;
	n_tchars.t_intrc = -1;
	n_tchars.t_quitc = -1;
	if (-1 == ioctl(0, TIOCSETC, (char *)&n_tchars)) {
		fprintf(stderr, "%s: ioctl: setc: %s\n", progname, strerror(errno));
		return;
	}
	if (-1 == ioctl(0, TIOCGLTC, (char *)&n_ltchars)) {
		fprintf(stderr, "%s: ioctl: gltc: %s\n", progname, strerror(errno));
		return;
	}
	o_ltchars = n_ltchars;
	n_ltchars.t_suspc = -1;
	n_ltchars.t_dsuspc = -1;
	n_ltchars.t_flushc = -1;
	n_ltchars.t_lnextc = -1;
	if (-1 == ioctl(0, TIOCSLTC, (char *)&n_ltchars)) {
		fprintf(stderr, "%s: ioctl: sltc: %s\n", progname, strerror(errno));
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
c2cooked()
{
	if (!screwy)
		return;
#ifdef HAVE_TERMIOS_H
# ifdef HAVE_TCSETATTR
	tcsetattr(0, TCSANOW, &o_tios);
# else
	(void)ioctl(0, TCSETS, (char *)&o_tios);
# endif
#else
# ifdef HAVE_TERMIO_H
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
SendOut(fd, pcBuf, iLen)
int fd, iLen;
char *pcBuf;
{
	register int nr;

	while (0 != iLen) {
		if (-1 == (nr = write(fd, pcBuf, iLen))) {
			c2cooked();
			fprintf(stderr, "%s: lost connection\n", progname);
			exit(3);
		}
		iLen -= nr;
		pcBuf += nr;
	}
}

/* read a reply from the console server					(ksb)
 * if pcWnat == (char *)0 we strip \r\n from the and and return strlen
 */
static int
ReadReply(fd, pcBuf, iLen, pcWant)
int fd, iLen;
char *pcBuf, *pcWant;
{
	register int nr, j, iKeep;
	
	iKeep = iLen;
	for (j = 0; j < iLen; /* j+=nr */) {
		switch (nr = read(fd, &pcBuf[j], iLen-1)) {
		case 0:
			if (iKeep != iLen) {
				break;
			}
			/* fall through */
		case -1:
			c2cooked();
			fprintf(stderr, "%s: lost connection\n", progname);
			exit(3);
		default:
			j += nr;
			iLen -= nr;
			if ('\n' == pcBuf[j-1]) {
				pcBuf[j] = '\000';
				break;
			}
			if (0 == iLen) {
				c2cooked();
				fprintf(stderr, "%s: reply too long\n", progname);
				exit(3);
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
		while (0 != j && isspace(pcBuf[j-1])) {
			pcBuf[--j] = '\000';
		}
		return j;
	}
	return strcmp(pcBuf, pcWant);
}

#if defined(SERVICENAME)
static struct servent *pSE;
#endif

/* call a machine master for group master ports and machine master ports
 * take a list like "1782@localhost:@mentor.cc.purdue.edu:@pop.stat.purdue.edu"
 * and send the given command to the group leader at 1782
 * and ask the machine master at mentor for more group leaders
 * and ask the machine master at pop.stat for more group leaders
 */
static int
Gather(pfi, pcPorts, pcMaster, pcTo, pcCmd, pcWho)
int (*pfi)();
char *pcPorts, *pcMaster, *pcTo, *pcCmd, *pcWho;
{
	register int s;
	register short j;
	register char *pcNext, *pcServer;
	auto char acExcg[256];
	auto struct sockaddr_in client_port;
	auto int iRet = 0;

	for (/* param */; '\000' != *pcPorts; pcPorts = pcNext) {
		if ((char *)0 == (pcNext = strchr(pcPorts, ':')))
			pcNext = "";
		else
			*pcNext++ = '\000';

		(void)strcpy(acExcg, pcMaster);
		if ((char *)0 != (pcServer = strchr(pcPorts, '@'))) {
			*pcServer++ = '\000';
			if ('\000' != *pcServer) {
				(void)strcpy(acExcg, pcServer);
			}
		}

		if ('\000' == *pcPorts) {
#if defined(SERVICENAME)
			/* in net order -- ksb */
			j = pSE->s_port;
#else
# if defined(PORTNUMBER)
			j = htons(PORTNUMBER);
# else
			fprintf(stderr, "%s: no port or service compiled in?\n", progname);
			exit(8);
# endif
#endif
		} else if (!isdigit(pcPorts[0])) {
			fprintf(stderr, "%s: %s: %s\n", progname, pcMaster, pcPorts);
			exit(2);
		} else {
			j = htons((short)atoi(pcPorts));
		}

		s = GetPort(acExcg, & client_port, j);

		if (0 != ReadReply(s, acMesg, sizeof(acMesg), "ok\r\n")) {
			fprintf(stderr, "%s: %s: %s", progname, acExcg, acMesg);
			exit(4);
		}

		iRet += (*pfi)(s, acExcg, pcTo, pcCmd, pcWho);
		(void)close(s);
		if ((char *)0 != pcServer) {
			*pcServer = '@';
		}
	}
	return iRet;
}


static int SawUrg = 0;

/* when the conserver program gets the suspend sequence it will send us
 * an out of band command to suspend ourself.  We just tell the reader
 * routine we saw one
 */
RETSIGTYPE
oob(sig)
int sig;
{
	++SawUrg;
}

void
processUrgentData(s)
int s;
{
	static char acCmd[64];

	SawUrg = 0;
#if defined(SIGURG)
	(void)signal(SIGURG, oob);
#endif

	/* get the pending urgent message
	 */
	while (recv(s, acCmd, 1, MSG_OOB) < 0) {
		switch (errno) {
		case EWOULDBLOCK:
			/* clear any pending input to make room */
			(void)read(s, acCmd, sizeof(acCmd));
			CSTROUT(1, ".");
			continue;
		case EINVAL:
		default:
			fprintf(stderr, "%s: recv: %d: %s\r\n", progname, s, strerror(errno));
			sleep(1);
			continue;
		}
	}
	switch (acCmd[0]) {
	case OB_SUSP:
#if defined(SIGSTOP)
		CSTROUT(1, "stop]");
		c2cooked();
		(void)kill(getpid(), SIGSTOP);
		c2raw();
		CSTROUT(1, "[press any character to continue");
#else
		CSTROUT(1, "stop not supported -- press any character to continue");
#endif
		break;
	case OB_DROP:
		CSTROUT(1, "dropped by server]\r\n");
		c2cooked();
		exit(1);
		/*NOTREACHED*/
	default:
		fprintf(stderr, "%s: unknown out of band command `%c\'\r\n", progname, acCmd[0]);
		(void)fflush(stderr);
		break;
	}
}

/* interact with a group server					(ksb)
 */
static int
CallUp(s, pcMaster, pcMach, pcHow, pcUser)
int s;
char *pcMaster, *pcMach, *pcHow, *pcUser;
{
	register int nc;
	register int fIn;
	auto fd_set rmask, rinit;
	extern int atoi();

	if (fVerbose) {
		printf("%s: %s to %s (%son %s)\n", progname, pcHow, pcMach, fRaw ? "raw " : "", pcMaster);
	}
#if defined(F_SETOWN)
	if (-1 == fcntl(s, F_SETOWN, getpid())) {
		fprintf(stderr, "%s: fcntl: %d: %s\n", progname, s, strerror(errno));
	}
#else
# if defined(SIOCSPGRP)
	{
	auto int iTemp;
	/* on the HP-UX systems if different
	 */
	iTemp = -getpid();
	if (-1 == ioctl(s, SIOCSPGRP, & iTemp)) {
		fprintf(stderr, "%s: ioctl: %d: %s\n", progname, s, strerror(errno));
	}
	}
# endif
#endif
#if defined(SIGURG)
	(void)signal(SIGURG, oob);
#endif

	/* change escape sequence (if set on the command line)
	 * and replay the log for the user, if asked
	 */
	if (chAttn == -1 || chEsc == -1) {
		chAttn = DEFATTN;
		chEsc = DEFESC;
	} else {
		/* tell the conserver to change escape sequences, assmue OK
		 * (we'll find out soon enough)
		 */
		(void)sprintf(acMesg, "%c%ce%c%c", DEFATTN, DEFESC, chAttn, chEsc);
		SendOut(s, acMesg, 5);
		if (0 == ReadReply(s, acMesg, sizeof(acMesg), (char *)0)) {
			fprintf(stderr, "protocol botch on redef on escape sequence\n");
			exit(8);
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
		if (0 != ReadReply(s, acMesg, sizeof(acMesg), "[login:\r\n") && 0 != strcmp(acMesg, "\r\n[login:\r\n")) {
			fprintf(stderr, "%s: call: %s\n", progname, acMesg);
			exit(2);
		}

		(void)sprintf(acMesg, "%s@%s\n", pcUser, acThisHost);
		SendOut(s, acMesg, strlen(acMesg));
		if (0 != ReadReply(s, acMesg, sizeof(acMesg), "host:\r\n")) {
			fprintf(stderr, "%s: %s\n", progname, acMesg);
			exit(2);
		}

		/* which host we want, and a passwd if asked for one
		 */
		(void)sprintf(acMesg, "%s\n", pcMach);
		SendOut(s, acMesg, strlen(acMesg));
		(void)ReadReply(s, acMesg, sizeof(acMesg), (char *)0);
		if (0 == strcmp(acMesg, "passwd:")) {
			auto char pass[32];
			(void)sprintf(acMesg, "Enter %s's password:", pcUser);
			(void)strcpy(pass, getpass(acMesg));
			(void)sprintf(acMesg, "%s\n", pass);
			SendOut(s, acMesg, strlen(acMesg));
			(void)ReadReply(s, acMesg, sizeof(acMesg), (char *)0);
		}

		/* how did we do, did we get a read-only or read-write?
		 */
		if (0 == strcmp(acMesg, "attached]")) {
			/* OK -- we are good as gold */
			fIn = 'a';
		} else if (0 == strcmp(acMesg, "spy]") || 0 == strcmp(acMesg, "ok]")) {
			/* Humph, someone else is on
			 * or we have an old version of the server (4.X)
			 */
			fIn = 's';
		} else if (0 == strcmp(acMesg, "host is read-only]")) {
			fIn = 'r';
		} else if (0 == strcmp(acMesg, "line to host is down]")) {
			/* ouch, the machine is down on the server */
			fIn = '-';
			fprintf(stderr, "%s: %s is down\n", progname, pcMach);
			if (fVerbose) {
				printf("[use `");
				putCtlc(chAttn, stdout);
				putCtlc(chEsc, stdout);
				printf("o\' to open console line]\n");
			}
		} else if (0 == strcmp(acMesg, "no -- on ctl]")) {
			fIn = '-';
			fprintf(stderr, "%s: %s is a control port\n", progname, pcMach);
			if (fVerbose) {
				printf("[use `");
				putCtlc(chAttn, stdout);
				putCtlc(chEsc, stdout);
				printf(";\' to open a console line]\n");
			}
		} else {
			fprintf(stderr, "%s: %s: %s\n", progname, pcMach, acMesg);
			exit(5);
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
				fprintf(stderr, "%s: %s is read-only\n", progname, pcMach);
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
	FD_ZERO(& rinit);
	FD_SET(s, &rinit);
	FD_SET(0, &rinit);
	for (;;) {
		if ( SawUrg ) {
			processUrgentData(s);
		}
		/* reset read mask and select on it
		 */
		rmask = rinit;
		while (-1 == select(sizeof(rmask)*8, &rmask, (fd_set *)0, (fd_set *)0, (struct timeval *)0)) {
			rmask = rinit;
			if ( SawUrg ) {
				processUrgentData(s);
			}
		}

		/* anything from socket? */
		if (FD_ISSET(s, &rmask)) {
			if ((nc = read(s, acMesg, sizeof(acMesg))) == 0) {
				break;
			}
#if STRIP8
			/* clear parity? */
			for (i = 0; i < nc; ++i)
				acMesg[i] &= 127;
#endif
			SendOut(1, acMesg, nc);
		}
		/* anything from stdin? */
		if (FD_ISSET(0, &rmask)) {
			if ((nc = read(0, acMesg, sizeof(acMesg))) == 0)
				break;
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
Indir(s, pcMaster, pcMach, pcCmd, pcWho)
int s;
char *pcMaster, *pcMach, *pcCmd, *pcWho;
{
	auto char acPorts[4097];

	/* send request for master list
	 */
	(void)sprintf(acPorts, "call:%s\r\n", pcMach);
	SendOut(s, acPorts, strlen(acPorts));

	/* get the ports number */
	if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
		fprintf(stderr, "%s: master forward broken\n", progname);
		exit(1);
	}

	if ('@' == acPorts[0]) {
		static int iLimit = 0;
		if (iLimit++ > 10) {
			fprintf(stderr, "%s: forwarding level too deep!\n", progname);
			return 1;
		}
		return Gather(Indir, acPorts, pcMaster, pcMach, pcCmd, pcWho);
	}
	/* to the command to each master
	 */
	return Gather(CallUp, acPorts, pcMaster, pcMach, pcCmd, pcWho);
}

#define BUF_G1		(MAXGRP*80)
#define BUF_MIN		80
#define BUF_CHUNK	(2*132)

/* Cmd is implemented separately from above because of the need buffer	(ksb)
 * the ports' output.  It's about the same as what's above otherwise.
 * We trick lint because we have to be call compatible (prototype'd)
 * the same as all the other Gather functions.
 */
/*ARGSUSED*/
static int
Cmd(s, pcMaster, pcMach, pcCmd, pcWho)
int s;
char *pcMaster, *pcMach, *pcCmd, *pcWho;
{
	static int iMax = 0;
	static char *pcBuf = (char *)0;
	register int nr, iRem, i, fBrace;

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
	if ( *pcCmd == 'b' ) {
	    (void)sprintf(acMesg, "%c%c%c%s\r\n%c%c.", DEFATTN, DEFESC, *pcCmd, pcMach, DEFATTN, DEFESC);
	    SendOut(s, acMesg, strlen(acMesg));
	} else {
	    (void)sprintf(acMesg, "%c%c%c%c%c.", DEFATTN, DEFESC, *pcCmd, DEFATTN, DEFESC);
	    SendOut(s, acMesg, 6);
	}

	/* read the server's reply,
	 * We buffer until we close the connection because it
	 * wouldn't be fair to ask the server to keep up with
	 * itself :-)  {if we are inside a console connection}.
	 */
	iRem = iMax;
	i = 0;
	while (0 < (nr = read(s, pcBuf+i, iRem))) {
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
CmdGroup(s, pcMaster, pcMach, pcCmd, pcWho)
int s;
char *pcMaster, *pcMach, *pcCmd, *pcWho;
{
	auto char acPorts[4097];

	/* send request for master list
	 */
	(void)sprintf(acPorts, "groups\r\n", pcCmd);
	SendOut(s, acPorts, strlen(acPorts));

	/* get the ports number */
	if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
		fprintf(stderr, "%s: master forward broken\n", progname);
		exit(1);
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
CmdMaster(s, pcMaster, pcMach, pcCmd, pcWho)
int s;
char *pcMaster, *pcMach, *pcCmd, *pcWho;
{
	auto char acPorts[4097];

	/* send request for master list
	 */
	CSTROUT(s, "master\r\n");

	/* get the ports number */
	if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
		fprintf(stderr, "%s: master forward broken\n", progname);
		exit(1);
	}
	/* to the command to each master
	 */
	return Gather(CmdGroup, acPorts, pcMaster, pcMach, pcCmd, pcWho);
}


/* The masters tell us the group masters with a "groups" command.	(ksb)
 * We trick lint because we have to be call compatible (prototype'd)
 * the same as all the other Gather functions.
 */
/*ARGSUSED*/
static int
Ctl(s, pcMaster, pcMach, pcCmd, pcWho)
int s;
char *pcMaster, *pcMach, *pcCmd, *pcWho;
{
	auto char acPorts[4097];

	/* send request for master list
	 */
	(void)sprintf(acPorts, "%s:%s\r\n", pcCmd, pcMach);
	SendOut(s, acPorts, strlen(acPorts));

	/* get the ports number */
	if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
		fprintf(stderr, "%s: group leader died?\n", progname);
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
CtlMaster(s, pcMaster, pcMach, pcCmd, pcWho)
int s;
char *pcMaster, *pcMach, *pcCmd, *pcWho;
{
	auto char acPorts[4097];

	/* send request for master list
	 */
	CSTROUT(s, "master\r\n");

	/* get the ports number */
	if (0 >= ReadReply(s, acPorts, sizeof(acPorts), (char *)0)) {
		fprintf(stderr, "%s: master forward broken\n", progname);
		exit(1);
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
main(argc, argv)
int argc;
char **argv;
{
	register struct hostent *hp;
	register char *ptr, *pcCmd, *pcTo;
	register struct passwd *pwdMe;
	auto int opt;
	auto int fLocal;
	auto char acPorts[1024];
	auto char *pcUser;
	auto char *pcMsg;
	auto int (*pfiCall)();
	static char acOpts[] = "b:aAdDsSfFe:hl:M:pvVwWUqQrux";
	extern long atol();
	extern int optind;
	extern int optopt;
	extern char *optarg;

	if ((char *)0 == (progname = strrchr(argv[0], '/'))) {
		progname = argv[0];
	} else {
		++progname;
	}

#if defined(SERVICENAME)
	if ((struct servent *)0 == (pSE = getservbyname(SERVICENAME, "tcp"))) {
		fprintf(stderr, "%s: getservbyname: %s: %s\n", progname, SERVICENAME, strerror(errno));
		exit(1);
	}
#endif

	if (((char *)0 != (ptr = getenv("USER")) || (char *)0 != (ptr = getenv("LOGNAME"))) &&
	    (struct passwd *)0 != (pwdMe = getpwnam(ptr)) &&
	    getuid() == pwdMe->pw_uid) {
		/* use the login $USER is set to, if it is our (real) uid */;
	} else if ((struct passwd *)0 == (pwdMe = getpwuid(getuid()))) {
		fprintf(stderr, "%s: getpwuid: %d: %s\n", progname, getuid(), strerror(errno));
		exit(1);
	}
	pcUser = pwdMe->pw_name;

	/* get the out hostname and the loopback devices IP address
	 * (for trusted connections mostly)
	 */
	if (-1 == gethostname(acMyName, sizeof(acMyName)-1)) {
		fprintf(stderr, "%s: gethostname: %s\n", progname, strerror(errno));
		exit(2);
	}
	if ((struct hostent *)0 != (hp = gethostbyname(acLocalhost))) {
#if HAVE_MEMCPY
		memcpy((char *)&local_port.sin_addr, (char *)hp->h_addr, hp->h_length);
#else
		(void)bcopy((char *)hp->h_addr, (char *)&local_port.sin_addr, hp->h_length);
#endif
	} else {
		acLocalhost[0] = '\000';
	}

	/* command line parsing
	 */
	pcCmd = (char *)0;
	fLocal = 0;
	while (EOF != (opt = getopt(argc, argv, acOpts))) {
		switch(opt) {
		case 'A':	/* attach with log replay */
			fReplay = 1;
			/* fall through */
		case 'a':	/* attach */
			pcCmd = "attach";
			break;

		case 'b':
			pcCmd = "broadcast";
			pcMsg = optarg;
			break;

		case 'D':
			fLocal = 1;
			/*fallthrough*/
		case 'd':	/* display daemon version */
			pcCmd = "version";
			break;

		case 'e':	/* set escape chars */
			ParseEsc(optarg);
			break;

		case 'F':	/* force attach with log replay */
			fReplay = 1;
			/* fall through */
		case 'f':	/* force attach */
			pcCmd = "force";
			break;

		case 'M':
			pcInMaster = optarg;
			break;

		case 'l':
			pcUser = optarg;
			break;

		case 'r':
			fRaw = 1;
			if ((char *)0 == pcCmd) {
				pcCmd = "spy";
			}
			break;

		case 'S':	/* spy with log replay */
			fReplay = 1;
			/* fall through */
		case 's':	/* spy */
			pcCmd = "spy";
			break;

		case 'u':
		case 'U':
			pcCmd = "users";
			break;

		case 'w':	/* who */
		case 'W' :
			pcCmd = "groups";
			break;

		case 'x':
			pcCmd = "xamine";
			break;
		
		case 'p':	/* send a pid command to the server	*/
			pcCmd = "pid";
			break;

		case 'Q':	/* only quit this host		*/
			fLocal = 1;
			/*fallthough*/
		case 'q':	/* send quit command to server	*/
			pcCmd = "quit";
			break;

		case 'v':
			fVerbose = 1;
			break;

		case 'V':
			Version();
			exit(0);

		default:	/* huh? */
			if ( opt != 'h' )
			    fprintf(stderr, "%s: unknown option `%c\'\n", progname, optopt);
			printf("%s: usage [-aAfFsS] [-rv] [-e esc] [-M mach] [-l username] machine\n", progname);
			printf("%s: usage [-v] [-hdDuVwx] [-b message]\n", progname);
			printf("%s: usage [-qQ] [-M mach]\n", progname);
			Usage(stdout, apcLong);
			exit(0);
			/*NOTREACHED*/

		}
	}

	/* finish resolving the command to do, call Gather
	 */
	if ((char *)0 == pcCmd) {
		pcCmd = "attach";
	}

	if ('a' == *pcCmd || 'f' == *pcCmd || 's' == *pcCmd) {
		if (optind >= argc) {
			fprintf(stderr, "%s: missing machine name\n", progname);
			exit(1);
		}
		pcTo = argv[optind++];
	} else {
		pcTo = "*";
	}
	if (optind < argc) {
		fprintf(stderr, "%s: extra garbage on command line? (%s...)\n", progname, argv[optind]);
		exit(1);
	}
	(void)sprintf(acPorts, "@%s", pcInMaster);
	if ('b' == *pcCmd) {
	    pcTo = pcMsg;
	}
	if ('q' == *pcCmd) {
		auto char acPass[32];
		(void)strcpy(acPass, getpass("Enter root password:"));
		pfiCall = fLocal ? Ctl : CtlMaster;
		pcTo = acPass;
	} else if ('v' == *pcCmd) {
		pfiCall = fLocal ? Ctl : CtlMaster;
	} else if ('p' == *pcCmd) {
		pfiCall = CtlMaster;
	} else if ('a' == *pcCmd || 'f' == *pcCmd || 's' == *pcCmd) {
		pfiCall = Indir;
	} else {
		pfiCall = CmdMaster;
	}
	exit(Gather(pfiCall, acPorts, pcInMaster, pcTo, pcCmd, pcUser));
}
