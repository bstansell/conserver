/*
 *  $Id: console.c,v 5.117 2003-04-06 05:29:24-07 bryan Exp $
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
#include <util.h>

#include <version.h>

#if HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#endif


int fReplay = 0, fRaw = 0, fVersion = 0, fStrip = 0;
#if HAVE_OPENSSL
int fReqEncryption = 1;
char *pcCredFile = (char *)0;
#endif
int chAttn = -1, chEsc = -1;
char *pcInMaster =		/* which machine is current */
    MASTERHOST;
char *pcPort = DEFPORT;
unsigned short bindPort;
CONSFILE *cfstdout;

static char acMesg[8192];	/* the buffer for startup negotiation   */

#if HAVE_OPENSSL
SSL_CTX *ctx = (SSL_CTX *) 0;

void
#if PROTOTYPES
SetupSSL(void)
#else
SetupSSL()
#endif
{
    if (ctx == (SSL_CTX *) 0) {
	SSL_load_error_strings();
	if (!SSL_library_init()) {
	    Error("SSL library initialization failed");
	    exit(EX_UNAVAILABLE);
	}
	if ((ctx = SSL_CTX_new(SSLv23_method())) == (SSL_CTX *) 0) {
	    Error("Creating SSL context failed");
	    exit(EX_UNAVAILABLE);
	}
	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
	    Error("Could not load SSL default CA file and/or directory");
	    exit(EX_UNAVAILABLE);
	}
	if (pcCredFile != (char *)0) {
	    if (SSL_CTX_use_certificate_chain_file(ctx, pcCredFile) != 1) {
		Error("Could not load SSL certificate from '%s'",
		      pcCredFile);
		exit(EX_UNAVAILABLE);
	    }
	    if (SSL_CTX_use_PrivateKey_file
		(ctx, pcCredFile, SSL_FILETYPE_PEM) != 1) {
		Error("Could not SSL private key from '%s'", pcCredFile);
		exit(EX_UNAVAILABLE);
	    }
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, SSLVerifyCallback);
	SSL_CTX_set_options(ctx,
			    SSL_OP_ALL | SSL_OP_NO_SSLv2 |
			    SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_mode(ctx,
			 SSL_MODE_ENABLE_PARTIAL_WRITE |
			 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
			 SSL_MODE_AUTO_RETRY);
	if (SSL_CTX_set_cipher_list(ctx, "ALL:!LOW:!EXP:!MD5:@STRENGTH") !=
	    1) {
	    Error("Setting SSL cipher list failed");
	    exit(EX_UNAVAILABLE);
	}
    }
}

void
#if PROTOTYPES
AttemptSSL(CONSFILE * pcf)
#else
AttemptSSL(pcf)
    CONSFILE *pcf;
#endif
{
    SSL *ssl;

    if (ctx == (SSL_CTX *) 0) {
	Error("WTF?  The SSL context disappeared?!?!?");
	exit(EX_UNAVAILABLE);
    }
    if (!(ssl = SSL_new(ctx))) {
	Error("Couldn't create new SSL context");
	exit(EX_UNAVAILABLE);
    }
    FileSetSSL(pcf, ssl);
    SSL_set_fd(ssl, FileFDNum(pcf));
    Debug(1, "About to SSL_connect() on fd %d", FileFDNum(pcf));
    if (SSL_connect(ssl) <= 0) {
	Error("SSL negotiation failed");
	ERR_print_errors_fp(stderr);
	exit(EX_UNAVAILABLE);
    }
    FileSetType(pcf, SSLSocket);
    if (fDebug)
	Debug(1, "SSL Connection: %s :: %s", SSL_get_cipher_version(ssl),
	      SSL_get_cipher_name(ssl));
}
#endif

void
#if PROTOTYPES
DestroyDataStructures(void)
#else
DestroyDataStructures()
#endif
{
}

/* output a control (or plain) character as a UNIX user would expect it	(ksb)
 */
static void
#if PROTOTYPES
PutCtlc(int c, FILE * fp)
#else
PutCtlc(c, fp)
    int c;
    FILE *fp;
#endif
{
    if (0 != (0200 & c)) {
	putc('M', fp);
	putc('-', fp);
	c &= ~0200;
    }
    if (isprint(c)) {
	putc(c, fp);
	return;
    }
    putc('^', fp);
    if (c == 0177) {
	putc('?', fp);
	return;
    }
    putc(c + 0100, fp);
}

/* output a long message to the user
 */
static void
#if PROTOTYPES
Usage(int wantfull)
#else
Usage(wantfull)
    int wantfull;
#endif
{
    static char *full[] = {
	"7       strip the high bit of all console data",
	"a(A)    attach politely (and replay last 20 lines)",
	"b(B)    send broadcast message to all users (on master)",
#if HAVE_OPENSSL
	"c cred  load an SSL certificate and key from the PEM encoded file",
#else
	"c cred  ignored - encryption not compiled into code",
#endif
	"D       enable debug output, sent to stderr",
	"e esc   set the initial escape characters",
#if HAVE_OPENSSL
	"E       don't require encrypted connections",
#else
	"E       ignored - encryption not compiled into code",
#endif
	"f(F)    force read/write connection (and replay)",
	"G       connect to the console group only",
	"i(I)    display information in machine-parseable form (on master)",
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

    fprintf(stderr,
	    "%s: usage [-aAEfFGsS] [-7Dv] [-c cred] [-M mach] [-p port] [-e esc] [-l username] console\n",
	    progname);
    fprintf(stderr,
	    "%s: usage [-hiIPrRuVwWx] [-7Dv] [-M mach] [-p port] [-[bB] message]\n",
	    progname);
    fprintf(stderr, "%s: usage [-qQ] [-7Dv] [-M mach] [-p port]\n",
	    progname);

    if (wantfull) {
	int i;
	for (i = 0; full[i] != (char *)0; i++)
	    fprintf(stderr, "\t%s\n", full[i]);
    }
}

/* expain who we are and which revision we are				(ksb)
 */
static void
#if PROTOTYPES
Version()
#else
Version()
#endif
{
    int i;
    static STRING *acA1 = (STRING *) 0;
    static STRING *acA2 = (STRING *) 0;
    char *optionlist[] = {
#if HAVE_DMALLOC
	"dmalloc",
#endif
#if USE_LIBWRAP
	"libwrap",
#endif
#if HAVE_OPENSSL
	"openssl",
#endif
#if HAVE_PAM
	"pam",
#endif
#if HAVE_POSIX_REGCOMP
	"regex",
#endif
	(char *)0
    };

    if (acA1 == (STRING *) 0)
	acA1 = AllocString();
    if (acA2 == (STRING *) 0)
	acA2 = AllocString();

    Msg("%s", THIS_VERSION);
    Msg("initial master server `%s\'", pcInMaster);
    Msg("default escape sequence `%s%s\'", FmtCtl(DEFATTN, acA1),
	FmtCtl(DEFESC, acA2));
    /* Look for non-numeric characters */
    for (i = 0; pcPort[i] != '\000'; i++)
	if (!isdigit((int)pcPort[i]))
	    break;

    if (pcPort[i] == '\000') {
	/* numeric only */
	bindPort = atoi(pcPort);
	Msg("on port %hu (referenced as `%s')", bindPort, pcPort);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 == (pSE = getservbyname(pcPort, "tcp"))) {
	    Error("getservbyname(%s): %s", pcPort, strerror(errno));
	} else {
	    bindPort = ntohs((u_short) pSE->s_port);
	    Msg("on port %hu (referenced as `%s')", bindPort, pcPort);
	}
    }
    BuildString((char *)0, acA1);
    if (optionlist[0] == (char *)0)
	BuildString("none", acA1);
    for (i = 0; optionlist[i] != (char *)0; i++) {
	if (i == 0)
	    BuildString(optionlist[i], acA1);
	else {
	    BuildString(", ", acA1);
	    BuildString(optionlist[i], acA1);
	}
    }
    Msg("options: %s", acA1->string);
#if HAVE_DMALLOC
    BuildString((char *)0, acA1);
    BuildStringChar('0' + DMALLOC_VERSION_MAJOR, acA1);
    BuildStringChar('.', acA1);
    BuildStringChar('0' + DMALLOC_VERSION_MINOR, acA1);
    BuildStringChar('.', acA1);
    BuildStringChar('0' + DMALLOC_VERSION_PATCH, acA1);
    if (DMALLOC_VERSION_BETA != 0) {
	BuildString("-b", acA1);
	BuildStringChar('0' + DMALLOC_VERSION_BETA, acA1);
    }
    Msg("dmalloc version: %s", acA1->string);
#endif
#if HAVE_OPENSSL
    Msg("openssl version: %s", OPENSSL_VERSION_TEXT);
#endif
    Msg("built with `%s'", CONFIGINVOCATION);
    if (fVerbose)
	printf(COPYRIGHT);
}


/* convert text to control chars, we take `cat -v' style		(ksb)
 *	^X (or ^x)		contro-x
 *	M-x			x plus 8th bit
 *	c			a plain character
 */
static int
#if PROTOTYPES
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
#if PROTOTYPES
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
#if PROTOTYPES
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
CONSFILE *
#if PROTOTYPES
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
    bzero((char *)pPort, sizeof(*pPort));
#endif

    pPort->sin_addr.s_addr = inet_addr(pcToHost);
    if ((in_addr_t) (-1) == pPort->sin_addr.s_addr) {
	if ((struct hostent *)0 != (hp = gethostbyname(pcToHost))) {
#if HAVE_MEMCPY
	    memcpy((char *)&pPort->sin_addr.s_addr, (char *)hp->h_addr,
		   hp->h_length);
#else
	    bcopy((char *)hp->h_addr, (char *)&pPort->sin_addr.s_addr,
		  hp->h_length);
#endif
	} else {
	    Error("gethostbyname(%s): %s", pcToHost, hstrerror(h_errno));
	    exit(EX_UNAVAILABLE);
	}
    }
    pPort->sin_port = sPort;
    pPort->sin_family = AF_INET;

    if (fDebug) {
	if ((struct hostent *)0 != hp && (char *)0 != hp->h_name)
	    Debug(1, "GetPort: hostname=%s (%s), ip=%s, port=%hu",
		  hp->h_name, pcToHost, inet_ntoa(pPort->sin_addr),
		  ntohs(sPort));
	else
	    Debug(1,
		  "GetPort: hostname=<unresolved> (%s), ip=%s, port=%hu",
		  pcToHost, inet_ntoa(pPort->sin_addr), ntohs(sPort));
    }

    /* set up the socket to talk to the server for all consoles
     * (it will tell us who to talk to to get a real connection)
     */
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	Error("socket(AF_INET,SOCK_STREAM): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    if (connect(s, (struct sockaddr *)pPort, sizeof(*pPort)) < 0) {
	Error("connect(): %hu@%s: %s", ntohs(pPort->sin_port), pcToHost,
	      strerror(errno));
	exit(EX_UNAVAILABLE);
    }

    return FileOpenFD(s, simpleSocket);
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
#if PROTOTYPES
C2Raw()
#else
C2Raw()
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
    if (0 != tcgetattr(0, &o_tios)) {
	Error("tcgetattr(0): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
# else
    if (0 != ioctl(0, TCGETS, &o_tios)) {
	Error("iotcl(0, TCGETS): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
# endif
    n_tios = o_tios;
    n_tios.c_iflag &= ~(INLCR | IGNCR | ICRNL | IUCLC | IXON);
    n_tios.c_oflag &= ~OPOST;
    n_tios.c_lflag &= ~(ICANON | ISIG | ECHO | IEXTEN);
    n_tios.c_cc[VMIN] = 1;
    n_tios.c_cc[VTIME] = 0;
# if HAVE_TCSETATTR
    if (0 != tcsetattr(0, TCSANOW, &n_tios)) {
	Error("tcsetattr(0, TCSANOW): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
# else
    if (0 != ioctl(0, TCSETS, &n_tios)) {
	Error("ioctl(0, TCSETS): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
# endif
#else
# if HAVE_TERMIO_H
    if (0 != ioctl(0, TCGETA, &o_tio)) {
	Error("iotcl(0, TCGETA): %s", strerror(errno));
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
	Error("iotcl(0, TCSETAF): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
# else
    if (0 != ioctl(0, TIOCGETP, (char *)&o_sty)) {
	Error("iotcl(0, TIOCGETP): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    n_sty = o_sty;

    n_sty.sg_flags |= CBREAK;
    n_sty.sg_flags &= ~(CRMOD | ECHO);
    n_sty.sg_kill = -1;
    n_sty.sg_erase = -1;
    if (0 != ioctl(0, TIOCSETP, (char *)&n_sty)) {
	Error("iotcl(0, TIOCSETP): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }

    /* stty undef all tty chars
     */
    if (-1 == ioctl(0, TIOCGETC, (char *)&n_tchars)) {
	Error("ioctl(0, TIOCGETC): %s", strerror(errno));
	return;
    }
    o_tchars = n_tchars;
    n_tchars.t_intrc = -1;
    n_tchars.t_quitc = -1;
    if (-1 == ioctl(0, TIOCSETC, (char *)&n_tchars)) {
	Error("ioctl(0, TIOCSETC): %s", strerror(errno));
	return;
    }
    if (-1 == ioctl(0, TIOCGLTC, (char *)&n_ltchars)) {
	Error("ioctl(0, TIOCGLTC): %s", strerror(errno));
	return;
    }
    o_ltchars = n_ltchars;
    n_ltchars.t_suspc = -1;
    n_ltchars.t_dsuspc = -1;
    n_ltchars.t_flushc = -1;
    n_ltchars.t_lnextc = -1;
    if (-1 == ioctl(0, TIOCSLTC, (char *)&n_ltchars)) {
	Error("ioctl(0, TIOCSLTC): %s", strerror(errno));
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
#if PROTOTYPES
C2Cooked()
#else
C2Cooked()
#endif
{
    if (!screwy)
	return;
#if HAVE_TERMIOS_H
# if HAVE_TCSETATTR
    tcsetattr(0, TCSANOW, &o_tios);
# else
    ioctl(0, TCSETS, (char *)&o_tios);
# endif
#else
# if HAVE_TERMIO_H
    ioctl(0, TCSETA, (char *)&o_tio);
# else
    ioctl(0, TIOCSETP, (char *)&o_sty);
    ioctl(0, TIOCSETC, (char *)&o_tchars);
    ioctl(0, TIOCSLTC, (char *)&o_ltchars);
# endif
#endif
    screwy = 0;
}



/* send out some data along the connection				(ksb)
 */
static void
#if PROTOTYPES
SendOut(CONSFILE * fd, char *pcBuf, int iLen)
#else
SendOut(fd, pcBuf, iLen)
    CONSFILE *fd;
    int iLen;
    char *pcBuf;
#endif
{
    int nr;

    if (fDebug) {
	static STRING *tmpString = (STRING *) 0;
	if (tmpString == (STRING *) 0)
	    tmpString = AllocString();
	BuildString((char *)0, tmpString);
	FmtCtlStr(pcBuf, iLen, tmpString);
	Debug(1, "SendOut: `%s'", tmpString->string);
    }
    while (0 != iLen) {
	if (-1 == (nr = FileWrite(fd, pcBuf, iLen))) {
	    C2Cooked();
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
#if PROTOTYPES
ReadReply(CONSFILE * fd, char *pcBuf, int iLen, char *pcWant)
#else
ReadReply(fd, pcBuf, iLen, pcWant)
    CONSFILE *fd;
    int iLen;
    char *pcBuf, *pcWant;
#endif
{
    int nr, j, iKeep;

    iKeep = iLen;
    for (j = 0; j < iLen; /* j+=nr */ ) {
	switch (nr = FileRead(fd, &pcBuf[j], iLen - 1)) {
	    case 0:
		if (iKeep != iLen) {
		    break;
		}
		/* fall through */
	    case -1:
		C2Cooked();
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
		    C2Cooked();
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
	static STRING *tmpString = (STRING *) 0;
	if (tmpString == (STRING *) 0)
	    tmpString = AllocString();
	BuildString((char *)0, tmpString);
	FmtCtlStr(pcWant, -1, tmpString);
	if (strcmp(pcBuf, pcWant))
	    Debug(1, "ReadReply: didn't match `%s'", tmpString->string);
	else
	    Debug(1, "ReadReply: matched `%s'", tmpString->string);
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
#if PROTOTYPES
Gather(int (*pfi) (), char *pcPorts, char *pcMaster, char *pcTo,
       char *pcCmd, char *pcWho)
#else
Gather(pfi, pcPorts, pcMaster, pcTo, pcCmd, pcWho)
    int (*pfi) ();
    char *pcPorts, *pcMaster, *pcTo, *pcCmd, *pcWho;
#endif
{
    CONSFILE *pcf;
    unsigned short j;
    char *pcNext, *pcServer;
    STRING *acExcg = (STRING *) 0;
    struct sockaddr_in client_port;
    int iRet = 0;

    if (acExcg == (STRING *) 0)
	acExcg = AllocString();

    for ( /* param */ ; '\000' != *pcPorts; pcPorts = pcNext) {
	if ((char *)0 == (pcNext = strchr(pcPorts, ':')))
	    pcNext = "";
	else
	    *pcNext++ = '\000';

	BuildString((char *)0, acExcg);
	BuildString(pcMaster, acExcg);
	if ((char *)0 != (pcServer = strchr(pcPorts, '@'))) {
	    *pcServer++ = '\000';
	    if ('\000' != *pcServer) {
		BuildString((char *)0, acExcg);
		BuildString(pcServer, acExcg);
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

	pcf = GetPort(acExcg->string, &client_port, j);

	if (0 != ReadReply(pcf, acMesg, sizeof(acMesg), "ok\r\n")) {
	    int s = strlen(acMesg);
	    if ((s > 0) && ('\n' == acMesg[s - 1]))
		acMesg[s - 1] = '\000';
	    Error("%s: %s", acExcg->string, acMesg);
	    exit(EX_UNAVAILABLE);
	}

	iRet += (*pfi) (pcf, acExcg->string, pcTo, pcCmd, pcWho);

	FileClose(&pcf);

	if ((char *)0 != pcServer) {
	    *pcServer = '@';
	}
    }
    DestroyString(acExcg);
    return iRet;
}


static int SawUrg = 0;

/* when the conserver program gets the suspend sequence it will send us
 * an out of band command to suspend ourself.  We just tell the reader
 * routine we saw one
 */
RETSIGTYPE
#if PROTOTYPES
OOB(int sig)
#else
OOB(sig)
    int sig;
#endif
{
    ++SawUrg;
#if !HAVE_SIGACTION
#if defined(SIGURG)
    SimpleSignal(SIGURG, OOB);
#endif
#endif
}

void
#if PROTOTYPES
ProcessUrgentData(int s)
#else
ProcessUrgentData(s)
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
		read(s, &acCmd, 1);
		write(1, ".", 1);
		continue;
	    case EINVAL:
	    default:
		Error("recv(%d): %s\r", s, strerror(errno));
		sleep(1);
		continue;
	}
    }
    switch (acCmd) {
	case OB_SUSP:
#if defined(SIGSTOP)
	    write(1, "stop]", 5);
	    C2Cooked();
	    kill(getpid(), SIGSTOP);
	    C2Raw();
	    write(1, "[press any character to continue", 32);
#else
	    write(1,
		  "stop not supported -- press any character to continue",
		  53);
#endif
	    break;
	case OB_DROP:
	    write(1, "dropped by server]\r\n", 20);
	    C2Cooked();
	    exit(EX_UNAVAILABLE);
	 /*NOTREACHED*/ default:
	    Error("unknown out of band command `%c\'\r", acCmd);
	    fflush(stderr);
	    break;
    }
}

/* interact with a group server					(ksb)
 */
static int
#if PROTOTYPES
CallUp(CONSFILE * pcf, char *pcMaster, char *pcMach, char *pcHow,
       char *pcUser)
#else
CallUp(pcf, pcMaster, pcMach, pcHow, pcUser)
    CONSFILE *pcf;
    char *pcMaster, *pcMach, *pcHow, *pcUser;
#endif
{
    int nc;
    int fIn = '-';
    fd_set rmask, rinit;
    int i;
    int justProcessedUrg = 0;

    if (fVerbose) {
	Msg("%s to %s (%son %s)", pcHow, pcMach, fRaw ? "raw " : "",
	    pcMaster);
    }
#if !defined(__CYGWIN__)
# if defined(F_SETOWN)
    if (-1 == fcntl(FileFDNum(pcf), F_SETOWN, getpid())) {
	Error("fcntl(F_SETOWN,%d): %d: %s", getpid(), FileFDNum(pcf),
	      strerror(errno));
    }
# else
#  if defined(SIOCSPGRP)
    {
	int iTemp;
	/* on the HP-UX systems if different
	 */
	iTemp = -getpid();
	if (-1 == ioctl(FileFDNum(pcf), SIOCSPGRP, &iTemp)) {
	    Error("ioctl(%d,SIOCSPGRP): %s", FileFDNum(pcf),
		  strerror(errno));
	}
    }
#  endif
# endif
#endif
#if defined(SIGURG)
    SimpleSignal(SIGURG, OOB);
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
	sprintf(acMesg, "%c%ce%c%c", DEFATTN, DEFESC, chAttn, chEsc);
	SendOut(pcf, acMesg, 5);
	if (0 == ReadReply(pcf, acMesg, sizeof(acMesg), (char *)0)) {
	    Error("protocol botch on redef of escape sequence");
	    exit(EX_UNAVAILABLE);
	}
    }
    if (fVerbose) {
	printf("Enter `");
	PutCtlc(chAttn, stdout);
	PutCtlc(chEsc, stdout);
	printf("?\' for help.\n");
    }


    /* if we are going for a particular console
     * send sign-on stuff, then wait for some indication of what mode
     * we got from the server (if we are the only people on we get write
     * access by default, which is fine for most people).
     */
    if (!fRaw) {
#if HAVE_OPENSSL
	sprintf(acMesg, "%c%c*", chAttn, chEsc);
	SendOut(pcf, acMesg, 3);
	if (0 == ReadReply(pcf, acMesg, sizeof(acMesg), "[ssl:\r\n")) {
	    AttemptSSL(pcf);
	}
	if (fReqEncryption && FileGetType(pcf) != SSLSocket) {
	    Error("Encryption not supported by server");
	    exit(EX_UNAVAILABLE);
	}
#endif
	/* begin connect with who we are
	 */
	sprintf(acMesg, "%c%c;", chAttn, chEsc);
	SendOut(pcf, acMesg, 3);
	if (0 != ReadReply(pcf, acMesg, sizeof(acMesg), "[login:\r\n") &&
	    0 != strcmp(acMesg, "\r\n[login:\r\n")) {
	    int s = strlen(acMesg);
	    if (0 != strcmp(acMesg, "[Encryption required\r\n")) {
		if ((s > 0) && ('\n' == acMesg[s - 1]))
		    acMesg[s - 1] = '\000';
		Error("call: %s", acMesg);
	    } else {
		Error("Encryption required by server for login");
	    }
	    exit(EX_UNAVAILABLE);
	}

	sprintf(acMesg, "%s\r\n", pcUser);
	SendOut(pcf, acMesg, strlen(acMesg));
	if (0 != ReadReply(pcf, acMesg, sizeof(acMesg), "host:\r\n")) {
	    int s = strlen(acMesg);
	    if ((s > 0) && ('\n' == acMesg[s - 1]))
		acMesg[s - 1] = '\000';
	    Error("%s", acMesg);
	    exit(EX_UNAVAILABLE);
	}

	/* which host we want, and a passwd if asked for one
	 */
	sprintf(acMesg, "%s\r\n", pcMach);
	SendOut(pcf, acMesg, strlen(acMesg));
	ReadReply(pcf, acMesg, sizeof(acMesg), (char *)0);
	if (0 == strcmp(acMesg, "passwd:")) {
	    static STRING *tmpString = (STRING *) 0;
	    if (tmpString == (STRING *) 0)
		tmpString = AllocString();
	    BuildString((char *)0, tmpString);
	    sprintf(acMesg, "Enter %s@%s's password:", pcUser, pcMaster);
#if defined(HAVE_GETPASSPHRASE)
	    BuildString(getpassphrase(acMesg), tmpString);
#else
	    BuildString(getpass(acMesg), tmpString);
#endif
	    BuildString("\r\n", tmpString);
	    SendOut(pcf, tmpString->string, strlen(tmpString->string));
	    ReadReply(pcf, acMesg, sizeof(acMesg), (char *)0);
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
		PutCtlc(chAttn, stdout);
		PutCtlc(chEsc, stdout);
		printf("o\' to open console line]\n");
	    }
	} else if (0 == strcmp(acMesg, "no -- on ctl]")) {
	    fIn = '-';
	    Error("%s is a control port", pcMach);
	    if (fVerbose) {
		printf("[use `");
		PutCtlc(chAttn, stdout);
		PutCtlc(chEsc, stdout);
		printf(";\' to open a console line]\n");
	    }
	} else {
	    Error("%s: %s", pcMach, acMesg);
	    exit(EX_UNAVAILABLE);
	}
    }

    printf("[Enter `");
    PutCtlc(chAttn, stdout);
    PutCtlc(chEsc, stdout);
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
	    sprintf(acMesg, "%c%c%c", chAttn, chEsc, *pcHow);
	    SendOut(pcf, acMesg, 3);
	}
	if (fReplay) {
	    sprintf(acMesg, "%c%cr", chAttn, chEsc);
	    SendOut(pcf, acMesg, 3);
	} else if (fVerbose) {
	    sprintf(acMesg, "%c%c\022", chAttn, chEsc);
	    SendOut(pcf, acMesg, 3);
	}
    }
    fflush(stdout);
    fflush(stderr);

    C2Raw();

    /* read from stdin and the socket (non-blocking!).
     * rmask indicates which descriptors to read from,
     * the others are not used, nor is the result from
     * select, read, or write.
     */
    FD_ZERO(&rinit);
    FD_SET(FileFDNum(pcf), &rinit);
    FD_SET(0, &rinit);
    for (;;) {
	justProcessedUrg = 0;
	if (SawUrg) {
	    ProcessUrgentData(FileFDNum(pcf));
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
		ProcessUrgentData(FileFDNum(pcf));
		justProcessedUrg = 1;
	    }
	}

	/* anything from socket? */
	if (FD_ISSET(FileFDNum(pcf), &rmask)) {
	    if ((nc = FileRead(pcf, acMesg, sizeof(acMesg))) == 0) {
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
	    SendOut(cfstdout, acMesg, nc);
	}

	/* anything from stdin? */
	if (FD_ISSET(0, &rmask)) {
	    if ((nc = read(0, acMesg, sizeof(acMesg))) == 0)
		break;
	    if (fStrip) {
		for (i = 0; i < nc; ++i)
		    acMesg[i] &= 127;
	    }
	    SendOut(pcf, acMesg, nc);
	}
    }
    C2Cooked();
    if (fVerbose)
	printf("Console %s closed.\n", pcMach);
    return 0;
}


/* the group leader tells is the server to connect to			(ksb)
 * we use CallUp to start a session with each target, or forward it
 */
static int
#if PROTOTYPES
Indir(CONSFILE * pcf, char *pcMaster, char *pcMach, char *pcCmd,
      char *pcWho)
#else
Indir(pcf, pcMaster, pcMach, pcCmd, pcWho)
    CONSFILE *pcf;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    sprintf(acPorts, "call:%s\r\n", pcMach);
    SendOut(pcf, acPorts, strlen(acPorts));

    /* get the ports number */
    if (0 >= ReadReply(pcf, acPorts, sizeof(acPorts), (char *)0)) {
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
#if PROTOTYPES
Cmd(CONSFILE * pcf, char *pcMaster, char *pcMach, char *pcCmd, char *pcWho)
#else
Cmd(pcf, pcMaster, pcMach, pcCmd, pcWho)
    CONSFILE *pcf;
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
	sprintf(acMesg, "%c%c%c%s:%s\r%c%c.", DEFATTN, DEFESC, *pcCmd,
		pcWho, pcMach, DEFATTN, DEFESC);
	SendOut(pcf, acMesg, strlen(acMesg));
    } else {
	sprintf(acMesg, "%c%c%c%c%c.", DEFATTN, DEFESC, *pcCmd, DEFATTN,
		DEFESC);
	SendOut(pcf, acMesg, 6);
    }

    /* read the server's reply,
     * We buffer until we close the connection because it
     * wouldn't be fair to ask the server to keep up with
     * itself :-)  {if we are inside a console connection}.
     */
    iRem = iMax;
    i = 0;
    while (0 < (nr = FileRead(pcf, pcBuf + i, iRem))) {
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
		putchar('\n');
		iRem = 0;
		continue;
	    case '[':
		fBrace = 1;
		continue;
	}
	putchar(pcBuf[nr]);
	iRem = 1;
    }
    /* SendOut(1, pcBuf, i); */
    fflush(stdout);

    return 0;
}

/* the masters tell us the group masters with a "groups" command	(ksb)
 */
static int
#if PROTOTYPES
CmdGroup(CONSFILE * pcf, char *pcMaster, char *pcMach, char *pcCmd,
	 char *pcWho)
#else
CmdGroup(pcf, pcMaster, pcMach, pcCmd, pcWho)
    CONSFILE *pcf;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    sprintf(acPorts, "groups\r\n");
    SendOut(pcf, acPorts, strlen(acPorts));

    /* get the ports number */
    if (0 >= ReadReply(pcf, acPorts, sizeof(acPorts), (char *)0)) {
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
#if PROTOTYPES
CmdMaster(CONSFILE * pcf, char *pcMaster, char *pcMach, char *pcCmd,
	  char *pcWho)
#else
CmdMaster(pcf, pcMaster, pcMach, pcCmd, pcWho)
    CONSFILE *pcf;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    SendOut(pcf, "master\r\n", 8);

    /* get the ports number */
    if (0 >= ReadReply(pcf, acPorts, sizeof(acPorts), (char *)0)) {
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
#if PROTOTYPES
Ctl(CONSFILE * pcf, char *pcMaster, char *pcMach, char *pcCmd, char *pcWho)
#else
Ctl(pcf, pcMaster, pcMach, pcCmd, pcWho)
    CONSFILE *pcf;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    sprintf(acPorts, "%s:%s\r\n", pcCmd, pcMach);
    SendOut(pcf, acPorts, strlen(acPorts));

    /* get the ports number */
    if (0 >= ReadReply(pcf, acPorts, sizeof(acPorts), (char *)0)) {
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
#if PROTOTYPES
CtlMaster(CONSFILE * pcf, char *pcMaster, char *pcMach, char *pcCmd,
	  char *pcWho)
#else
CtlMaster(pcf, pcMaster, pcMach, pcCmd, pcWho)
    CONSFILE *pcf;
    char *pcMaster, *pcMach, *pcCmd, *pcWho;
#endif
{
    char acPorts[4097];

    /* send request for master list
     */
    SendOut(pcf, "master\r\n", 8);

    /* get the ports number */
    if (0 >= ReadReply(pcf, acPorts, sizeof(acPorts), (char *)0)) {
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
#if PROTOTYPES
main(int argc, char **argv)
#else
main(argc, argv)
    int argc;
    char **argv;
#endif
{
    char *pcCmd, *pcTo;
    struct passwd *pwdMe = (struct passwd *)0;
    int opt;
    int fLocal;
    static STRING *acPorts = (STRING *) 0;
    char *pcUser = (char *)0;
    char *pcMsg = (char *)0;
    int (*pfiCall) ();
    static char acOpts[] = "7aAb:B:c:De:EfFGhiIl:M:p:PqQrRsSuvVwWx";
    extern int optind;
    extern int optopt;
    extern char *optarg;
    int i;
    STRING *tmpString = (STRING *) 0;

    isMultiProc = 0;		/* make sure stuff DOESN'T have the pid */

    if (tmpString == (STRING *) 0)
	tmpString = AllocString();
    if (acPorts == (STRING *) 0)
	acPorts = AllocString();

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

	    case 'B':		/* broadcast message */
		fReplay = 1;
		/* fall through */
	    case 'b':
		pcCmd = "broadcast";
		pcMsg = optarg;
		break;

	    case 'c':
#if HAVE_OPENSSL
		pcCredFile = optarg;
#endif
		break;

	    case 'D':
		fDebug++;
		break;

	    case 'E':
#if HAVE_OPENSSL
		fReqEncryption = 0;
#endif
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

	    case 'I':
		fLocal = 1;
		/* fall through */
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

	    case 'h':		/* huh? */
		Usage(1);
		exit(EX_OK);

	    case '\?':		/* huh? */
		Usage(0);
		exit(EX_UNAVAILABLE);

	    default:
		Error("option %c needs a parameter", optopt);
		exit(EX_UNAVAILABLE);
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
	    Error("getservbyname(%s): %s", pcPort, strerror(errno));
	    exit(EX_UNAVAILABLE);
	} else {
	    bindPort = ntohs((u_short) pSE->s_port);
	}
    }

    if (pcUser == (char *)0 || pcUser[0] == '\000') {
	if (((pcUser = getenv("LOGNAME")) == (char *)0) &&
	    ((pcUser = getenv("USER")) == (char *)0) &&
	    ((pwdMe = getpwuid(getuid())) == (struct passwd *)0)) {
	    Error
		("$LOGNAME and $USER do not exist and getpwuid fails: %d: %s",
		 (int)(getuid()), strerror(errno));
	    exit(EX_UNAVAILABLE);
	}
	if (pcUser == (char *)0) {
	    if (pwdMe->pw_name == (char *)0 || pwdMe->pw_name[0] == '\000') {
		Error("Username for uid %d does not exist",
		      (int)(getuid()));
		exit(EX_UNAVAILABLE);
	    } else {
		pcUser = pwdMe->pw_name;
	    }
	}
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

    cfstdout = FileOpenFD(1, simpleFile);

    BuildString((char *)0, acPorts);
    BuildStringChar('@', acPorts);
    BuildString(pcInMaster, acPorts);

#if HAVE_OPENSSL
    SetupSSL();			/* should only do if we want ssl - provide flag! */
#endif

    if ('q' == *pcCmd) {
	BuildString((char *)0, tmpString);
#if defined(HAVE_GETPASSPHRASE)
	BuildString(getpassphrase("Enter root password:"), tmpString);
#else
	BuildString(getpass("Enter root password:"), tmpString);
#endif
	pfiCall = fLocal ? Ctl : CtlMaster;
	if (tmpString->string == (char *)0)
	    pcTo = "";
	else
	    pcTo = tmpString->string;
    } else if ('v' == *pcCmd) {
	pfiCall = fLocal ? Ctl : CtlMaster;
    } else if ('p' == *pcCmd) {
	pfiCall = CtlMaster;
    } else if ('a' == *pcCmd || 'f' == *pcCmd || 's' == *pcCmd) {
	ValidateEsc();
	pfiCall = Indir;
    } else if ('g' == *pcCmd || 'i' == *pcCmd || 'b' == *pcCmd) {
	pfiCall = fLocal ? CmdGroup : CmdMaster;
    } else {
	pfiCall = CmdMaster;
    }
    exit(Gather
	 (pfiCall, acPorts->string, pcInMaster, pcTo, pcCmd, pcUser));
}
