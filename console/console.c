/*
 *  $Id: console.c,v 5.168 2004/09/21 23:45:53 bryan Exp $
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

#include <compat.h>

#include <pwd.h>

#include <getpassword.h>
#include <cutil.h>
#include <version.h>
#include <readconf.h>
#if HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#endif


int fReplay = 0, fVersion = 0;
int showExecData = 1;
int chAttn = -1, chEsc = -1;
unsigned short bindPort;
CONSFILE *cfstdout;
int disconnectCount = 0;
STRING *execCmd = (STRING *)0;
CONSFILE *execCmdFile = (CONSFILE *)0;
pid_t execCmdPid = 0;
CONSFILE *gotoConsole = (CONSFILE *)0;
CONSFILE *prevConsole = (CONSFILE *)0;
char *gotoName = (char *)0;
char *prevName = (char *)0;
CONFIG *optConf = (CONFIG *)0;
CONFIG *config = (CONFIG *)0;

#if HAVE_OPENSSL
SSL_CTX *ctx = (SSL_CTX *)0;

void
#if PROTOTYPES
SetupSSL(void)
#else
SetupSSL()
#endif
{
    if (ctx == (SSL_CTX *)0) {
	SSL_load_error_strings();
	if (!SSL_library_init()) {
	    Error("SSL library initialization failed");
	    Bye(EX_UNAVAILABLE);
	}
	if ((ctx = SSL_CTX_new(SSLv23_method())) == (SSL_CTX *)0) {
	    Error("Creating SSL context failed");
	    Bye(EX_UNAVAILABLE);
	}
	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
	    Error("Could not load SSL default CA file and/or directory");
	    Bye(EX_UNAVAILABLE);
	}
	if (config->sslcredentials != (char *)0) {
	    if (SSL_CTX_use_certificate_chain_file
		(ctx, config->sslcredentials) != 1) {
		Error("Could not load SSL certificate from '%s'",
		      config->sslcredentials);
		Bye(EX_UNAVAILABLE);
	    }
	    if (SSL_CTX_use_PrivateKey_file
		(ctx, config->sslcredentials, SSL_FILETYPE_PEM) != 1) {
		Error("Could not SSL private key from '%s'",
		      config->sslcredentials);
		Bye(EX_UNAVAILABLE);
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
	    Bye(EX_UNAVAILABLE);
	}
    }
}

void
#if PROTOTYPES
AttemptSSL(CONSFILE *pcf)
#else
AttemptSSL(pcf)
    CONSFILE *pcf;
#endif
{
    SSL *ssl;

    if (ctx == (SSL_CTX *)0) {
	Error("WTF?  The SSL context disappeared?!?!?");
	Bye(EX_UNAVAILABLE);
    }
    if (!(ssl = SSL_new(ctx))) {
	Error("Couldn't create new SSL context");
	Bye(EX_UNAVAILABLE);
    }
    FileSetSSL(pcf, ssl);
    SSL_set_fd(ssl, FileFDNum(pcf));
    CONDDEBUG((1, "About to SSL_connect() on fd %d", FileFDNum(pcf)));
    if (SSL_connect(ssl) <= 0) {
	Error("SSL negotiation failed");
	ERR_print_errors_fp(stderr);
	Bye(EX_UNAVAILABLE);
    }
    FileSetType(pcf, SSLSocket);
    CONDDEBUG((1, "SSL Connection: %s :: %s", SSL_get_cipher_version(ssl),
	       SSL_get_cipher_name(ssl)));
}
#endif

/* output a control (or plain) character as a UNIX user would expect it	(ksb)
 */
static void
#if PROTOTYPES
PutCtlc(int c, FILE *fp)
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
	"7         strip the high bit off all console data",
	"a(A)      attach politely (and replay last 20 lines)",
	"b(B)      send broadcast message to all users (on master)",
#if HAVE_OPENSSL
	"c cred    load an SSL certificate and key from the PEM encoded file",
#else
	"c cred    ignored - encryption not compiled into code",
#endif
	"C config  override per-user config file",
	"d         disconnect [user][@console]",
	"D         enable debug output, sent to stderr",
	"e esc     set the initial escape characters",
#if HAVE_OPENSSL
	"E         don't attempt encrypted connections",
#else
	"E         ignored - encryption not compiled into code",
#endif
	"f(F)      force read/write connection (and replay)",
	"h         output this message",
	"i(I)      display information in machine-parseable form (on master)",
	"l user    use username instead of current username",
	"M master  master server to poll first",
	"n         do not read system-wide config file",
	"p port    port to connect to",
	"P         display pids of daemon(s)",
	"q(Q)      send a quit command to the (master) server",
	"r(R)      display (master) daemon version (think 'r'emote version)",
	"s(S)      spy on a console (and replay)",
	"t         send a text message to [user][@console]",
	"u         show users on the various consoles",
#if HAVE_OPENSSL
	"U         allow unencrypted connections if SSL not available",
#else
	"U         ignored - encryption not compiled into code",
#endif
	"v         be more verbose",
	"V         show version information",
	"w(W)      show who is on which console (on master)",
	"x         examine ports and baud rates",
	(char *)0
    };

    fprintf(stderr,
	    "usage: %s [-aAfFsS] [-7DEnUv] [-c cred] [-C config] [-M master] [-p port] [-e esc] [-l username] console\n",
	    progname);
    fprintf(stderr,
	    "       %s [-hiIPrRuVwWx] [-7DEnUv] [-c cred] [-C config] [-M master] [-p port] [-d [user][@console]] [-[bB] message] [-t [user][@console] message]\n",
	    progname);
    fprintf(stderr,
	    "       %s [-qQ] [-7DEnUv] [-c cred] [-C config] [-M master] [-p port]\n",
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
    static STRING *acA1 = (STRING *)0;
    static STRING *acA2 = (STRING *)0;
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
#if USE_UNIX_DOMAIN_SOCKETS
	"uds",
#endif
	(char *)0
    };

    if (acA1 == (STRING *)0)
	acA1 = AllocString();
    if (acA2 == (STRING *)0)
	acA2 = AllocString();

    Msg("%s", THIS_VERSION);
#if USE_UNIX_DOMAIN_SOCKETS
    Msg("default socket directory `%s\'", UDSDIR);
#else
    Msg("default initial master server `%s\'", MASTERHOST);
    Msg("default port referenced as `%s'", DEFPORT);
#endif
    Msg("default escape sequence `%s%s\'", FmtCtl(DEFATTN, acA1),
	FmtCtl(DEFESC, acA2));
    Msg("default site-wide configuration in `%s'", CLIENTCONFIGFILE);
    Msg("default per-user configuration in `%s'", "$HOME/.consolerc");

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
#if defined(DMALLOC_VERSION_BETA)
    if (DMALLOC_VERSION_BETA != 0) {
	BuildString("-b", acA1);
	BuildStringChar('0' + DMALLOC_VERSION_BETA, acA1);
    }
#endif
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

    if (config->striphigh != FLAGTRUE)
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
	Bye(EX_UNAVAILABLE);
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
	Bye(EX_UNAVAILABLE);
    }
    if ('\000' != *pcTemp) {
	Error("too many characters in new escape sequence at ...`%s\'",
	      pcTemp);
	Bye(EX_UNAVAILABLE);
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
GetPort(char *pcToHost, unsigned short sPort)
#else
GetPort(pcToHost, sPort)
    char *pcToHost;
    unsigned short sPort;
#endif
{
    int s;
#if USE_UNIX_DOMAIN_SOCKETS
    struct sockaddr_un port;
    static STRING *portPath = (STRING *)0;
#else
    struct hostent *hp = (struct hostent *)0;
    struct sockaddr_in port;
#endif

#if HAVE_MEMSET
    memset((void *)(&port), '\000', sizeof(port));
#else
    bzero((char *)(&port), sizeof(port));
#endif

#if USE_UNIX_DOMAIN_SOCKETS
    if (portPath == (STRING *)0)
	portPath = AllocString();
    BuildStringPrint(portPath, "%s/%hu", config->master, sPort);
    port.sun_family = AF_UNIX;
    if (portPath->used > sizeof(port.sun_path)) {
	Error("GetPort: path to socket too long: %s", portPath->string);
	return (CONSFILE *)0;
    }
    strcpy(port.sun_path, portPath->string);

    CONDDEBUG((1, "GetPort: socket=%s", port.sun_path));

    /* set up the socket to talk to the server for all consoles
     * (it will tell us who to talk to to get a real connection)
     */
    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	Error("socket(AF_UNIX,SOCK_STREAM): %s", strerror(errno));
	return (CONSFILE *)0;
    }

    if (connect(s, (struct sockaddr *)(&port), sizeof(port)) < 0) {
	Error("connect(): %s: %s", port.sun_path, strerror(errno));
	return (CONSFILE *)0;
    }
#else
# if HAVE_INET_ATON
    if (inet_aton(pcToHost, &(port.sin_addr)) == 0)
# else
    port.sin_addr.s_addr = inet_addr(pcToHost);
    if ((in_addr_t) (-1) == port.sin_addr.s_addr)
# endif
    {
	if ((struct hostent *)0 != (hp = gethostbyname(pcToHost))) {
# if HAVE_MEMCPY
	    memcpy((char *)&port.sin_addr.s_addr, (char *)hp->h_addr,
		   hp->h_length);
# else
	    bcopy((char *)hp->h_addr, (char *)&port.sin_addr.s_addr,
		  hp->h_length);
# endif
	} else {
	    Error("gethostbyname(%s): %s", pcToHost, hstrerror(h_errno));
	    return (CONSFILE *)0;
	}
    }
    port.sin_port = sPort;
    port.sin_family = AF_INET;

    if (fDebug) {
	if ((struct hostent *)0 != hp && (char *)0 != hp->h_name) {
	    CONDDEBUG((1, "GetPort: hostname=%s (%s), ip=%s, port=%hu",
		       hp->h_name, pcToHost, inet_ntoa(port.sin_addr),
		       ntohs(sPort)));
	} else {
	    CONDDEBUG((1,
		       "GetPort: hostname=<unresolved> (%s), ip=%s, port=%hu",
		       pcToHost, inet_ntoa(port.sin_addr), ntohs(sPort)));
	}
    }

    /* set up the socket to talk to the server for all consoles
     * (it will tell us who to talk to to get a real connection)
     */
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	Error("socket(AF_INET,SOCK_STREAM): %s", strerror(errno));
	return (CONSFILE *)0;
    }

    if (connect(s, (struct sockaddr *)(&port), sizeof(port)) < 0) {
	Error("connect(): %hu@%s: %s", ntohs(port.sin_port), pcToHost,
	      strerror(errno));
	return (CONSFILE *)0;
    }
#endif

    return FileOpenFD(s, simpleSocket);
}


/* the next two routines assure that the users tty is in the
 * correct mode for us to do our thing
 */
static int screwy = 0;
static struct termios o_tios;


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
    struct termios n_tios;

    if (!isatty(0) || 0 != screwy)
	return;

    if (0 != tcgetattr(0, &o_tios)) {
	Error("tcgetattr(0): %s", strerror(errno));
	Bye(EX_UNAVAILABLE);
    }
    n_tios = o_tios;
    n_tios.c_iflag &= ~(INLCR | IGNCR | ICRNL | IUCLC | IXON);
    n_tios.c_oflag &= ~OPOST;
    n_tios.c_lflag &= ~(ICANON | ISIG | ECHO | IEXTEN);
    n_tios.c_cc[VMIN] = 1;
    n_tios.c_cc[VTIME] = 0;
    if (0 != tcsetattr(0, TCSANOW, &n_tios)) {
	Error("tcsetattr(0, TCSANOW): %s", strerror(errno));
	Bye(EX_UNAVAILABLE);
    }
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
    tcsetattr(0, TCSANOW, &o_tios);
    screwy = 0;
}

void
#if PROTOTYPES
DestroyDataStructures(void)
#else
DestroyDataStructures()
#endif
{
    C2Cooked();
    if (cfstdout != (CONSFILE *)0)
	FileUnopen(cfstdout);
    DestroyConfig(pConfig);
    DestroyConfig(optConf);
    DestroyConfig(config);
    DestroyTerminal(pTerm);
    if (myAddrs != (struct in_addr *)0)
	free(myAddrs);
    DestroyStrings();
    if (substData != (SUBST *) 0)
	free(substData);
}

char *
#if PROTOTYPES
ReadReply(CONSFILE *fd, int toEOF)
#else
ReadReply(fd)
    CONSFILE *fd;
    int toEOF;
#endif
{
    int nr;
    static char buf[1024];
    static STRING *result = (STRING *)0;

    if (result == (STRING *)0)
	result = AllocString();
    else
	BuildString((char *)0, result);

    while (1) {
	int l;
	switch (nr = FileRead(fd, buf, sizeof(buf))) {
	    case 0:
		/* fall through */
	    case -1:
		if (result->used > 1 || toEOF)
		    break;
		C2Cooked();
		Error("lost connection");
		Bye(EX_UNAVAILABLE);
	    default:
		while ((l = ParseIACBuf(fd, buf, &nr)) >= 0) {
		    if (l == 0)
			continue;
		    BuildStringN(buf, l, result);
		    nr -= l;
		    MemMove(buf, buf + l, nr);
		}
		BuildStringN(buf, nr, result);
		if (toEOF)	/* if toEOF, read until EOF */
		    continue;
		if ((result->used > 1) &&
		    strchr(result->string, '\n') != (char *)0)
		    break;
		continue;
	}
	break;
    }
    if (fDebug) {
	static STRING *tmpString = (STRING *)0;
	if (tmpString == (STRING *)0)
	    tmpString = AllocString();
	BuildString((char *)0, tmpString);
	FmtCtlStr(result->string, result->used - 1, tmpString);
	CONDDEBUG((1, "ReadReply: `%s'", tmpString->string));
    }
    return result->string;
}

static void
#if PROTOTYPES
ReapVirt(void)
#else
ReapVirt()
#endif
{
    pid_t pid;
    int UWbuf;

    while (-1 != (pid = waitpid(-1, &UWbuf, WNOHANG | WUNTRACED))) {
	if (0 == pid)
	    break;

	/* stopped child is just continued
	 */
	if (WIFSTOPPED(UWbuf) && 0 == kill(pid, SIGCONT)) {
	    Msg("child pid %lu: stopped, sending SIGCONT",
		(unsigned long)pid);
	    continue;
	}

	if (WIFEXITED(UWbuf))
	    Verbose("child process %lu: exit(%d)", pid,
		    WEXITSTATUS(UWbuf));
	if (WIFSIGNALED(UWbuf))
	    Verbose("child process %lu: signal(%d)", pid, WTERMSIG(UWbuf));
	if (pid == execCmdPid) {
	    if (WIFEXITED(UWbuf))
		FilePrint(cfstdout, FLAGFALSE,
			  "[local command terminated - pid %lu: exit(%d)]\r\n",
			  pid, WEXITSTATUS(UWbuf));
	    if (WIFSIGNALED(UWbuf))
		FilePrint(cfstdout, FLAGFALSE,
			  "[local command terminated - pid %lu: signal(%d)]\r\n",
			  pid, WTERMSIG(UWbuf));
	}
    }
}

static sig_atomic_t fSawReapVirt = 0;

#if HAVE_SIGACTION
static
#endif
  RETSIGTYPE
#if PROTOTYPES
FlagReapVirt(int sig)
#else
FlagReapVirt(sig)
    int sig;
#endif
{
    fSawReapVirt = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGCHLD, FlagReapVirt);
#endif
}

/* invoke the execcmd command */
void
#if PROTOTYPES
ExecCmd(void)
#else
ExecCmd()
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

    if (execCmd == (STRING *)0 || execCmd->used <= 1)
	return;

    CONDDEBUG((1, "ExecCmd(): `%s'", execCmd->string));

    /* pin[0] = parent read, pin[1] = child write */
    if (pipe(pin) != 0) {
	Error("ExecCmd(): pipe(): %s", strerror(errno));
	return;
    }
    /* pout[0] = child read, pout[l] = parent write */
    if (pipe(pout) != 0) {
	close(pin[0]);
	close(pin[1]);
	Error("ExecCmd(): pipe(): %s", strerror(errno));
	return;
    }

    fflush(stdout);
    fflush(stderr);

    switch (execCmdPid = fork()) {
	case -1:
	    return;
	case 0:
	    thepid = getpid();
	    break;
	default:
	    close(pout[0]);
	    close(pin[1]);
	    if ((execCmdFile =
		 FileOpenPipe(pin[0], pout[1])) == (CONSFILE *)0) {
		Error("ExecCmd(): FileOpenPipe(%d,%d) failed", pin[0],
		      pout[1]);
		close(pin[0]);
		close(pout[1]);
		kill(execCmdPid, SIGHUP);
		return;
	    }
	    FilePrint(cfstdout, FLAGFALSE,
		      "[local command running - pid %lu]\r\n", execCmdPid);
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
    SimpleSignal(SIGPIPE, SIG_DFL);
    SimpleSignal(SIGCHLD, SIG_DFL);

    /* setup new process with clean file descriptors
     * stderr still goes to stderr...so user sees it
     */
    i = GetMaxFiles();
    for ( /* i above */ ; --i > 3;) {
	if (i != pout[0] && i != pin[1])
	    close(i);
    }
    close(1);
    close(0);

# if HAVE_SETSID
    iNewGrp = setsid();
    if (-1 == iNewGrp) {
	Error("ExecCmd(): setsid(): %s", strerror(errno));
	iNewGrp = thepid;
    }
# else
    iNewGrp = thepid;
# endif

    if (dup(pout[0]) != 0 || dup(pin[1]) != 1) {
	Error("ExecCmd(): fd sync error");
	Bye(EX_OSERR);
    }
    close(pout[0]);
    close(pin[1]);

    tcsetpgrp(0, iNewGrp);

    apcArgv[2] = execCmd->string;

    execve(apcArgv[0], apcArgv, environ);
    Error("ExecCmd(): execve(%s): %s", apcArgv[2], strerror(errno));
    Bye(EX_OSERR);
    return;
}

void
#if PROTOTYPES
GetUserInput(STRING *str)
#else
GetUserInput(str)
    STRING *str;
#endif
{
    char c;

    if (str == (STRING *)0)
	return;

    BuildString((char *)0, str);

    for (;;) {
	if (read(0, &c, 1) == 0)
	    break;
	if (c == '\n' || c == '\r') {
	    break;
	}
	if (c >= ' ' && c <= '~') {
	    BuildStringChar(c, str);
	    FileWrite(cfstdout, FLAGFALSE, &c, 1);
	} else if ((c == '\b' || c == 0x7f) && str->used > 1) {
	    FileWrite(cfstdout, FLAGFALSE, "\b \b", 3);
	    str->string[str->used - 2] = '\000';
	    str->used--;
	} else if ((c == 0x15) && str->used > 1) {
	    while (str->used > 1) {
		FileWrite(cfstdout, FLAGFALSE, "\b \b", 3);
		str->string[str->used - 2] = '\000';
		str->used--;
	    }
	} else if ((c == 0x17) && str->used > 1) {
	    while (str->used > 1 &&
		   isspace((int)(str->string[str->used - 2]))) {
		FileWrite(cfstdout, FLAGFALSE, "\b \b", 3);
		str->string[str->used - 2] = '\000';
		str->used--;
	    }
	    while (str->used > 1 &&
		   !isspace((int)(str->string[str->used - 2]))) {
		FileWrite(cfstdout, FLAGFALSE, "\b \b", 3);
		str->string[str->used - 2] = '\000';
		str->used--;
	    }
	}
    }
}

void
#if PROTOTYPES
DoExec(CONSFILE *pcf)
#else
DoExec(pcf)
    CONSFILE *pcf;
#endif
{
    showExecData = 1;
    FileWrite(cfstdout, FLAGFALSE, "exec: ", 6);

    GetUserInput(execCmd);
    FileWrite(cfstdout, FLAGFALSE, "]\r\n", 3);

    if (execCmd != (STRING *)0 && execCmd->used > 1) {
	ExecCmd();
	BuildString((char *)0, execCmd);
	if (execCmdFile == (CONSFILE *)0) {	/* exec failed */
	    /* say forget it */
	    FileSetQuoteIAC(pcf, FLAGFALSE);
	    FilePrint(pcf, FLAGFALSE, "%c%c", OB_IAC, OB_ABRT);
	    FileSetQuoteIAC(pcf, FLAGTRUE);
	} else {
	    char *r;
	    /* go back to blocking mode */
	    SetFlags(FileFDNum(pcf), 0, O_NONBLOCK);
	    /* say we're ready */
	    FileSetQuoteIAC(pcf, FLAGFALSE);
	    FilePrint(pcf, FLAGFALSE, "%c%c", OB_IAC, OB_EXEC);
	    FileSetQuoteIAC(pcf, FLAGTRUE);
	    r = ReadReply(pcf, 0);
	    /* now back to non-blocking, now that we've got reply */
	    SetFlags(FileFDNum(pcf), O_NONBLOCK, 0);
	    /* if we aren't still r/w, abort */
	    if (strncmp(r, "[rw]", 4) != 0) {
		FileWrite(cfstdout, FLAGFALSE,
			  "[no longer read-write - aborting command]\r\n",
			  -1);
		FD_CLR(FileFDNum(execCmdFile), &rinit);
		FD_CLR(FileFDOutNum(execCmdFile), &winit);
		FileClose(&execCmdFile);
		FileSetQuoteIAC(pcf, FLAGFALSE);
		FilePrint(pcf, FLAGFALSE, "%c%c", OB_IAC, OB_ABRT);
		FileSetQuoteIAC(pcf, FLAGTRUE);
		kill(execCmdPid, SIGHUP);
	    }
	}
    } else {
	/* say forget it */
	FileSetQuoteIAC(pcf, FLAGFALSE);
	FilePrint(pcf, FLAGFALSE, "%c%c", OB_IAC, OB_ABRT);
	FileSetQuoteIAC(pcf, FLAGTRUE);
    }
}

void
#if PROTOTYPES
ExpandString(char *str, CONSFILE *c)
#else
ExpandString(str, c)
    char *str;
    CONSFILE *c;
#endif
{
    char s;
    short backslash = 0;
    short cntrl = 0;
    char oct = '\000';
    short octs = 0;
    static STRING *exp = (STRING *)0;

    if (str == (char *)0 || c == (CONSFILE *)0)
	return;

    if (exp == (STRING *)0)
	exp = AllocString();

    BuildString((char *)0, exp);

    backslash = 0;
    cntrl = 0;
    while ((s = (*str++)) != '\000') {
	if (octs > 0 && octs < 3 && s >= '0' && s <= '7') {
	    ++octs;
	    oct = oct * 8 + (s - '0');
	    continue;
	}
	if (octs != 0) {
	    BuildStringChar(oct, exp);
	    octs = 0;
	    oct = '\000';
	}
	if (backslash) {
	    backslash = 0;
	    if (s == 'a')
		s = '\a';
	    else if (s == 'b')
		s = '\b';
	    else if (s == 'f')
		s = '\f';
	    else if (s == 'n')
		s = '\n';
	    else if (s == 'r')
		s = '\r';
	    else if (s == 't')
		s = '\t';
	    else if (s == 'v')
		s = '\v';
	    else if (s == '^')
		s = '^';
	    else if (s >= '0' && s <= '7') {
		++octs;
		oct = oct * 8 + (s - '0');
		continue;
	    }
	    BuildStringChar(s, exp);
	    continue;
	}
	if (cntrl) {
	    cntrl = 0;
	    if (s == '?')
		s = 0x7f;	/* delete */
	    else
		s = s & 0x1f;
	    BuildStringChar(s, exp);
	    continue;
	}
	if (s == '\\') {
	    backslash = 1;
	    continue;
	}
	if (s == '^') {
	    cntrl = 1;
	    continue;
	}
	BuildStringChar(s, exp);
    }

    if (octs != 0)
	BuildStringChar(oct, exp);

    if (backslash)
	BuildStringChar('\\', exp);

    if (cntrl)
	BuildStringChar('^', exp);

    if (exp->used > 1)
	FileWrite(c, FLAGFALSE, exp->string, exp->used - 1);
}

void
#if PROTOTYPES
PrintSubst(CONSFILE *pcf, char *pcMach, char *string, char *subst)
#else
PrintSubst(pcf, pcMach, string, subst)
    CONSFILE *pcf;
    char *pcMach;
    char *string;
    char *subst;
#endif
{
    if (string == (char *)0)
	return;

    if (subst != (char *)0) {
	char *str;
	if ((str = StrDup(string)) == (char *)0)
	    OutOfMem();
	substData->data = (void *)config;
	config->console = pcMach;
	ProcessSubst(substData, &str, (char **)0, (char *)0, subst);
	ExpandString(str, pcf);
	free(str);
    } else
	ExpandString(string, pcf);
}

void
#if PROTOTYPES
Interact(CONSFILE *pcf, char *pcMach)
#else
Interact(pcf, pcMach)
    CONSFILE *pcf;
    char *pcMach;
#endif
{
    int i;
    int nc;
    fd_set rmask, wmask;
    int justSuspended = 0;
    static char acMesg[8192];

    /* if this is true, it means we successfully moved to a new console
     * so we need to close the old one.
     */
    if (prevConsole != (CONSFILE *)0) {
	FileClose(&prevConsole);
	PrintSubst(cfstdout, prevName, pTerm->detach, pTerm->detachsubst);
    }
    if (prevName != (char *)0) {
	free(prevName);
	prevName = (char *)0;
    }

    /* this is only true in other parts of the code iff pcf == gotoConsole */
    if (gotoConsole != (CONSFILE *)0) {
	gotoConsole = (CONSFILE *)0;
	FilePrint(cfstdout, FLAGFALSE, "[returning to `%s'", pcMach);
	FileWrite(pcf, FLAGFALSE, "\n", 1);
    }

    PrintSubst(cfstdout, pcMach, pTerm->attach, pTerm->attachsubst);

    C2Raw();

    /* set socket to non-blocking */
    SetFlags(FileFDNum(pcf), O_NONBLOCK, 0);

    /* read from stdin and the socket (non-blocking!).
     * rmask indicates which descriptors to read from,
     * the others are not used, nor is the result from
     * select, read, or write.
     */
    FD_ZERO(&rinit);
    FD_ZERO(&winit);
    FD_SET(FileFDNum(pcf), &rinit);
    FD_SET(0, &rinit);
    if (maxfd < FileFDNum(pcf) + 1)
	maxfd = FileFDNum(pcf) + 1;
    for (;;) {
	justSuspended = 0;
	if (fSawReapVirt) {
	    fSawReapVirt = 0;
	    ReapVirt();
	}
	/* reset read mask and select on it
	 */
	rmask = rinit;
	wmask = winit;
	if (-1 ==
	    select(maxfd, &rmask, &wmask, (fd_set *)0,
		   (struct timeval *)0)) {
	    if (errno != EINTR) {
		Error("Master(): select(): %s", strerror(errno));
		break;
	    }
	    continue;
	}

	/* anything from execCmd */
	if (execCmdFile != (CONSFILE *)0) {
	    if (FileCanRead(execCmdFile, &rmask, &wmask)) {
		if ((nc =
		     FileRead(execCmdFile, acMesg, sizeof(acMesg))) < 0) {
		    FD_CLR(FileFDNum(execCmdFile), &rinit);
		    FD_CLR(FileFDOutNum(execCmdFile), &winit);
		    FileClose(&execCmdFile);
		    FileSetQuoteIAC(pcf, FLAGFALSE);
		    FilePrint(pcf, FLAGFALSE, "%c%c", OB_IAC, OB_ABRT);
		    FileSetQuoteIAC(pcf, FLAGTRUE);
		} else {
		    if (config->striphigh == FLAGTRUE) {
			for (i = 0; i < nc; ++i)
			    acMesg[i] &= 127;
		    }
		    FileWrite(pcf, FLAGFALSE, acMesg, nc);
		}
	    } else if (!FileBufEmpty(execCmdFile) &&
		       FileCanWrite(execCmdFile, &rmask, &wmask)) {
		CONDDEBUG((1, "Interact(): flushing fd %d",
			   FileFDNum(execCmdFile)));
		if (FileWrite(execCmdFile, FLAGFALSE, (char *)0, 0) < 0) {
		    /* -bryan */
		    break;
		}
	    }
	}

	/* anything from socket? */
	if (FileCanRead(pcf, &rmask, &wmask)) {
	    int l;
	    if ((nc = FileRead(pcf, acMesg, sizeof(acMesg))) < 0) {
		/* if we got an error/eof after returning from suspend */
		if (justSuspended) {
		    fprintf(stderr, "\n");
		    Error("lost connection");
		}
		break;
	    }
	    while ((l = ParseIACBuf(pcf, acMesg, &nc)) >= 0) {
		if (l == 0) {
		    if (execCmdFile == (CONSFILE *)0) {
			if (FileSawQuoteExec(pcf) == FLAGTRUE)
			    DoExec(pcf);
			else if (FileSawQuoteSusp(pcf) == FLAGTRUE) {
			    justSuspended = 1;
#if defined(SIGSTOP)
			    FileWrite(cfstdout, FLAGFALSE, "stop]", 5);
			    C2Cooked();
			    kill(thepid, SIGSTOP);
			    C2Raw();
			    FileWrite(cfstdout, FLAGFALSE,
				      "[press any character to continue",
				      32);
#else
			    FileWrite(cfstdout, FLAGFALSE,
				      "stop not supported -- press any character to continue",
				      53);
#endif
			} else if (FileSawQuoteGoto(pcf) == FLAGTRUE) {
			    gotoConsole = pcf;
			    if (gotoName != (char *)0)
				free(gotoName);
			    if ((gotoName = StrDup(pcMach)) == (char *)0)
				OutOfMem();
			    C2Cooked();
			    return;
			}
		    } else {
			if (FileSawQuoteAbrt(pcf) == FLAGTRUE) {
			    FD_CLR(FileFDNum(execCmdFile), &rinit);
			    FD_CLR(FileFDOutNum(execCmdFile), &winit);
			    FileClose(&execCmdFile);
			    kill(execCmdPid, SIGHUP);
			}
		    }
		    continue;
		}
		if (config->striphigh == FLAGTRUE) {
		    for (i = 0; i < l; ++i)
			acMesg[i] &= 127;
		}
		if (execCmdFile != (CONSFILE *)0) {
		    FileWrite(execCmdFile, FLAGFALSE, acMesg, l);
		    if (showExecData)
			FileWrite(cfstdout, FLAGFALSE, acMesg, l);
		} else
		    FileWrite(cfstdout, FLAGFALSE, acMesg, l);
		nc -= l;
		MemMove(acMesg, acMesg + l, nc);
	    }
	} else if (!FileBufEmpty(pcf) && FileCanWrite(pcf, &rmask, &wmask)) {
	    CONDDEBUG((1, "Interact(): flushing fd %d", FileFDNum(pcf)));
	    if (FileWrite(pcf, FLAGFALSE, (char *)0, 0) < 0) {
		/* -bryan */
		break;
	    }
	}

	/* anything from stdin? */
	if (FD_ISSET(0, &rmask)) {
	    if ((nc = read(0, acMesg, sizeof(acMesg))) == 0) {
		if (screwy)
		    break;
		else {
		    FD_SET(0, &rinit);
		    continue;
		}
	    }
	    if (execCmdFile == (CONSFILE *)0) {
		if (config->striphigh == FLAGTRUE) {
		    for (i = 0; i < nc; ++i)
			acMesg[i] &= 127;
		}
		FileWrite(pcf, FLAGFALSE, acMesg, nc);
	    } else {
		for (i = 0; i < nc; ++i) {
		    if (acMesg[i] == '\n' || acMesg[i] == '\r')
			FilePrint(cfstdout, FLAGFALSE,
				  "[local command running - pid %lu]\r\n",
				  execCmdPid);
		    else if (acMesg[i] == 0x03) {	/* ctrl-c */
			kill(execCmdPid, SIGHUP);
			FilePrint(cfstdout, FLAGFALSE,
				  "[local command sent SIGHUP - pid %lu]\r\n",
				  execCmdPid);
		    } else if (acMesg[i] == 0x1c) {	/* ctrl-\ */
			kill(execCmdPid, SIGKILL);
			FilePrint(cfstdout, FLAGFALSE,
				  "[local command sent SIGKILL - pid %lu]\r\n",
				  execCmdPid);
		    } else if (acMesg[i] == 'o' || acMesg[i] == 'O') {
			showExecData = !showExecData;
			FilePrint(cfstdout, FLAGFALSE,
				  "[local command data %s]\r\n",
				  showExecData ? "on" : "off");
		    }
		}
	    }
	}
    }

    C2Cooked();

    PrintSubst(cfstdout, pcMach, pTerm->detach, pTerm->detachsubst);

    if (fVerbose)
	printf("Console %s closed.\n", pcMach);
}

/* interact with a group server					(ksb)
 */
void
#if PROTOTYPES
CallUp(CONSFILE *pcf, char *pcMaster, char *pcMach, char *pcHow,
       char *result)
#else
CallUp(pcf, pcMaster, pcMach, pcHow, result)
    CONSFILE *pcf;
    char *pcMaster, *pcMach, *pcHow, *result;
#endif
{
    int fIn = '-';
    char *r = (char *)0;

    if (fVerbose) {
	Msg("%s to %s (on %s)", pcHow, pcMach, pcMaster);
    }
#if !defined(__CYGWIN__)
# if defined(F_SETOWN)
    if (fcntl(FileFDNum(pcf), F_SETOWN, thepid) == -1) {
	Error("fcntl(F_SETOWN,%lu): %d: %s", (unsigned long)thepid,
	      FileFDNum(pcf), strerror(errno));
    }
# else
#  if defined(SIOCSPGRP)
    {
	int iTemp;
	/* on the HP-UX systems if different
	 */
	iTemp = -thepid;
	if (ioctl(FileFDNum(pcf), SIOCSPGRP, &iTemp) == -1) {
	    Error("ioctl(%d,SIOCSPGRP): %s", FileFDNum(pcf),
		  strerror(errno));
	}
    }
#  endif
# endif
#endif
    SimpleSignal(SIGCHLD, FlagReapVirt);

    /* if we are going for a particular console
     * send sign-on stuff, then wait for some indication of what mode
     * we got from the server (if we are the only people on we get write
     * access by default, which is fine for most people).
     */

    /* how did we do, did we get a read-only or read-write?
     */
    if (0 == strcmp(result, "[attached]\r\n")) {
	/* OK -- we are good as gold */
	fIn = 'a';
    } else if (0 == strcmp(result, "[spy]\r\n") ||
	       0 == strcmp(result, "[ok]\r\n") ||
	       0 == strcmp(result, "[read-only -- initializing]\r\n")) {
	/* Humph, someone else is on
	 * or we have an old version of the server (4.X)
	 */
	fIn = 's';
    } else if (0 == strcmp(result, "[console is read-only]\r\n")) {
	fIn = 'r';
    } else if (0 == strcmp(result, "[line to console is down]\r\n")) {
	/* ouch, the machine is down on the server */
	fIn = '-';
	Error("%s is down", pcMach);
	if (fVerbose) {
	    printf("[use `");
	    PutCtlc(chAttn, stdout);
	    PutCtlc(chEsc, stdout);
	    printf("o\' to open console line]\n");
	}
    } else {
	FilePrint(cfstdout, FLAGFALSE, "%s: %s", pcMach, result);
	Bye(EX_UNAVAILABLE);
    }

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
	FilePrint(pcf, FLAGFALSE, "%c%ce%c%c", DEFATTN, DEFESC, chAttn,
		  chEsc);
	r = ReadReply(pcf, 0);
	if (strncmp(r, "[redef:", 7) != 0) {
	    Error("protocol botch on redef of escape sequence");
	    Bye(EX_UNAVAILABLE);
	}
    }

    printf("[Enter `");
    PutCtlc(chAttn, stdout);
    PutCtlc(chEsc, stdout);
    printf("?\' for help]\n");

    /* try and display the MOTD */
    FilePrint(pcf, FLAGFALSE, "%c%cm", chAttn, chEsc);
    r = ReadReply(pcf, 0);
    if (strncmp(r, "[unknown", 8) != 0 &&
	strncmp(r, "[-- MOTD --]", 12) != 0)
	FileWrite(cfstdout, FLAGFALSE, r, -1);

    FilePrint(pcf, FLAGFALSE, "%c%c;", chAttn, chEsc);
    r = ReadReply(pcf, 0);
    if (strncmp(r, "[unknown", 8) != 0 &&
	strncmp(r, "[connected]", 11) != 0)
	FileWrite(cfstdout, FLAGFALSE, r, -1);

    /* if the host is not down, finish the connection, and force
     * the correct attachment for the user
     */
    if (fIn != '-') {
	if (fIn == 'r') {
	    if (*pcHow != 's') {
		Error("%s is read-only", pcMach);
	    }
	} else if (fIn != (*pcHow == 'f' ? 'a' : *pcHow)) {
	    FilePrint(pcf, FLAGFALSE, "%c%c%c", chAttn, chEsc, *pcHow);
	}
	if (fReplay) {
	    FilePrint(pcf, FLAGFALSE, "%c%cr", chAttn, chEsc);
	} else if (fVerbose) {
	    FilePrint(pcf, FLAGFALSE, "%c%c\022", chAttn, chEsc);
	}
    }
    fflush(stdout);
    fflush(stderr);

    Interact(pcf, pcMach);
}

/* shouldn't need more than 3 levels of commands (but alloc 4 just 'cause)
 * worst case so far: master, groups, broadcast
 *   (cmdarg == broadcast msg)
 */
char *cmds[4] = { (char *)0, (char *)0, (char *)0, (char *)0 };
char *cmdarg = (char *)0;

/* call a machine master for group master ports and machine master ports
 * take a list like "1782@localhost:@mentor.cc.purdue.edu:@pop.stat.purdue.edu"
 * and send the given command to the group leader at 1782
 * and ask the machine master at mentor for more group leaders
 * and ask the machine master at pop.stat for more group leaders
 */
int
#if PROTOTYPES
DoCmds(char *master, char *pports, int cmdi)
#else
DoCmds(master, pports, cmdi)
    char *master;
    char *pports;
    int cmdi;
#endif
{
    CONSFILE *pcf;
    char *t;
    char *next;
    char *server;
    unsigned short port;
    char *result = (char *)0;
    int len;
    char *ports;
    char *pcopy;
    char *serverName;

    if ((pcopy = ports = StrDup(pports)) == (char *)0)
	OutOfMem();

    len = strlen(ports);
    while (len > 0 && (ports[len - 1] == '\r' || ports[len - 1] == '\n'))
	len--;
    ports[len] = '\000';

    for ( /* param */ ; *ports != '\000'; ports = next) {
	if ((next = strchr(ports, ':')) == (char *)0)
	    next = "";
	else
	    *next++ = '\000';

	if ((server = strchr(ports, '@')) != (char *)0) {
	    *server++ = '\000';
	    if (*server == '\000')
		server = master;
	} else
	    server = master;

#if USE_UNIX_DOMAIN_SOCKETS
	serverName = "localhost";
#else
	serverName = server;
#endif

	if (*ports == '\000') {
#if USE_UNIX_DOMAIN_SOCKETS
	    port = 0;
#else
	    port = htons(bindPort);
#endif
	} else if (!isdigit((int)(ports[0]))) {
	    Error("invalid port spec for %s: `%s'", serverName, ports);
	    continue;
	} else {
#if USE_UNIX_DOMAIN_SOCKETS
	    port = (short)atoi(ports);
#else
	    port = htons((short)atoi(ports));
#endif
	}

      attemptLogin:
	if ((pcf = GetPort(server, port)) == (CONSFILE *)0)
	    continue;

	FileSetQuoteIAC(pcf, FLAGTRUE);

	t = ReadReply(pcf, 0);
	if (strcmp(t, "ok\r\n") != 0) {
	    FileClose(&pcf);
	    FilePrint(cfstdout, FLAGFALSE, "%s: %s", serverName, t);
	    continue;
	}
#if HAVE_OPENSSL
	if (config->sslenabled == FLAGTRUE) {
	    FileWrite(pcf, FLAGFALSE, "ssl\r\n", 5);
	    t = ReadReply(pcf, 0);
	    if (strcmp(t, "ok\r\n") == 0) {
		AttemptSSL(pcf);
		if (FileGetType(pcf) != SSLSocket) {
		    Error("Encryption not supported by server `%s'",
			  serverName);
		    FileClose(&pcf);
		    continue;
		}
	    } else if (config->sslrequired == FLAGTRUE) {
		Error("Encryption not supported by server `%s'",
		      serverName);
		FileClose(&pcf);
		continue;
	    }
	}
#endif

	FilePrint(pcf, FLAGFALSE, "login %s\r\n", config->username);

	t = ReadReply(pcf, 0);
	if (strncmp(t, "passwd?", 7) == 0) {
	    static int count = 0;
	    static STRING *tmpString = (STRING *)0;
	    char *hostname = (char *)0;

	    if (t[7] == ' ') {
		hostname = PruneSpace(t + 7);
		if (*hostname == '\000')
		    hostname = serverName;
	    } else
		hostname = serverName;
	    if (tmpString == (STRING *)0)
		tmpString = AllocString();
	    if (tmpString->used <= 1) {
		char *pass;
		BuildStringPrint(tmpString, "Enter %s@%s's password: ",
				 config->username, hostname);
		pass = GetPassword(tmpString->string);
		if (pass == (char *)0) {
		    Error("could not get password from tty for `%s'",
			  serverName);
		    FileClose(&pcf);
		    continue;
		}
		BuildString((char *)0, tmpString);
		BuildString(pass, tmpString);
		BuildString("\r\n", tmpString);
	    }
	    FileWrite(pcf, FLAGFALSE, tmpString->string,
		      tmpString->used - 1);
	    t = ReadReply(pcf, 0);
	    if (strcmp(t, "ok\r\n") != 0) {
		FilePrint(cfstdout, FLAGFALSE, "%s: %s", serverName, t);
		if (++count < 3) {
		    BuildString((char *)0, tmpString);
		    goto attemptLogin;
		}
		Error("too many bad passwords for `%s'", serverName);
		count = 0;
		FileClose(&pcf);
		continue;
	    } else
		count = 0;
	} else if (strcmp(t, "ok\r\n") != 0) {
	    FileClose(&pcf);
	    FilePrint(cfstdout, FLAGFALSE, "%s: %s", serverName, t);
	    continue;
	}

	/* now that we're logged in, we can do something */
	/* if we're on the last cmd or the command is 'call' and we
	 * have an arg (always true if it's 'call'), then send the arg
	 */
	if ((cmdi == 0 || cmds[cmdi][0] == 'c') && cmdarg != (char *)0)
	    FilePrint(pcf, FLAGFALSE, "%s %s\r\n", cmds[cmdi], cmdarg);
	else
	    FilePrint(pcf, FLAGFALSE, "%s\r\n", cmds[cmdi]);

	/* if we haven't gone down the stack, do "normal" stuff.
	 * if we did hit the bottom, we send the exit\r\n now so
	 * that the ReadReply can stop once the socket closes.
	 */
	if (cmdi != 0) {
	    t = ReadReply(pcf, 0);
	    /* save the result */
	    if (result != (char *)0)
		free(result);
	    if ((result = StrDup(t)) == (char *)0)
		OutOfMem();
	}

	/* if we're working on finding a console */
	if (cmds[cmdi][0] == 'c') {
	    static int limit = 0;
	    /* did we get a redirect? */
	    if (result[0] == '@' || (result[0] >= '0' && result[0] <= '9')) {
		if (limit++ > 10) {
		    Error("forwarding level too deep!");
		    Bye(EX_SOFTWARE);
		}
	    } else if (result[0] != '[') {	/* did we not get a connection? */
		limit = 0;
		FilePrint(cfstdout, FLAGFALSE, "%s: %s", serverName,
			  result);
		FileClose(&pcf);
		continue;
	    } else {
		limit = 0;
		CallUp(pcf, server, cmdarg, cmds[0], result);
		if (pcf != gotoConsole)
		    FileClose(&pcf);
		break;
	    }
	} else if (cmds[cmdi][0] == 'q') {
	    t = ReadReply(pcf, 0);
	    FileWrite(cfstdout, FLAGFALSE, t, -1);
	    if (t[0] != 'o' || t[1] != 'k') {
		FileWrite(pcf, FLAGFALSE, "exit\r\n", 6);
		t = ReadReply(pcf, 1);
	    }
	} else {
	    /* all done */
	    FileWrite(pcf, FLAGFALSE, "exit\r\n", 6);
	    t = ReadReply(pcf, cmdi == 0 ? 1 : 0);

	    if (cmdi == 0) {
		int len;
		/* if we hit bottom, this is where we get our results */
		if (result != (char *)0)
		    free(result);
		if ((result = StrDup(t)) == (char *)0)
		    OutOfMem();
		len = strlen(result);
		if (len > 8 &&
		    strcmp("goodbye\r\n", result + len - 9) == 0) {
		    len -= 9;
		    *(result + len) = '\000';
		}
		/* if (not 'broadcast' and not 'textmsg') or 
		 *   result doesn't start with 'ok' (only checks this if
		 *      it's a 'broadcast' or 'textmsg')
		 */
		if (cmds[0][0] == 'd') {
		    if (result[0] != 'o' || result[1] != 'k') {
			FileWrite(cfstdout, FLAGTRUE, serverName, -1);
			FileWrite(cfstdout, FLAGTRUE, ": ", 2);
			FileWrite(cfstdout, FLAGFALSE, result, len);
		    } else {
			disconnectCount += atoi(result + 19);
		    }
		} else if ((cmds[0][0] != 'b' && cmds[0][0] != 't') ||
			   (result[0] != 'o' || result[1] != 'k')) {
		    /* did a 'master' before this or doing a 'disconnect' */
		    if ((cmds[1] != (char *)0 && cmds[1][0] == 'm') ||
			cmds[0][0] == 'd') {
			FileWrite(cfstdout, FLAGTRUE, serverName, -1);
			FileWrite(cfstdout, FLAGTRUE, ": ", 2);
		    }
		    FileWrite(cfstdout, FLAGFALSE, result, len);
		}
	    }
	}

	FileClose(&pcf);

	/* this would only be true if we got extra redirects (@... above) */
	if (cmds[cmdi][0] == 'c')
	    DoCmds(server, result, cmdi);
	else if (cmdi > 0)
	    DoCmds(server, result, cmdi - 1);
	if (result != (char *)0)
	    free(result);
	result = (char *)0;
    }

    if (result != (char *)0)
	free(result);
    free(pcopy);
    return 0;
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
    char *pcCmd;
    struct passwd *pwdMe = (struct passwd *)0;
    int opt;
    int fLocal;
    static STRING *acPorts = (STRING *)0;
    static char acOpts[] = "7aAb:B:c:C:d:De:EfFhiIl:M:np:PqQrRsSt:uUvVwWx";
    extern int optind;
    extern int optopt;
    extern char *optarg;
    static STRING *textMsg = (STRING *)0;
    int cmdi;
    static STRING *consoleName = (STRING *)0;
    short readSystemConf = 1;
    char *userConf = (char *)0;

    isMultiProc = 0;		/* make sure stuff DOESN'T have the pid */

    thepid = getpid();

    if (textMsg == (STRING *)0)
	textMsg = AllocString();
    if (acPorts == (STRING *)0)
	acPorts = AllocString();

    if ((char *)0 == (progname = strrchr(argv[0], '/'))) {
	progname = argv[0];
    } else {
	++progname;
    }

    /* prep the config options */
    if ((optConf = (CONFIG *)calloc(1, sizeof(CONFIG))) == (CONFIG *)0)
	OutOfMem();
    if ((config = (CONFIG *)calloc(1, sizeof(CONFIG))) == (CONFIG *)0)
	OutOfMem();
    if ((pConfig = (CONFIG *)calloc(1, sizeof(CONFIG))) == (CONFIG *)0)
	OutOfMem();
    /* and the terminal options */
    if ((pTerm = (TERM *)calloc(1, sizeof(TERM))) == (TERM *)0)
	OutOfMem();

    /* command line parsing
     */
    pcCmd = (char *)0;
    fLocal = 0;
    while ((opt = getopt(argc, argv, acOpts)) != EOF) {
	switch (opt) {
	    case '7':		/* strip high-bit */
		optConf->striphigh = FLAGTRUE;
		break;

	    case 'A':		/* attach with log replay */
		fReplay = 1;
		/* fall through */
	    case 'a':		/* attach */
		pcCmd = "attach";
		break;

	    case 'B':		/* broadcast message */
		fLocal = 1;
		/* fall through */
	    case 'b':
		pcCmd = "broadcast";
		if (cmdarg != (char *)0)
		    free(cmdarg);
		if ((cmdarg = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;

	    case 'C':
		userConf = optarg;
		break;

	    case 'c':
#if HAVE_OPENSSL
		if ((optConf->sslcredentials =
		     StrDup(optarg)) == (char *)0)
		    OutOfMem();
#endif
		break;

	    case 'D':
		fDebug++;
		break;

	    case 'd':
		pcCmd = "disconnect";
		if (cmdarg != (char *)0)
		    free(cmdarg);
		if ((cmdarg = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;

	    case 'E':
#if HAVE_OPENSSL
		optConf->sslenabled = FLAGFALSE;
#endif
		break;

	    case 'e':		/* set escape chars */
		if ((optConf->escape = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;

	    case 'F':		/* force attach with log replay */
		fReplay = 1;
		/* fall through */
	    case 'f':		/* force attach */
		pcCmd = "force";
		break;

	    case 'I':
		fLocal = 1;
		/* fall through */
	    case 'i':
		pcCmd = "info";
		break;

	    case 'l':
		if ((optConf->username = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;

	    case 'M':
		if ((optConf->master = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;

	    case 'n':
		readSystemConf = 0;
		break;

	    case 'p':
		if ((optConf->port = StrDup(optarg)) == (char *)0)
		    OutOfMem();
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

	    case 't':
		BuildString((char *)0, textMsg);
		if (optarg == (char *)0 || *optarg == '\000') {
		    Error("no destination specified for -t", optarg);
		    Bye(EX_UNAVAILABLE);
		} else if (strchr(optarg, ' ') != (char *)0) {
		    Error("-t option cannot contain a space: `%s'",
			  optarg);
		    Bye(EX_UNAVAILABLE);
		}
		BuildString("textmsg ", textMsg);
		BuildString(optarg, textMsg);
		pcCmd = textMsg->string;
		break;

	    case 'U':
#if HAVE_OPENSSL
		optConf->sslrequired = FLAGFALSE;
#endif
		break;

	    case 'u':
		pcCmd = "hosts";
		break;

	    case 'W':
		fLocal = 1;
		/*fallthrough */
	    case 'w':		/* who */
		pcCmd = "group";
		break;

	    case 'x':
		pcCmd = "examine";
		break;

	    case 'v':
		fVerbose = 1;
		break;

	    case 'V':
		fVersion = 1;
		break;

	    case 'h':		/* huh? */
		Usage(1);
		Bye(EX_OK);

	    case '\?':		/* huh? */
		Usage(0);
		Bye(EX_UNAVAILABLE);

	    default:
		Error("option %c needs a parameter", optopt);
		Bye(EX_UNAVAILABLE);
	}
    }

    if (fVersion) {
	Version();
	Bye(EX_OK);
    }

    ProbeInterfaces(INADDR_ANY);

    if (readSystemConf)
	ReadConf(CLIENTCONFIGFILE, FLAGFALSE);

    if (userConf == (char *)0) {
	/* read the config files */
	char *h = (char *)0;

	if (((h = getenv("HOME")) == (char *)0) &&
	    ((pwdMe = getpwuid(getuid())) == (struct passwd *)0)) {
	    Error("$HOME does not exist and getpwuid fails: %d: %s",
		  (int)(getuid()), strerror(errno));
	} else {
	    if (h == (char *)0) {
		if (pwdMe->pw_dir == (char *)0 ||
		    pwdMe->pw_dir[0] == '\000') {
		    Error("Home directory for uid %d is not defined",
			  (int)(getuid()));
		    Bye(EX_UNAVAILABLE);
		} else {
		    h = pwdMe->pw_dir;
		}
	    }
	}
	if (h != (char *)0) {
	    BuildTmpString((char *)0);
	    BuildTmpString(h);
	    h = BuildTmpString("/.consolerc");
	    ReadConf(h, FLAGFALSE);
	    BuildTmpString((char *)0);
	}
    } else
	ReadConf(userConf, FLAGTRUE);

    if (optConf->striphigh != FLAGUNKNOWN)
	config->striphigh = optConf->striphigh;
    else if (pConfig->striphigh != FLAGUNKNOWN)
	config->striphigh = pConfig->striphigh;
    else
	config->striphigh = FLAGFALSE;

    if (optConf->escape != (char *)0)
	ParseEsc(optConf->escape);
    else if (pConfig->escape != (char *)0)
	ParseEsc(pConfig->escape);

    if (optConf->username != (char *)0)
	config->username = StrDup(optConf->username);
    else if (pConfig->username != (char *)0)
	config->username = StrDup(pConfig->username);
    else
	config->username = (char *)0;

    if (optConf->master != (char *)0 && optConf->master[0] != '\000')
	config->master = StrDup(optConf->master);
    else if (pConfig->master != (char *)0 && pConfig->master[0] != '\000')
	config->master = StrDup(pConfig->master);
    else
	config->master = StrDup(
#if USE_UNIX_DOMAIN_SOCKETS
				   UDSDIR
#else
				   MASTERHOST	/* which machine is current */
#endif
	    );
    if (config->master == (char *)0)
	OutOfMem();

    if (optConf->port != (char *)0 && optConf->port[0] != '\000')
	config->port = StrDup(optConf->port);
    else if (pConfig->port != (char *)0 && pConfig->port[0] != '\000')
	config->port = StrDup(pConfig->port);
    else
	config->port = StrDup(DEFPORT);
    if (config->port == (char *)0)
	OutOfMem();

#if HAVE_OPENSSL
    if (optConf->sslcredentials != (char *)0 &&
	optConf->sslcredentials[0] != '\000')
	config->sslcredentials = StrDup(optConf->sslcredentials);
    else if (pConfig->sslcredentials != (char *)0 &&
	     pConfig->sslcredentials[0] != '\000')
	config->sslcredentials = StrDup(pConfig->sslcredentials);
    else
	config->sslcredentials = (char *)0;

    if (optConf->sslenabled != FLAGUNKNOWN)
	config->sslenabled = optConf->sslenabled;
    else if (pConfig->sslenabled != FLAGUNKNOWN)
	config->sslenabled = pConfig->sslenabled;
    else
	config->sslenabled = FLAGTRUE;

    if (optConf->sslrequired != FLAGUNKNOWN)
	config->sslrequired = optConf->sslrequired;
    else if (pConfig->sslrequired != FLAGUNKNOWN)
	config->sslrequired = pConfig->sslrequired;
    else
	config->sslrequired = FLAGTRUE;
#endif

    /* finish resolving the command to do */
    if (pcCmd == (char *)0) {
	pcCmd = "attach";
    }

    if (*pcCmd == 'a' || *pcCmd == 'f' || *pcCmd == 's') {
	if (optind >= argc) {
	    Error("missing console name");
	    Bye(EX_UNAVAILABLE);
	}
	if (cmdarg != (char *)0)
	    free(cmdarg);
	if ((cmdarg = StrDup(argv[optind++])) == (char *)0)
	    OutOfMem();
    } else if (*pcCmd == 't') {
	if (optind >= argc) {
	    Error("missing message text");
	    Bye(EX_UNAVAILABLE);
	}
	if (cmdarg != (char *)0)
	    free(cmdarg);
	if ((cmdarg = StrDup(argv[optind++])) == (char *)0)
	    OutOfMem();
    }

    if (optind < argc) {
	Error("extra garbage on command line? (%s...)", argv[optind]);
	Bye(EX_UNAVAILABLE);
    }
#if !USE_UNIX_DOMAIN_SOCKETS
    /* Look for non-numeric characters */
    for (opt = 0; config->port[opt] != '\000'; opt++)
	if (!isdigit((int)config->port[opt]))
	    break;

    if (config->port[opt] == '\000') {
	/* numeric only */
	bindPort = atoi(config->port);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((pSE =
	     getservbyname(config->port, "tcp")) == (struct servent *)0) {
	    Error("getservbyname(%s) failed", config->port);
	    Bye(EX_UNAVAILABLE);
	} else {
	    bindPort = ntohs((u_short) pSE->s_port);
	}
    }
#endif

    if (config->username == (char *)0 || config->username[0] == '\000') {
	if (config->username != (char *)0)
	    free(config->username);
	if (((config->username = getenv("LOGNAME")) == (char *)0) &&
	    ((config->username = getenv("USER")) == (char *)0) &&
	    ((pwdMe = getpwuid(getuid())) == (struct passwd *)0)) {
	    Error
		("$LOGNAME and $USER do not exist and getpwuid fails: %d: %s",
		 (int)(getuid()), strerror(errno));
	    Bye(EX_UNAVAILABLE);
	}
	if (config->username == (char *)0) {
	    if (pwdMe->pw_name == (char *)0 || pwdMe->pw_name[0] == '\000') {
		Error("Username for uid %d does not exist",
		      (int)(getuid()));
		Bye(EX_UNAVAILABLE);
	    } else {
		config->username = pwdMe->pw_name;
	    }
	}
	if ((config->username = StrDup(config->username)) == (char *)0)
	    OutOfMem();
    }

    if (execCmd == (STRING *)0)
	execCmd = AllocString();

    SimpleSignal(SIGPIPE, SIG_IGN);

    cfstdout = FileOpenFD(1, simpleFile);

    BuildString((char *)0, acPorts);
    BuildStringChar('@', acPorts);
    BuildString(config->master, acPorts);

#if HAVE_OPENSSL
    SetupSSL();			/* should only do if we want ssl - provide flag! */
#endif

    /* stack up the commands for DoCmds() */
    cmdi = -1;
    cmds[++cmdi] = pcCmd;

    if (*pcCmd == 'q' || *pcCmd == 'v' || *pcCmd == 'p') {
	if (!fLocal)
	    cmds[++cmdi] = "master";
    } else if (*pcCmd == 'a' || *pcCmd == 'f' || *pcCmd == 's') {
	ValidateEsc();
	cmds[++cmdi] = "call";
    } else {
	cmds[++cmdi] = "groups";
	if (!fLocal)
	    cmds[++cmdi] = "master";
    }

    for (;;) {
	if (gotoConsole == (CONSFILE *)0)
	    DoCmds(config->master, acPorts->string, cmdi);
	else
	    Interact(gotoConsole, gotoName);

	/* if we didn't ask for another console, done */
	if (gotoConsole == (CONSFILE *)0 && prevConsole == (CONSFILE *)0)
	    break;

	if (consoleName == (STRING *)0)
	    consoleName = AllocString();
	C2Raw();
	if (prevConsole == (CONSFILE *)0)
	    FileWrite(cfstdout, FLAGFALSE, "console: ", 9);
	else
	    FileWrite(cfstdout, FLAGFALSE, "[console: ", 10);
	GetUserInput(consoleName);
	FileWrite(cfstdout, FLAGFALSE, "]\r\n", 3);
	C2Cooked();
	if (consoleName->used > 1) {
	    if (cmdarg != (char *)0)
		free(cmdarg);
	    if ((cmdarg = StrDup(consoleName->string)) == (char *)0)
		OutOfMem();
	    if (prevConsole == (CONSFILE *)0) {
		prevConsole = gotoConsole;
		gotoConsole = (CONSFILE *)0;
		prevName = gotoName;
		gotoName = (char *)0;
	    }
	} else {
	    if (prevConsole != (CONSFILE *)0) {
		gotoConsole = prevConsole;
		prevConsole = (CONSFILE *)0;
		gotoName = prevName;
		prevName = (char *)0;
	    }
	}
    }

    if (cmdarg != (char *)0)
	free(cmdarg);

    if (*pcCmd == 'd')
	FilePrint(cfstdout, FLAGFALSE, "disconnected %d %s\n",
		  disconnectCount,
		  disconnectCount == 1 ? "user" : "users");

    Bye(0);
    return 0;			/* noop - Bye() terminates us */
}
