/*
 *  $Id: main.c,v 5.95 2002-09-22 09:31:54-07 bryan Exp $
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
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>

#include <compat.h>
#include <port.h>
#include <util.h>

#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <master.h>
#include <readcfg.h>
#include <version.h>

int fAll = 0, fVerbose = 0, fSoftcar = 0, fNoinit = 0, fVersion =
    0, fStrip = 0, fDaemon = 0, fUseLogfile = 0, fReopen = 0, fReopenall =
    0, fNoautoreup = 0;

char chDefAcc = 'r';

#define FULLCFPATH SYSCONFDIR "/" CONFIGFILE
#define FULLPDPATH SYSCONFDIR "/" PASSWDFILE

char *pcLogfile = LOGFILEPATH;
char *pcConfig = FULLCFPATH;
char *pcPasswd = FULLPDPATH;
char *pcPort = DEFPORT;
char *pcBasePort = DEFBASEPORT;
int domainHack = 0;
int isMaster = 1;
int cMaxMemb = MAXMEMB;
char *pcAddress = NULL;
in_addr_t bindAddr;
unsigned int bindPort;
unsigned int bindBasePort;

struct sockaddr_in in_port;
struct in_addr acMyAddr;
char acMyHost[1024];		/* staff.cc.purdue.edu                  */

void
#if USE_ANSI_PROTO
reopenLogfile()
#else
reopenLogfile()
#endif
{
    /* redirect stdout and stderr to the logfile.
     *
     * first time through any problems will show up (stderr still there).
     * after that, all bets are off...probably not see the errors (well,
     * aside from the tail of the old logfile, if it was rolled).
     */
    if (!fUseLogfile)
	return;

    close(1);
    if (1 != open(pcLogfile, O_WRONLY | O_CREAT | O_APPEND, 0644)) {
	Error("open: %s: %s", pcLogfile, strerror(errno));
	exit(EX_TEMPFAIL);
    }
    close(2);
    dup(1);
}

/* become a daemon							(ksb)
 */
static void
#if USE_ANSI_PROTO
daemonize()
#else
daemonize()
#endif
{
    int res;
#if !HAVE_SETSID
    int td;
#endif

    simpleSignal(SIGQUIT, SIG_IGN);
    simpleSignal(SIGINT, SIG_IGN);
#if defined(SIGTTOU)
    simpleSignal(SIGTTOU, SIG_IGN);
#endif
#if defined(SIGTTIN)
    simpleSignal(SIGTTIN, SIG_IGN);
#endif
#if defined(SIGTSTP)
    simpleSignal(SIGTSTP, SIG_IGN);
#endif

    (void)fflush(stdout);
    (void)fflush(stderr);

    switch (res = fork()) {
	case -1:
	    Error("fork: %s", strerror(errno));
	    exit(EX_UNAVAILABLE);
	case 0:
	    thepid = getpid();
	    break;
	default:
	    exit(EX_OK);
    }

    reopenLogfile();

    /* Further disassociate this process from the terminal
     * Maybe this will allow you to start a daemon from rsh,
     * i.e. with no controlling terminal.
     */
#if HAVE_SETSID
    (void)setsid();
#else
    (void)setpgrp(0, getpid());

    /* lose our controlling terminal
     */
    if (-1 != (td = open("/dev/tty", O_RDWR, 0600))) {
	(void)ioctl(td, TIOCNOTTY, (char *)0);
	close(td);
    }
#endif
}


static char u_terse[] =
    " [-7dDFhinouvV] [-a type] [-m max] [-M addr] [-p port] [-b port] [-C config] [-P passwd] [-L logfile] [-O min]";
static char *apcLong[] = {
    "7          strip the high bit of all console data",
    "a type     set the default access type",
    "b port     base port for secondary channel (any by default)",
    "C config   give a new config file to the server process",
    "d          become a daemon, redirecting stdout/stderr to logfile",
    "D          enable debug output, sent to stderr",
    "F          do not automatically reinitialize failed consoles",
    "h          output this message",
    "i          initialize console connections on demand",
    "L logfile  give a new logfile path to the server process",
    "m max      maximum consoles managed per process",
    "M addr     address to listen on (all addresses by default)",
    "n          obsolete - see -u",
    "o          reopen downed console on client connect",
    "O min      reopen all downed consoles every <min> minutes",
    "p port     port to listen on",
    "P passwd   give a new passwd file to the server process",
    "u          copy \"unloved\" console data to stdout",
    "v          be verbose on startup",
    "V          output version info",
    (char *)0
};

/* output a long message to the user					(ksb)
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

/* show the user our version info					(ksb)
 */
static void
#if USE_ANSI_PROTO
Version()
#else
Version()
#endif
{
    static STRING acA1 = { (char *)0, 0, 0 };
    static STRING acA2 = { (char *)0, 0, 0 };
    int i;

    outputPid = 0;

    Info("%s", THIS_VERSION);
    Info("default access type `%c\'", chDefAcc);
    Info("default escape sequence `%s%s\'", FmtCtl(DEFATTN, &acA1),
	 FmtCtl(DEFESC, &acA2));
    Info("configuration in `%s\'", pcConfig);
    Info("password in `%s\'", pcPasswd);
    Info("logfile is `%s\'", pcLogfile);
    Info("pidfile is `%s\'", PIDFILE);
    Info("limited to %d member%s per group", cMaxMemb,
	 cMaxMemb == 1 ? "" : "s");

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

    /* Look for non-numeric characters */
    for (i = 0; pcBasePort[i] != '\000'; i++)
	if (!isdigit((int)pcBasePort[i]))
	    break;

    if (pcBasePort[i] == '\000') {
	/* numeric only */
	bindBasePort = atoi(pcBasePort);
	Info("secondary channel base port %u (referenced as `%s')",
	     bindBasePort, pcBasePort);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 ==
	    (pSE = getservbyname(pcBasePort, "tcp"))) {
	    Error("getservbyname: %s: %s", pcBasePort, strerror(errno));
	} else {
	    bindBasePort = ntohs((u_short) pSE->s_port);
	    Info("secondary channel base port %u (referenced as `%s')",
		 bindBasePort, pcBasePort);
	}
    }
    Info("built with `%s'", CONFIGINVOCATION);

    if (fVerbose)
	printf(COPYRIGHT);
    exit(EX_OK);
}

void
#if USE_ANSI_PROTO
dumpDataStructures()
#else
dumpDataStructures()
#endif
{
    GRPENT *pGE;
    CONSENT *pCE;
    REMOTE *pRC;
    char *empty = "<empty>";

    if (!fDebug)
	return;

    for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
	Debug(1, "Group: id=%u pid=%d, port=%d, imembers=%d", pGE->id,
	      pGE->port, pGE->pid, pGE->imembers);

	for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	    if (pCE->pccmd.string == (char *)0)
		pCE->pccmd.string = empty;
	    if (pCE->server.string == (char *)0)
		pCE->server.string = empty;
	    if (pCE->dfile.string == (char *)0)
		pCE->dfile.string = empty;
	    if (pCE->lfile.string == (char *)0)
		pCE->lfile.string = empty;
	    if (pCE->networkConsoleHost.string == (char *)0)
		pCE->networkConsoleHost.string = empty;
	    if (pCE->acslave.string == (char *)0)
		pCE->acslave.string = empty;

	    Debug(1, "  server=%s, dfile=%s, lfile=%s", pCE->server.string,
		  pCE->dfile.string, pCE->lfile.string);
	    Debug(1, "  mark=%d, nextMark=%ld, breakType=%d", pCE->mark,
		  pCE->nextMark, pCE->breakType);

	    Debug(1, "  isNetworkConsole=%d, networkConsoleHost=%s",
		  pCE->isNetworkConsole, pCE->networkConsoleHost.string);
	    Debug(1,
		  "  networkConsolePort=%d, telnetState=%d, autoReup=%d",
		  pCE->networkConsolePort, pCE->telnetState,
		  pCE->autoReUp);

	    Debug(1, "  baud=%s, parity=%c", pCE->pbaud->acrate,
		  pCE->pparity->ckey);

	    Debug(1, "  fvirtual=%d, acslave=%s, pccmd=%s, ipid=%d",
		  pCE->fvirtual, pCE->acslave.string, pCE->pccmd.string,
		  pCE->ipid);

	    Debug(1, "  nolog=%d, fdtty=%d, activitylog=%d, breaklog=%d",
		  pCE->nolog, pCE->fdtty, pCE->activitylog, pCE->breaklog);
	    Debug(1, "  fup=%d, fronly=%d", pCE->fup, pCE->fronly);
	    Debug(1, "  ------");
	}
    }
    for (pRC = pRCList; (REMOTE *) 0 != pRC; pRC = pRC->pRCnext) {
	if (pRC->rserver.string == (char *)0)
	    pRC->rserver.string = empty;
	if (pRC->rhost.string == (char *)0)
	    pRC->rhost.string = empty;
	Debug(1, "Remote: rserver=%s, rhost =%s", pRC->rserver.string,
	      pRC->rhost.string);
    }
}

/* find out where/who we are						(ksb)
 * parse optons
 * read in the config file, open the log file
 * spawn the kids to drive the console groups
 * become the master server
 * shutdown with grace
 * exit happy
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
    int i;
    FILE *fpConfig;
    struct hostent *hpMe;
    static char acOpts[] = "7a:b:C:dDFhiL:m:M:noO:p:P:suVv";
    extern int optopt;
    extern char *optarg;
    struct passwd *pwd;
    char *origuser = (char *)0;
    char *curuser = (char *)0;
    int curuid;
    GRPENT *pGE;
    CONSENT *pCE;

    outputPid = 1;		/* make sure stuff has the pid */

    thepid = getpid();
    if ((char *)0 == (progname = strrchr(argv[0], '/'))) {
	progname = argv[0];
    } else {
	++progname;
    }

    (void)setpwent();

#if HAVE_SETLINEBUF
    setlinebuf(stdout);
    setlinebuf(stderr);
#endif
#if HAVE_SETVBUF
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
    setvbuf(stderr, NULL, _IOLBF, BUFSIZ);
#endif


    (void)gethostname(acMyHost, sizeof(acMyHost));
    if ((struct hostent *)0 == (hpMe = gethostbyname(acMyHost))) {
	Error("gethostbyname(%s): %s", acMyHost, hstrerror(h_errno));
	exit(EX_UNAVAILABLE);
    }
    if (4 != hpMe->h_length || AF_INET != hpMe->h_addrtype) {
	Error("wrong address size (4 != %d) or adress family (%d != %d)",
	      hpMe->h_length, AF_INET, hpMe->h_addrtype);
	exit(EX_UNAVAILABLE);
    }
#if HAVE_MEMCPY
    (void)memcpy(&acMyAddr, hpMe->h_addr, hpMe->h_length);
#else
    (void)bcopy(hpMe->h_addr, &acMyAddr, hpMe->h_length);
#endif

    while (EOF != (i = getopt(argc, argv, acOpts))) {
	switch (i) {
	    case '7':
		fStrip = 1;
		break;
	    case 'a':
		chDefAcc = '\000' == *optarg ? 'r' : *optarg;
		if (isupper((int)(chDefAcc))) {
		    chDefAcc = tolower(chDefAcc);
		}
		switch (chDefAcc) {
		    case 'r':
		    case 'a':
		    case 't':
			break;
		    default:
			Error("unknown access type `%s\'", optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
	    case 'b':
		pcBasePort = optarg;
		break;
	    case 'C':
		pcConfig = optarg;
		break;
	    case 'd':
		fDaemon = 1;
		fUseLogfile = 1;
		break;
	    case 'D':
		fDebug++;
		break;
	    case 'F':
		fNoautoreup = 1;
		break;
	    case 'h':
		fprintf(stderr, "%s: usage%s\n", progname, u_terse);
		Usage(apcLong);
		exit(EX_OK);
	    case 'i':
		fNoinit = 1;
		break;
	    case 'L':
		pcLogfile = optarg;
		break;
	    case 'm':
		cMaxMemb = atoi(optarg);
		break;
	    case 'M':
		pcAddress = optarg;
		break;
	    case 'n':
		/* noop now */
		break;
	    case 'o':
		/* try reopening downed consoles on connect */
		fReopen = 1;
		break;
	    case 'O':
		/* How often to try opening all down consoles, in minutes */
		fReopenall = atoi(optarg);
		break;
	    case 'p':
		pcPort = optarg;
		break;
	    case 'P':
		pcPasswd = optarg;
		break;
	    case 's':
		fSoftcar ^= 1;
		break;
	    case 'u':
		fAll = 1;
		break;
	    case 'V':
		fVersion = 1;
		break;
	    case 'v':
		fVerbose = 1;
		break;
	    case '\?':
		fprintf(stderr, "%s: usage%s\n", progname, u_terse);
		exit(EX_UNAVAILABLE);
	    default:
		Error("option %c needs a parameter", optopt);
		exit(EX_UNAVAILABLE);
	}
    }

    if (cMaxMemb <= 0) {
	Error("ignoring invalid -m option (%d <= 0)", cMaxMemb);
	cMaxMemb = MAXMEMB;
    }

    /* if we read from stdin (by accident) we don't wanna block.
     * we just don't want any more input at this point.
     */
    close(0);
    if (0 != open("/dev/null", O_RDWR, 0644)) {
	Error("open: /dev/null: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }

    if (fVersion) {
	Version();
	exit(EX_OK);
    }

    if (fDaemon) {
	daemonize();
    }

    Info("%s", THIS_VERSION);

#if HAVE_GETLOGIN
    origuser = getlogin();
#endif
    curuid = getuid();
    if ((struct passwd *)0 != (pwd = getpwuid(curuid)))
	curuser = pwd->pw_name;

    if (curuser == (char *)0)
	if (origuser == (char *)0)
	    Info("Started as uid %d by uid %d at %s", curuid, curuid,
		 strtime(NULL));
	else
	    Info("Started as uid %d by `%s' at %s", curuid, origuser,
		 strtime(NULL));
    else
	Info("Started as `%s' by `%s' at %s", curuser,
	     (origuser == (char *)0) ? curuser : origuser, strtime(NULL));
    (void)endpwent();

#if HAVE_GETSPNAM
    if (0 != geteuid()) {
	Error
	    ("Warning: Running as a non-root user - any shadow password usage will most likely fail!");
    }
#endif

    if (pcAddress == NULL) {
	bindAddr = INADDR_ANY;
    } else {
	bindAddr = inet_addr(pcAddress);
	if (bindAddr == (in_addr_t) (-1)) {
	    Error("inet_addr: %s: %s", pcAddress, "invalid IP address");
	    exit(EX_UNAVAILABLE);
	}
    }
    if (fDebug) {
	struct in_addr ba;
	ba.s_addr = bindAddr;
	Debug(1, "Bind address set to `%s'", inet_ntoa(ba));
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

    /* Look for non-numeric characters */
    for (i = 0; pcBasePort[i] != '\000'; i++)
	if (!isdigit((int)pcBasePort[i]))
	    break;

    if (pcBasePort[i] == '\000') {
	/* numeric only */
	bindBasePort = atoi(pcBasePort);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 ==
	    (pSE = getservbyname(pcBasePort, "tcp"))) {
	    Error("getservbyname: %s: %s", pcBasePort, strerror(errno));
	    exit(EX_UNAVAILABLE);
	} else {
	    bindBasePort = ntohs((u_short) pSE->s_port);
	}
    }

    /* read the config file
     */
    if ((FILE *) 0 == (fpConfig = fopen(pcConfig, "r"))) {
	Error("fopen: %s: %s", pcConfig, strerror(errno));
	exit(EX_UNAVAILABLE);
    }
#if HAVE_FLOCK
    /* we lock the configuration file so that two identical
     * conservers will not be running together  (but two with
     * different configurations can run on the same host).
     */
    if (-1 == flock(fileno(fpConfig), LOCK_NB | LOCK_EX)) {
	Error("%s is locked, won\'t run more than one conserver?",
	      pcConfig);
	exit(EX_UNAVAILABLE);
    }
#endif

    ReadCfg(pcConfig, fpConfig);

    if (pGroups == (GRPENT *) 0 && pRCList == (REMOTE *) 0) {
	Error("No consoles found in configuration file");
    } else {
	/* if no one can use us we need to come up with a default
	 */
	if (pACList == (ACCESS *) 0) {
	    SetDefAccess(&acMyAddr, acMyHost);
	}

	/* spawn all the children, so fix kids has an initial pid
	 */
	for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
	    if (pGE->imembers == 0)
		continue;

	    Spawn(pGE);

	    if (fVerbose) {
		Info("group #%d pid %d on port %u", pGE->id, pGE->pid,
		     ntohs(pGE->port));
	    }
	    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0;
		 pCE = pCE->pCEnext) {
		if (-1 != pCE->fdtty)
		    (void)close(pCE->fdtty);
	    }
	}

	if (fVerbose) {
	    ACCESS *pACtmp;
	    for (pACtmp = pACList; pACtmp != (ACCESS *) 0;
		 pACtmp = pACtmp->pACnext) {
		Info("access type '%c' for \"%s\"", pACtmp->ctrust,
		     pACtmp->pcwho);
	    }
	}

	pRCUniq = FindUniq(pRCList);
	/* output unique console server peers?
	 */
	if (fVerbose) {
	    REMOTE *pRC;
	    for (pRC = pRCUniq; (REMOTE *) 0 != pRC; pRC = pRC->pRCuniq) {
		Info("peer server on `%s'", pRC->rhost.string);
	    }
	}

	(void)fflush(stdout);
	(void)fflush(stderr);
	Master();

	/* stop putting kids back, and shoot them
	 */
	simpleSignal(SIGCHLD, SIG_DFL);
	SignalKids(SIGTERM);
    }

    dumpDataStructures();

    Info("Stopped at %s", strtime(NULL));
    (void)endpwent();
    (void)fclose(fpConfig);
    exit(EX_OK);
}
