/*
 *  $Id: main.c,v 5.75 2001-07-26 11:49:41-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000-2001
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
#include <master.h>
#include <access.h>
#include <readcfg.h>
#include <version.h>

int fAll = 0, fVerbose = 0, fSoftcar = 0, fNoinit = 0, fVersion =
    0, fStrip = 0, fDaemon = 0, fUseLogfile = 0;

char chDefAcc = 'r';

#define FULLCFPATH SYSCONFDIR "/" CONFIGFILE
#define FULLPDPATH SYSCONFDIR "/" PASSWDFILE

char *pcLogfile = LOGFILEPATH;
char *pcConfig = FULLCFPATH;
char *pcPasswd = FULLPDPATH;
char *pcPort = DEFPORT;
char *pcBasePort = DEFBASEPORT;
int domainHack = 0;
char *pcAddress = NULL;
unsigned long bindAddr;
unsigned int bindPort;
unsigned int bindBasePort;

struct sockaddr_in in_port;
struct in_addr acMyAddr;
char acMyHost[256];		/* staff.cc.purdue.edu                  */

void
reopenLogfile()
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
daemonize()
{
    int res;
    FILE *fp;
#if !HAVE_SETSID
    int td;
#endif

    simpleSignal(SIGQUIT, SIG_IGN);
    simpleSignal(SIGINT, SIG_IGN);
#if defined(SIGTTOU)
    simpleSignal(SIGTTOU, SIG_IGN);
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

    fp = fopen(PIDFILE, "w");
    if (fp) {
	fprintf(fp, "%d\n", (int)getpid());
	fclose(fp);
    } else {
	Error("can't write pid to %s", PIDFILE);
    }
}


static char u_terse[] =
    " [-7dDhinuvV] [-a type] [-M addr] [-p port] [-b port] [-C config] [-P passwd] [-L logfile]";
static char *apcLong[] = {
    "7          strip the high bit of all console data",
    "a type     set the default access type",
    "b port     base port for secondary channel (any by default)",
    "C config   give a new config file to the server process",
    "d          become a daemon, redirecting stdout/stderr to logfile",
    "D          enable debug output, sent to stderr",
    "h          output this message",
    "i          initialize console connections on demand",
    "L logfile  give a new logfile path to the server process",
    "M addr     address to listen on (all addresses by default)",
    "n          obsolete - see -u",
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
Usage(ppc)
    char **ppc;
{
    for ( /* passed */ ; (char *)0 != *ppc; ++ppc)
	fprintf(stderr, "\t%s\n", *ppc);
}

/* show the user our version info					(ksb)
 */
static void
Version()
{
    char acA1[16], acA2[16];
    int i;

    outputPid = 0;

    Info("%s", THIS_VERSION);
    Info("default access type `%c\'", chDefAcc);
    Info("default escape sequence `%s%s\'", FmtCtl(DEFATTN, acA1),
	 FmtCtl(DEFESC, acA2));
    Info("configuration in `%s\'", pcConfig);
    Info("password in `%s\'", pcPasswd);
    Info("logfile is `%s\'", pcLogfile);
    Info("pidfile is `%s\'", PIDFILE);
    Info("limited to %d group%s with %d member%s", MAXGRP,
	 MAXGRP == 1 ? "" : "s", MAXMEMB, MAXMEMB == 1 ? "" : "s");

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

    if (fVerbose)
	printf(COPYRIGHT);
    exit(EX_OK);
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
main(argc, argv)
    int argc;
    char **argv;
{
    int i, j;
    FILE *fpConfig;
    struct hostent *hpMe;
    static char acOpts[] = "7a:b:C:dDhiL:M:np:P:suVv";
    extern int optopt;
    extern char *optarg;
    REMOTE *pRCUniq;		/* list of uniq console servers         */
    struct passwd *pwd;

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
		fDebug = 1;
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
	    case 'M':
		pcAddress = optarg;
		break;
	    case 'n':
		/* noop now */
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
    if ((struct passwd *)0 == (pwd = getpwuid(getuid())))
	Info("Started by uid %d at %s", getuid(), strtime(NULL));
    else
	Info("Started by `%s' at %s", pwd->pw_name, strtime(NULL));

#if HAVE_GETSPNAM
    if (0 != geteuid()) {
	Error
	    ("Warning: Running as a non-root user - any shadow password usage will most likely fail!");
    }
#endif

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

    if (pcAddress == NULL) {
	bindAddr = (unsigned long)INADDR_ANY;
    } else {
	if ((bindAddr = inet_addr(pcAddress)) == -1) {
	    Error("inet_addr: %s: %s", pcAddress, "invalid IP address");
	    exit(EX_UNAVAILABLE);
	}
    }
    Debug("Bind address set to `%s'",
	  inet_ntoa(*(struct in_addr *)&bindAddr));

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

    /* if no one can use us we need to come up with a default
     */
    if (0 == iAccess) {
	SetDefAccess(hpMe);
    }

    /* spawn all the children, so fix kids has an initial pid
     */
    for (i = 0; i < MAXGRP; ++i) {
	if (0 == aGroups[i].imembers)
	    continue;
	if (aGroups[i].imembers) {
	    Spawn(&aGroups[i]);
	}
	if (fVerbose) {
	    Info("group #%d pid %d on port %u", i, aGroups[i].pid,
		 ntohs(aGroups[i].port));
	}
	for (j = 0; j < aGroups[i].imembers; ++j) {
	    if (-1 != aGroups[i].pCElist[j].fdtty)
		(void)close(aGroups[i].pCElist[j].fdtty);
	}
    }

    if (fVerbose) {
	for (i = 0; i < iAccess; ++i) {
	    Info("access type '%c' for \"%s\"", pACList[i].ctrust,
		 pACList[i].pcwho);
	}
    }

    pRCUniq = FindUniq(pRCList);
    /* output unique console server peers?
     */
    if (fVerbose) {
	REMOTE *pRC;
	for (pRC = pRCUniq; (REMOTE *) 0 != pRC; pRC = pRC->pRCuniq) {
	    Info("peer server on `%s'", pRC->rhost);
	}
    }

    (void)fflush(stdout);
    (void)fflush(stderr);
    Master(pRCUniq);

    /* stop putting kids back, and shoot them
     */
    simpleSignal(SIGCHLD, SIG_DFL);
    SignalKids(SIGTERM);

    Info("Stopped at %s", strtime(NULL));
    (void)endpwent();
    (void)fclose(fpConfig);
    exit(EX_OK);
}
