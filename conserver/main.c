/*
 *  $Id: main.c,v 5.56 2001-07-05 05:48:18-07 bryan Exp $
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
#include <consent.h>
#include <client.h>
#include <group.h>
#include <master.h>
#include <access.h>
#include <readcfg.h>
#include <version.h>
#include <output.h>

int fAll = 1, fVerbose = 0, fSoftcar = 0, fNoinit = 0, fVersion = 0;
int fDaemon = 0;
char chDefAcc = 'r';

#define FULLCFPATH SYSCONFDIR "/" CONFIGFILE;
#define FULLPDPATH SYSCONFDIR "/" PASSWDFILE;

char *pcLogfile = LOGFILEPATH;
char *pcConfig = FULLCFPATH;
char *pcPasswd = FULLPDPATH;
char *pcPort = DEFPORT;
int domainHack = 0;
char *pcAddress = NULL;
unsigned long bindAddr;
unsigned int bindPort;

struct sockaddr_in in_port;
char acMyAddr[4];	/* "\200\76\7\1"			*/
char acMyHost[256];	/* staff.cc.purdue.edu			*/

void
reopenLogfile()
{
    /* redirect stdout and stderr to the logfile.
     *
     * first time through any problems will show up (stderr still there).
     * after that, all bets are off...probably not see the errors (well,
     * aside from the tail of the old logfile, if it was rolled).
     */
    close(1);
    if (1 != open(pcLogfile, O_WRONLY|O_CREAT|O_APPEND, 0644)) {
	    Error( "open: %s: %s", pcLogfile, strerror(errno));
	    exit(1);
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

	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGINT,  SIG_IGN);
#if defined(SIGTTOU)
	(void) signal(SIGTTOU, SIG_IGN);
#endif
#if defined(SIGTSTP)
	(void) signal(SIGTSTP, SIG_IGN);
#endif

	(void)fflush(stdout);
	(void)fflush(stderr);

	switch (res = fork()) {
	case -1:
		Error( "fork: %s", strerror(errno));
		exit(1);
	case 0:
		thepid = getpid();
		break;
	default:
		exit(0);
	}

	/* if we read from stdin (by accident) we don't wanna block
	 */
	close(0);
	if (0 != open("/dev/null", O_RDWR, 0644)) {
		Error( "open: /dev/null: %s", strerror(errno));
		exit(1);
	}

	reopenLogfile();

	/* Further disassociate this process from the terminal
	 * Maybe this will allow you to start a daemon from rsh,
	 * i.e. with no controlling terminal.
	 */
#if HAVE_SETSID
	(void)setsid();
#else
	(void) setpgrp(0, getpid());

	/* lose our controlling terminal
	 */
	if (-1 != (td = open("/dev/tty", O_RDWR, 0600))) {
		(void)ioctl(td, TIOCNOTTY, (char *)0);
		close(td);
	}
#endif

	fp = fopen(PIDFILE, "w");
	if ( fp ) {
		fprintf(fp, "%d\n", (int) getpid());
		fclose(fp);
	} else {
		Error("can't write pid to %s", PIDFILE);
	}
}


static char u_terse[] =
	" [-dDhinsvV] [-a type] [-M addr] [-p port] [-C config] [-P passwd] [-L logfile]";
static char *apcLong[] = {
	"a type     set the default access type",
	"C config   give a new config file to the server process",
	"d          become a daemon, output to logfile (see -L)",
	"D          enable debug output, sent to stderr",
	"h          output this message",
	"i          init console connections on demand",
	"L logfile  give a new logfile path to the server process",
	"M addr     address to listen on (all addresses by default)",
	"n          do not output summary stream to stdout",
	"p port     port to listen on",
	"P passwd   give a new passwd file to the server process",
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
	for (/* passed */; (char *)0 != *ppc; ++ppc)
		fprintf(stderr, "\t%s\n", *ppc);
}

/* show the user our version info					(ksb)
 */
static void
Version()
{
	auto char acA1[16], acA2[16];
	int i;

	outputPid = 0;

	Info("%s", THIS_VERSION);
	Info("default access type `%c\'", chDefAcc);
	Info("default escape sequence `%s%s\'", FmtCtl(DEFATTN, acA1), FmtCtl(DEFESC, acA2));
	Info("configuration in `%s\'", pcConfig);
	Info("password in `%s\'", pcPasswd);
	Info("logfile is `%s\'", pcLogfile);
	Info("pidfile is `%s\'", PIDFILE);
	Info("limited to %d group%s with %d member%s", MAXGRP, MAXGRP == 1 ? "" : "s", MAXMEMB, MAXMEMB == 1 ? "" : "s");
#if CPARITY
	Info("high-bit of data stripped (7-bit clean)");
#else
	Info("high-bit of data *not* stripped (8-bit clean)");
#endif

	/* Look for non-numeric characters */
	for (i=0;pcPort[i] != '\000';i++)
		if (!isdigit((int)pcPort[i])) break;

	if ( pcPort[i] == '\000' ) {
		/* numeric only */
		bindPort = atoi( pcPort );
		Info("on port %u (referenced as `%s')", bindPort, pcPort);
	} else {
		/* non-numeric only */
		struct servent *pSE;
		if ((struct servent *)0 == (pSE = getservbyname(pcPort, "tcp"))) {
			Error("getservbyname: %s: %s", pcPort, strerror(errno));
		} else {
		    bindPort = ntohs((u_short)pSE->s_port);
		    Info("on port %u (referenced as `%s')", bindPort, pcPort);
		}
	}

	if (fVerbose)
	    printf(COPYRIGHT);
	exit(1);
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
	register int i, j;
	register FILE *fpConfig;
	auto struct hostent *hpMe;
	static char acOpts[] = "a:C:dDhiM:np:P:sVv";
	extern int optopt;
	extern char *optarg;
	auto REMOTE
		*pRCUniq;	/* list of uniq console servers		*/

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
		Error( "gethostbyname(%s): %s", acMyHost, hstrerror(h_errno));
		exit(1);
	}
	if (4 != hpMe->h_length || AF_INET != hpMe->h_addrtype) {
		Error( "wrong address size (4 != %d) or adress family (%d != %d)", hpMe->h_length, AF_INET, hpMe->h_addrtype);
		exit(1);
	}
#if HAVE_MEMCPY
	(void)memcpy(&acMyAddr[0], hpMe->h_addr, hpMe->h_length);
#else
	(void)bcopy(hpMe->h_addr, &acMyAddr[0], hpMe->h_length);
#endif

	while (EOF != (i = getopt(argc, argv, acOpts))) {
		switch (i) {
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
				Error( "unknown access type `%s\'", optarg);
				exit(3);
			}
			break;
		case 'C':
			pcConfig = optarg;
			break;
		case 'p':
			pcPort = optarg;
			break;
		case 'P':
			pcPasswd = optarg;
			break;
		case 'd':
			fDaemon = 1;
			break;
		case 'D':
			fDebug = 1;
			break;
		case 'h':
			fprintf(stderr, "%s: usage%s\n", progname, u_terse);
			Usage(apcLong);
			exit(0);
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
			fAll = 0;
			break;
		case 's':
			fSoftcar ^= 1;
			break;
		case 'V':
			fVersion = 1;
			break;
		case 'v':
			fVerbose = 1;
			break;
		case '\?':
			fprintf(stderr, "%s: usage%s\n", progname, u_terse);
			exit(1);
		default:
			Error( "option %c needs a parameter", optopt);
			exit(1);
		}
	}

	if (fVersion) {
		Version();
		exit(0);
	}

	if (fDaemon) {
		daemonize();
	}

#if HAVE_GETSPNAM
	if (0 != geteuid()) {
		Error( "Warning: Running as a non-root user - any shadow password usage will most likely fail!" );
	}
#endif

	/* read the config file
	 */
	if ((FILE *)0 == (fpConfig = fopen(pcConfig, "r"))) {
		Error( "fopen: %s: %s", pcConfig, strerror(errno));
		exit(1);
	}

#if HAVE_FLOCK
	/* we lock the configuration file so that two identical
	 * conservers will not be running together  (but two with
	 * different configurations can run on the same host).
	 */
	if (-1 == flock(fileno(fpConfig), LOCK_NB|LOCK_EX)) {
		Error( "%s is locked, won\'t run more than one conserver?", pcConfig);
		exit(3);
	}
#endif

	ReadCfg(pcConfig, fpConfig);

	if ( pcAddress == NULL ) {
		bindAddr = (unsigned long)INADDR_ANY;
	} else {
		if ((bindAddr = inet_addr(pcAddress)) == -1) {
			Error("inet_addr: %s: %s", pcAddress, "invalid IP address");
			exit(1);
		}
	}
	Debug( "Bind address set to `%s'", inet_ntoa(*(struct in_addr *)&bindAddr) );

	if ( pcPort == NULL )
	{
		Error( "Severe error: pcPort is NULL????  How can that be?" );
		exit(1);
	}

	/* Look for non-numeric characters */
	for (i=0;pcPort[i] != '\000';i++)
		if (!isdigit((int)pcPort[i])) break;

	if ( pcPort[i] == '\000' ) {
		/* numeric only */
		bindPort = atoi( pcPort );
	} else {
		/* non-numeric only */
		struct servent *pSE;
		if ((struct servent *)0 == (pSE = getservbyname(pcPort, "tcp"))) {
			Debug("getservbyname: %s: %s", pcPort, strerror(errno));
			exit(1);
		} else {
		    bindPort = ntohs((u_short)pSE->s_port);
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
			Spawn(& aGroups[i]);
		}
		if (fVerbose) {
			Info("group %d on port %d", i, ntohs((u_short)aGroups[i].port));
		}
		for (j = 0; j < aGroups[i].imembers; ++j) {
			if (-1 != aGroups[i].pCElist[j].fdtty)
				(void)close(aGroups[i].pCElist[j].fdtty);
		}
	}

	if (fVerbose) {
		for (i = 0; i < iAccess; ++i) {
			Info("access type '%c' for \"%s\"", pACList[i].ctrust, pACList[i].pcwho);
		}
	}

	pRCUniq = FindUniq(pRCList);
	/* output unique console server peers?
	 */
	if (fVerbose) {
		register REMOTE *pRC;
		for (pRC = pRCUniq; (REMOTE *)0 != pRC; pRC = pRC->pRCuniq) {
			Info("peer server on `%s'", pRC->rhost);
		}
	}

	(void)fflush(stdout);
	(void)fflush(stderr);
	Master(pRCUniq);

	/* stop putting kids back, and shoot them
	 */
	(void)signal(SIGCHLD, SIG_DFL);
	for (i = 0; i < MAXGRP; ++i) {
		if (0 == aGroups[i].imembers)
			continue;
		if (-1 == kill(aGroups[i].pid, SIGTERM)) {
			Error( "kill: %s", strerror(errno));
		}
	}

	(void)endpwent();
	(void)fclose(fpConfig);
	exit(0);
}
