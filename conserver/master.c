/*
 *  $Id: master.c,v 5.91 2003-03-10 17:37:04-08 bryan Exp $
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

#if defined(USE_LIBWRAP)
#include <syslog.h>
#include <tcpd.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif

#include <compat.h>
#include <util.h>

#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <master.h>
#include <readcfg.h>
#include <version.h>
#include <main.h>



static sig_atomic_t fSawQuit = 0, fSawHUP = 0, fSawUSR2 = 0, fSawUSR1 =
    0, fSawCHLD = 0;


static RETSIGTYPE
#if PROTOTYPES
FlagSawCHLD(int sig)
#else
FlagSawCHLD(sig)
    int sig;
#endif
{
    fSawCHLD = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGCHLD, FlagSawCHLD);
#endif
}

/* check all the kids and respawn as needed.				(fine)
 * Called when master process receives SIGCHLD
 */
static void
#if PROTOTYPES
FixKids()
#else
FixKids()
#endif
{
    pid_t pid;
    int UWbuf;
    GRPENT *pGE;

    while (-1 != (pid = waitpid(-1, &UWbuf, WNOHANG))) {
	if (0 == pid) {
	    break;
	}
	/* stopped child is just continuted
	 */
	if (WIFSTOPPED(UWbuf) && 0 == kill(pid, SIGCONT)) {
	    continue;
	}

	for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
	    if (0 == pGE->imembers)
		continue;
	    if (pid != pGE->pid)
		continue;

	    /* A couple ways to shut down the whole system */
	    if (WIFEXITED(UWbuf) && (WEXITSTATUS(UWbuf) == EX_UNAVAILABLE)) {
		fSawQuit = 1;
		/* So we don't kill something that's dead */
		pGE->pid = -1;
		Msg("[%s] exit(%d), shutdown", pGE->pCElist->server.string,
		    WEXITSTATUS(UWbuf));
		break;
	    }
	    if (WIFSIGNALED(UWbuf) && (WTERMSIG(UWbuf) == SIGTERM)) {
		fSawQuit = 1;
		/* So we don't kill something that's dead */
		pGE->pid = -1;
		Msg("[%s] signal(%d), shutdown",
		    pGE->pCElist->server.string, WTERMSIG(UWbuf));
		break;
	    }

	    /* If not, then just a simple restart of the child */
	    if (WIFEXITED(UWbuf))
		Msg("[%s] exit(%d), restarted", WEXITSTATUS(UWbuf));
	    if (WIFSIGNALED(UWbuf))
		Msg("[%s] signal(%d), restarted", WTERMSIG(UWbuf));

	    /* this kid kid is dead, start another
	     */
	    Spawn(pGE);
	    Verbose("group #%d pid %lu on port %hu", pGE->id,
		    (unsigned long)pGE->pid, ntohs(pGE->port));
	}
    }
}

/* kill all the kids and exit.
 * Called when master process receives SIGTERM
 */
static RETSIGTYPE
#if PROTOTYPES
FlagQuitIt(int arg)
#else
FlagQuitIt(arg)
    int arg;
#endif
{
    fSawQuit = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGTERM, FlagQuitIt);
#endif
}

/* yes, this is basically the same as FlagQuitIt but we *may*
 * want to do something special on SIGINT at some point.
 */
static RETSIGTYPE
#if PROTOTYPES
FlagSawINT(int arg)
#else
FlagSawINT(arg)
    int arg;
#endif
{
    fSawQuit = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGINT, FlagSawINT);
#endif
}

static RETSIGTYPE
#if PROTOTYPES
FlagSawHUP(int arg)
#else
FlagSawHUP(arg)
    int arg;
#endif
{
    fSawHUP = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGHUP, FlagSawHUP);
#endif
}

static RETSIGTYPE
#if PROTOTYPES
FlagSawUSR2(int arg)
#else
FlagSawUSR2(arg)
    int arg;
#endif
{
    fSawUSR2 = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGUSR2, FlagSawUSR2);
#endif
}

static RETSIGTYPE
#if PROTOTYPES
FlagSawUSR1(int arg)
#else
FlagSawUSR1(arg)
    int arg;
#endif
{
    fSawUSR1 = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGUSR1, FlagSawUSR1);
#endif
}

/* Signal all the kids...
 */
void
#if PROTOTYPES
SignalKids(int arg)
#else
SignalKids(arg)
    int arg;
#endif
{
    GRPENT *pGE;

    for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
	if (0 == pGE->imembers || -1 == pGE->pid)
	    continue;
	Debug(1, "SignalKids(): sending pid %lu signal %d",
	      (unsigned long)pGE->pid, arg);
	if (-1 == kill(pGE->pid, arg)) {
	    Error("SignalKids(): kill(%lu): %s", (unsigned long)pGE->pid,
		  strerror(errno));
	}
    }
}


/* this routine is used by the master console server process		(ksb)
 */
void
#if PROTOTYPES
Master(void)
#else
Master()
#endif
{
    char *pcArgs;
    int i, j, cfd;
    CONSFILE *csocket;
    REMOTE *pRC, *pRCFound;
    int nr, found, msfd;
    unsigned short prnum = 0;
    struct hostent *hpPeer;
    char cType;
    socklen_t so;
    fd_set rmask, rmaster;
    unsigned char acIn[1024];	/* a command to the master is limited to this */
    struct sockaddr_in master_port, response_port;
    int true = 1;
    pid_t pid, parentpid;
    char *ambiguous = (char *)0;
    GRPENT *pGE;
    CONSENT *pCE;
    FILE *fp;


    /* set up signal handler */
    SimpleSignal(SIGPIPE, SIG_IGN);
    SimpleSignal(SIGQUIT, SIG_IGN);
#if defined(SIGTTOU)
    SimpleSignal(SIGTTOU, SIG_IGN);
#endif
#if defined(SIGTTIN)
    SimpleSignal(SIGTTIN, SIG_IGN);
#endif
#if defined(SIGPOLL)
    SimpleSignal(SIGPOLL, SIG_IGN);
#endif
    SimpleSignal(SIGCHLD, FlagSawCHLD);
    SimpleSignal(SIGTERM, FlagQuitIt);
    SimpleSignal(SIGUSR1, FlagSawUSR1);
    SimpleSignal(SIGHUP, FlagSawHUP);
    SimpleSignal(SIGUSR2, FlagSawUSR2);
    SimpleSignal(SIGINT, FlagSawINT);

    /* set up port for master to listen on
     */
#if HAVE_MEMSET
    memset((void *)&master_port, 0, sizeof(master_port));
#else
    bzero((char *)&master_port, sizeof(master_port));
#endif
    master_port.sin_family = AF_INET;
    master_port.sin_addr.s_addr = bindAddr;
    master_port.sin_port = htons(bindPort);

    if ((msfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	Error("Master(): socket(AF_INET,SOCK_STREAM): %s",
	      strerror(errno));
	return;
    }
#if  HAVE_SETSOCKOPT
    if (setsockopt
	(msfd, SOL_SOCKET, SO_REUSEADDR, (char *)&true,
	 sizeof(true)) < 0) {
	Error("Master(): setsockopt(%u,SO_REUSEADDR): %s", msfd,
	      strerror(errno));
	return;
    }
#endif
    if (bind(msfd, (struct sockaddr *)&master_port, sizeof(master_port)) <
	0) {
	Error("Master(): bind(%u): %s", msfd, strerror(errno));
	return;
    }
    if (listen(msfd, SOMAXCONN) < 0) {
	Error("Master(): listen(%u): %s", msfd, strerror(errno));
	return;
    }

    fp = fopen(PIDFILE, "w");
    if (fp) {
	fprintf(fp, "%lu\n", (unsigned long)getpid());
	fclose(fp);
    } else {
	Error("Master(): can't write pid to %s", PIDFILE);
    }

    FD_ZERO(&rmaster);
    FD_SET(msfd, &rmaster);

    for (fSawQuit = 0; !fSawQuit; /* can't close here :-( */ ) {
	if (fSawCHLD) {
	    fSawCHLD = 0;
	    FixKids();
	}
	if (fSawHUP) {
	    fSawHUP = 0;
	    Msg("processing SIGHUP");
	    ReopenLogfile();
	    SignalKids(SIGHUP);
	    ReReadCfg();
	}
	if (fSawUSR1) {
	    fSawUSR1 = 0;
	    Msg("processing SIGUSR1");
	    SignalKids(SIGUSR1);
	}
	if (fSawUSR2) {
	    fSawUSR2 = 0;
	    Msg("processing SIGUSR2");
	    ReopenLogfile();
	    SignalKids(SIGUSR2);
	}
	if (fSawQuit) {		/* Something above set the quit flag */
	    break;
	}

	rmask = rmaster;

	if (-1 ==
	    select(msfd + 1, &rmask, (fd_set *) 0, (fd_set *) 0,
		   (struct timeval *)0)) {
	    if (errno != EINTR) {
		Error("Master(): select(): %s", strerror(errno));
	    }
	    continue;
	}
	if (!FD_ISSET(msfd, &rmask)) {
	    continue;
	}
	so = sizeof(response_port);
	cfd = accept(msfd, (struct sockaddr *)&response_port, &so);
	if (cfd < 0) {
	    Error("Master(): accept(%u): %s", msfd, strerror(errno));
	    continue;
	}

	if ((CONSFILE *) 0 == (csocket = FileOpenFD(cfd, simpleSocket))) {
	    Error("Master(): FileOpenFD(%u): %s", cfd, strerror(errno));
	    close(cfd);
	    continue;
	}
#if defined(USE_LIBWRAP)
	{
	    struct request_info request;
	    request_init(&request, RQ_DAEMON, progname, RQ_FILE, cfd, 0);
	    fromhost(&request);
	    if (!hosts_access(&request)) {
		FileWrite(csocket, "access from your host refused\r\n",
			  -1);
		FileClose(&csocket);
		continue;
	    }
	}
#endif

	so = sizeof(in_port);
	if (-1 ==
	    getpeername(FileFDNum(csocket), (struct sockaddr *)&in_port,
			&so)) {
	    FileWrite(csocket, "getpeername failed\r\n", -1);
	    FileClose(&csocket);
	    continue;
	}
	so = sizeof(in_port.sin_addr);
	if ((struct hostent *)0 ==
	    (hpPeer =
	     gethostbyaddr((char *)&in_port.sin_addr, so, AF_INET))) {
	    cType = AccType(&in_port.sin_addr, NULL);
	} else {
	    cType = AccType(&in_port.sin_addr, hpPeer->h_name);
	}
	if ('r' == cType) {
	    FileWrite(csocket, "access from your host refused\r\n", -1);
	    FileClose(&csocket);
	    continue;
	}

	fflush(stdin);
	fflush(stderr);
	switch (pid = fork()) {
	    case -1:
		FileWrite(csocket, "fork failed, try again later\r\n", -1);
		FileClose(&csocket);
		Error("Master(): fork(): %s", strerror(errno));
		continue;
	    default:
#if defined(__CYGWIN__)
		/* Since we've got all that "special" stuff in the FileClose
		 * routine for getting around a winsock bug, we have to
		 * shut things down differently here.  Instead of calling
		 * FileClose (which half-closes the socket as well as just
		 * closing the descriptor), we "unopen" the structure (to
		 * free memory) and then do a regular close.  The child (which
		 * writes to the client) will do a FileClose and all the
		 * flushing magic will happen.  UGH! -bryan
		 */
		close(FileUnopen(csocket));
#else
		FileClose(&csocket);
#endif
		continue;
	    case 0:
		parentpid = thepid;
		thepid = getpid();
		break;
	}

	/* handle the connection
	 * (port lookup, who, users, or quit)
	 */
	FileWrite(csocket, "ok\r\n", -1);
	for (i = 0; i < sizeof(acIn) - 1; /* i+=nr */ ) {
	    if ((nr =
		 FileRead(csocket, &acIn[i], sizeof(acIn) - 1 - i)) <= 0) {
		break;
	    }
	    for (j = 0; j < nr; j++, i++) {
		if (acIn[i] == '\n') {
		    acIn[i] = '\000';
		    if (i > 0 && acIn[i - 1] == '\r')
			acIn[--i] = '\000';
		    break;
		}
	    }
	    if (j != nr)
		break;
	    acIn[i] = '\000';
	}
	if (0 == i) {
	    Error("Master(): lost connection (%u)", FileFDNum(csocket));
	    FileClose(&csocket);
	    Bye(EX_OK);
	}
	if ((char *)0 != (pcArgs = strchr((char *)acIn, ':'))) {
	    *pcArgs++ = '\000';
	} else if ((char *)0 != (pcArgs = strchr((char *)acIn, ' '))) {
	    *pcArgs++ = '\000';
	}
	if (0 == strcmp((char *)acIn, "help")) {
	    static char *apcHelp[] = {
		"call    provide port for given machine\r\n",
		"groups  provide ports for group leaders\r\n",
		"help    this help message\r\n",
		"master  provide a list of master servers\r\n",
		"pid     provide pid of master process\r\n",
		"quit    terminate conserver\r\n",
		"version provide version info for server\r\n",
		(char *)0
	    };
	    char **ppc;
	    for (ppc = apcHelp; (char *)0 != *ppc; ++ppc) {
		FileWrite(csocket, *ppc, -1);
	    }
	    FileClose(&csocket);
	    Bye(EX_OK);
	}
	if (0 == strcmp((char *)acIn, "quit")) {
	    if ('t' == cType) {
		FileWrite(csocket, "trusted -- terminated\r\n", -1);
		kill(parentpid, SIGTERM);
	    } else if ((char *)0 == pcArgs) {
		FileWrite(csocket, "must be trusted to terminate\r\n", -1);
	    } else if (CheckPass("root", pcArgs) != AUTH_SUCCESS) {
		FileWrite(csocket, "Sorry.\r\n", -1);
	    } else {
		FileWrite(csocket, "ok -- terminated\r\n", -1);
		kill(parentpid, SIGTERM);
	    }
	    FileClose(&csocket);
	    Bye(EX_OK);
	}
	if (0 == strcmp((char *)acIn, "pid")) {
	    FilePrint(csocket, "%lu\r\n", (unsigned long)parentpid);
	    FileClose(&csocket);
	    Bye(EX_OK);
	}
	if (0 == strcmp((char *)acIn, "groups")) {
	    int iSep = 1;

	    for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
		if (0 == pGE->imembers)
		    continue;
		FilePrint(csocket, ":%hu" + iSep, ntohs(pGE->port));
		iSep = 0;
	    }
	    FileWrite(csocket, "\r\n", -1);
	    FileClose(&csocket);
	    Bye(EX_OK);
	}
	if (0 == strcmp((char *)acIn, "master")) {
	    int iSep = 1;

	    if ((GRPENT *) 0 != pGroups) {
		struct sockaddr_in lcl;
		so = sizeof(lcl);
		if (-1 ==
		    getsockname(FileFDNum(csocket),
				(struct sockaddr *)&lcl, &so)) {
		    FileWrite(csocket,
			      "getsockname failed, try again later\r\n",
			      -1);
		    Error("Master(): getsockname(%u): %s",
			  FileFDNum(csocket), strerror(errno));
		    exit(EX_UNAVAILABLE);
		}
		FilePrint(csocket, "@%s", inet_ntoa(lcl.sin_addr));
		iSep = 0;
	    }
	    if (!fNoredir) {
		for (pRC = pRCUniq; (REMOTE *) 0 != pRC;
		     pRC = pRC->pRCuniq) {
		    FilePrint(csocket, ":@%s" + iSep, pRC->rhost.string);
		    iSep = 0;
		}
	    }
	    FileWrite(csocket, "\r\n", -1);
	    FileClose(&csocket);
	    Bye(EX_OK);
	}
	if (0 == strcmp((char *)acIn, "version")) {
	    FilePrint(csocket, "version `%s'\r\n", THIS_VERSION);
	    FileClose(&csocket);
	    Bye(EX_OK);
	}
	if (0 != strcmp((char *)acIn, "call")) {
	    FileWrite(csocket, "unknown command\r\n", -1);
	    FileClose(&csocket);
	    Bye(EX_OK);
	}

	if ((char *)0 == pcArgs) {
	    FileWrite(csocket, "call requires argument\r\n", -1);
	    FileClose(&csocket);
	    Bye(EX_OK);
	}

	/* look up the machine to call
	 */
	found = 0;
	pRCFound = (REMOTE *) 0;
	/* look for a local machine */
	for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
	    if (0 == pGE->imembers)
		continue;
	    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0;
		 pCE = pCE->pCEnext) {
		if (0 != strcmp(pcArgs, pCE->server.string)) {
		    continue;
		}
		prnum = ntohs(pGE->port);
		ambiguous = BuildTmpString(pCE->server.string);
		ambiguous = BuildTmpString(", ");
		++found;
	    }
	}
	/* Purposefully hunt for another match - this will detect
	 * duplicates - a bad state to be in.
	 * Does the readcfg.c code even check for dups?
	 */
	if (!fNoredir || (fNoredir && found == 0)) {
	    for (pRC = pRCList; (REMOTE *) 0 != pRC; pRC = pRC->pRCnext) {
		if (0 != strcmp(pcArgs, pRC->rserver.string)) {
		    continue;
		}
		ambiguous = BuildTmpString(pRC->rserver.string);
		ambiguous = BuildTmpString(", ");
		++found;
		pRCFound = pRC;
	    }
	}
	if (found == 0) {	/* Then look for substring matches */
	    for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
		if (0 == pGE->imembers)
		    continue;
		for (pCE = pGE->pCElist; pCE != (CONSENT *) 0;
		     pCE = pCE->pCEnext) {
		    if (0 !=
			strncmp(pcArgs, pCE->server.string,
				strlen(pcArgs))) {
			continue;
		    }
		    prnum = ntohs(pGE->port);
		    ambiguous = BuildTmpString(pCE->server.string);
		    ambiguous = BuildTmpString(", ");
		    ++found;
		}
	    }
	    /* look for a remote server */
	    /* again, looks for dups with local consoles */
	    if (!fNoredir || (fNoredir && found != 1)) {
		for (pRC = pRCList; (REMOTE *) 0 != pRC;
		     pRC = pRC->pRCnext) {
		    if (0 !=
			strncmp(pcArgs, pRC->rserver.string,
				strlen(pcArgs))) {
			continue;
		    }
		    ambiguous = BuildTmpString(pRC->rserver.string);
		    ambiguous = BuildTmpString(", ");
		    ++found;
		    pRCFound = pRC;
		}
	    }
	}
	switch (found) {
	    case 0:
		FilePrint(csocket, "console `%s' not found\r\n", pcArgs);
		break;
	    case 1:
		if ((REMOTE *) 0 != pRCFound) {
		    if (fNoredir) {
			FilePrint(csocket,
				  "automatic redirection disabled - console on master `%s'\r\n",
				  pRCFound->rhost.string);
		    } else {
			FilePrint(csocket, "@%s\r\n",
				  pRCFound->rhost.string);
		    }
		} else {
		    FilePrint(csocket, "%hu\r\n", prnum);
		}
		break;
	    default:
		found = strlen(ambiguous);
		ambiguous[found - 2] = '\000';
		FilePrint(csocket,
			  "ambiguous console abbreviation, `%s'\r\n\tchoices are %s\r\n",
			  pcArgs, ambiguous);
		break;
	}
	BuildTmpString((char *)0);	/* we're done - clean up */
	ambiguous = (char *)0;
	FileClose(&csocket);
	Bye(EX_OK);
    }

    unlink(PIDFILE);
}
