/*
 *  $Id: master.c,v 5.60 2001-07-26 00:49:48-07 bryan Exp $
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
#include <access.h>
#include <master.h>
#include <readcfg.h>
#include <version.h>
#include <main.h>



static sig_atomic_t fSawQuit, fSawHUP, fSawUSR1, fSawCHLD;


static RETSIGTYPE
FlagSawCHLD(sig)
    int sig;
{
    fSawCHLD = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGCHLD, FlagSawCHLD);
#endif
}

/* check all the kids and respawn as needed.				(fine)
 * Called when master process receives SIGCHLD
 */
static void
FixKids()
{
    int i, pid;
    int UWbuf;

    while (-1 != (pid = waitpid(-1, &UWbuf, WNOHANG))) {
	if (0 == pid) {
	    break;
	}
	/* stopped child is just continuted
	 */
	if (WIFSTOPPED(UWbuf) && 0 == kill(pid, SIGCONT)) {
	    continue;
	}

	for (i = 0; i < MAXGRP; ++i) {
	    if (0 == aGroups[i].imembers)
		continue;
	    if (pid != aGroups[i].pid)
		continue;

	    /* A couple ways to shut down the whole system */
	    if (WIFEXITED(UWbuf) && (WEXITSTATUS(UWbuf) == EX_UNAVAILABLE)) {
		fSawQuit = 1;
		/* So we don't kill something that's dead */
		aGroups[i].pid = -1;
		Info("%s: exit(%d), shutdown [%s]",
		     aGroups[i].pCElist[0].server, WEXITSTATUS(UWbuf),
		     strtime(NULL));
		break;
	    }
	    if (WIFSIGNALED(UWbuf) && (WTERMSIG(UWbuf) == SIGTERM)) {
		fSawQuit = 1;
		/* So we don't kill something that's dead */
		aGroups[i].pid = -1;
		Info("%s: signal(%d), shutdown [%s]",
		     aGroups[i].pCElist[0].server, WTERMSIG(UWbuf),
		     strtime(NULL));
		break;
	    }

	    /* If not, then just a simple restart of the child */
	    if (WIFEXITED(UWbuf))
		Info("%s(%d): exit(%d), restarted [%s]", progname, pid,
		     WEXITSTATUS(UWbuf), strtime(NULL));
	    if (WIFSIGNALED(UWbuf))
		Info("%s(%d): signal(%d), restarted [%s]", progname, pid,
		     WTERMSIG(UWbuf), strtime(NULL));

	    /* this kid kid is dead, start another
	     */
	    Spawn(&aGroups[i]);
	    if (fVerbose) {
		Info("group #%d pid %d on port %u", i, aGroups[i].pid,
		     ntohs(aGroups[i].port));
	    }
	}
    }
}

/* kill all the kids and exit.
 * Called when master process receives SIGTERM
 */
static RETSIGTYPE
FlagQuitIt(arg)
    int arg;
{
    fSawQuit = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGTERM, FlagQuitIt);
#endif
}

/* yes, this is basically the same as FlagQuitIt but we *may*
 * want to do something special on SIGINT at some point.
 */
static RETSIGTYPE
FlagSawINT(arg)
    int arg;
{
    fSawQuit = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGINT, FlagSawINT);
#endif
}

static RETSIGTYPE
FlagSawHUP(arg)
    int arg;
{
    fSawHUP = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGHUP, FlagSawHUP);
#endif
}

static RETSIGTYPE
FlagSawUSR1(arg)
    int arg;
{
    fSawUSR1 = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGUSR1, FlagSawUSR1);
#endif
}

/* Signal all the kids...
 */
void
SignalKids(arg)
    int arg;
{
    int i;
    for (i = 0; i < MAXGRP; ++i) {
	if (0 == aGroups[i].imembers || -1 == aGroups[i].pid)
	    continue;
	Debug("Sending pid %d signal %d", aGroups[i].pid, arg);
	if (-1 == kill(aGroups[i].pid, arg)) {
	    Error("kill: %s", strerror(errno));
	}
    }
}


/* this routine is used by the master console server process		(ksb)
 */
void
Master(pRCUniq)
    REMOTE *pRCUniq;		/* list of uniq console servers         */
{
    char *pcArgs;
    int i, j, cfd;
    CONSFILE *csocket;
    REMOTE *pRC, *pRCFound;
    int nr, found, msfd;
    unsigned short prnum = 0;
    struct hostent *hpPeer;
    char cType;
    int so;
    fd_set rmask, rmaster;
    unsigned char acIn[1024], acOut[BUFSIZ];
    struct sockaddr_in master_port, response_port;
    int true = 1;
    int pid;
    char *ambiguous = (char *)0;

    /* set up signal handler */
#if defined(SIGPOLL)
    simpleSignal(SIGPOLL, SIG_IGN);
#endif
    simpleSignal(SIGCHLD, FlagSawCHLD);
    simpleSignal(SIGTERM, FlagQuitIt);
    simpleSignal(SIGUSR1, FlagSawUSR1);
    simpleSignal(SIGHUP, FlagSawHUP);
    if (!fDaemon)
	simpleSignal(SIGINT, FlagSawINT);

    /* set up port for master to listen on
     */
#if HAVE_MEMSET
    (void)memset((void *)&master_port, 0, sizeof(master_port));
#else
    (void)bzero((char *)&master_port, sizeof(master_port));
#endif
    master_port.sin_family = AF_INET;
    master_port.sin_addr.s_addr = bindAddr;
    master_port.sin_port = htons(bindPort);

    if ((msfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	Error("socket: %s", strerror(errno));
	return;
    }
#if  HAVE_SETSOCKOPT
    if (setsockopt
	(msfd, SOL_SOCKET, SO_REUSEADDR, (char *)&true,
	 sizeof(true)) < 0) {
	Error("setsockopt: %s", strerror(errno));
	return;
    }
#endif
    if (bind(msfd, (struct sockaddr *)&master_port, sizeof(master_port)) <
	0) {
	Error("bind: %s", strerror(errno));
	return;
    }
    if (listen(msfd, SOMAXCONN) < 0) {
	Error("listen: %s", strerror(errno));
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
	    reopenLogfile();
	    SignalKids(SIGHUP);
	}
	if (fSawUSR1) {
	    fSawUSR1 = 0;
	    SignalKids(SIGUSR1);
	}
	if (fSawQuit) {		/* Something above set the quit flag */
	    break;
	}

	rmask = rmaster;

	if (-1 ==
	    select(msfd + 1, &rmask, (fd_set *) 0, (fd_set *) 0,
		   (struct timeval *)0)) {
	    if (errno != EINTR) {
		Error("select: %s", strerror(errno));
	    }
	    continue;
	}
	if (!FD_ISSET(msfd, &rmask)) {
	    continue;
	}
	so = sizeof(response_port);
	cfd =
	    accept(msfd, (struct sockaddr *)&response_port,
		   (socklen_t *) & so);
	if (cfd < 0) {
	    Error("accept: %s", strerror(errno));
	    continue;
	}
	if ((CONSFILE *) 0 == (csocket = fileOpenFD(cfd, simpleSocket))) {
	    Error("fileOpenFD: %s", strerror(errno));
	    close(cfd);
	    continue;
	}

	so = sizeof(in_port);
	if (-1 ==
	    getpeername(fileFDNum(csocket), (struct sockaddr *)&in_port,
			(socklen_t *) & so)) {
	    fileWrite(csocket, "getpeername failed\r\n", -1);
	    (void)fileClose(csocket);
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
	    fileWrite(csocket, "access from your host refused\r\n", -1);
	    (void)fileClose(csocket);
	    continue;
	}

	(void)fflush(stdin);
	(void)fflush(stderr);
	switch (pid = fork()) {
	    case -1:
		fileWrite(csocket, "fork failed, try again later\r\n", -1);
		fileClose(csocket);
		Error("fork: %s", strerror(errno));
		continue;
	    default:
#if defined(__CYGWIN__)
		/* Since we've got all that "special" stuff in the fileClose
		 * routine for getting around a winsock bug, we have to
		 * shut things down differently here.  Instead of calling
		 * fileClose (which half-closes the socket as well as just
		 * closing the descriptor), we "unopen" the structure (to
		 * free memory) and then do a regular close.  The child (which
		 * writes to the client) will do a fileClose and all the
		 * flushing magic will happen.  UGH! -bryan
		 */
		close(fileUnopen(csocket));
#else
		fileClose(csocket);
#endif
		continue;
	    case 0:
		thepid = getpid();
		break;
	}

	/* handle the connection
	 * (port lookup, who, users, or quit)
	 */
	fileWrite(csocket, "ok\r\n", -1);
	for (i = 0; i < sizeof(acIn); /* i+=nr */ ) {
	    if (0 >=
		(nr = fileRead(csocket, &acIn[i], sizeof(acIn) - 1 - i))) {
		i = 0;
		break;
	    }
	    i += nr;
	    if ('\n' == acIn[i - 1]) {
		acIn[i] = '\000';
		--i;
		break;
	    }
	}
	if (i > 0 && '\n' == acIn[i - 1]) {
	    acIn[--i] = '\000';
	}
	if (i > 0 && '\r' == acIn[i - 1]) {
	    acIn[--i] = '\000';
	}
	if (0 == i) {
	    Error("lost connection");
	    (void)fileClose(csocket);
	    exit(EX_OK);
	}
	if ((char *)0 != (pcArgs = strchr(acIn, ':'))) {
	    *pcArgs++ = '\000';
	} else if ((char *)0 != (pcArgs = strchr(acIn, ' '))) {
	    *pcArgs++ = '\000';
	}
	if (0 == strcmp(acIn, "help")) {
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
		(void)fileWrite(csocket, *ppc, -1);
	    }
	    (void)fileClose(csocket);
	    exit(EX_OK);
	}
	if (0 == strcmp(acIn, "quit")) {
	    struct passwd *pwd;

	    if ('t' == cType) {
		fileWrite(csocket, "trusted -- terminated\r\n", -1);
		fSawQuit = 1;
	    } else if ((char *)0 == pcArgs) {
		fileWrite(csocket, "must be trusted to terminate\r\n", -1);
	    } else if ((struct passwd *)0 == (pwd = getpwuid(0))) {
		fileWrite(csocket, "no root passwd?\r\n", -1);
	    } else if (0 == CheckPass(pwd, (char *)0, pcArgs)) {
		fileWrite(csocket, "Sorry.\r\n", -1);
	    } else {
		fileWrite(csocket, "ok -- terminated\r\n", -1);
		fSawQuit = 1;
	    }
	    (void)fileClose(csocket);
	    exit(EX_OK);
	}
	if (0 == strcmp(acIn, "pid")) {
	    sprintf(acOut, "%d\r\n", (int)getpid());
	    (void)fileWrite(csocket, acOut, -1);
	    (void)fileClose(csocket);
	    exit(EX_OK);
	}
	if (0 == strcmp(acIn, "groups")) {
	    int iSep = 1;

	    for (i = 0; i < MAXGRP; ++i) {
		if (0 == aGroups[i].imembers)
		    continue;
		sprintf(acOut, ":%u" + iSep, ntohs(aGroups[i].port));
		(void)fileWrite(csocket, acOut, -1);
		iSep = 0;
	    }
	    fileWrite(csocket, "\r\n", -1);
	    (void)fileClose(csocket);
	    exit(EX_OK);
	}
	if (0 == strcmp(acIn, "master")) {
	    int iSep = 1;

	    if (0 != iLocal) {
		struct sockaddr_in lcl;
		so = sizeof(lcl);
		if (-1 ==
		    getsockname(fileFDNum(csocket),
				(struct sockaddr *)&lcl,
				(socklen_t *) & so)) {
		    fileWrite(csocket,
			      "getsockname failed, try again later\r\n",
			      -1);
		    Error("getsockname: %s", strerror(errno));
		    exit(EX_UNAVAILABLE);
		}
		sprintf(acOut, "@%s", inet_ntoa(lcl.sin_addr));
		(void)fileWrite(csocket, acOut, -1);
		iSep = 0;
	    }
	    for (pRC = pRCUniq; (REMOTE *) 0 != pRC; pRC = pRC->pRCuniq) {
		sprintf(acOut, ":@%s" + iSep, pRC->rhost);
		(void)fileWrite(csocket, acOut, -1);
		iSep = 0;
	    }
	    fileWrite(csocket, "\r\n", -1);
	    (void)fileClose(csocket);
	    exit(EX_OK);
	}
	if (0 == strcmp(acIn, "version")) {
	    sprintf(acOut, "version `%s\'\r\n", THIS_VERSION);
	    (void)fileWrite(csocket, acOut, -1);
	    (void)fileClose(csocket);
	    exit(EX_OK);
	}
	if (0 != strcmp(acIn, "call")) {
	    fileWrite(csocket, "unknown command\r\n", -1);
	    (void)fileClose(csocket);
	    exit(EX_OK);
	}

	if ((char *)0 == pcArgs) {
	    fileWrite(csocket, "call requires argument\r\n", -1);
	    (void)fileClose(csocket);
	    exit(EX_OK);
	}

	/* look up the machine to call
	 */
	found = 0;
	pRCFound = (REMOTE *) 0;
	/* look for a local machine */
	for (i = 0; i < MAXGRP; ++i) {
	    if (0 == aGroups[i].imembers)
		continue;
	    for (j = 0; j < aGroups[i].imembers; ++j) {
		if (0 != strcmp(pcArgs, aGroups[i].pCElist[j].server)) {
		    continue;
		}
		prnum = ntohs(aGroups[i].port);
		ambiguous = buildString(aGroups[i].pCElist[j].server);
		ambiguous = buildString(", ");
		++found;
	    }
	}
	/* Purposefully hunt for another match - this will detect
	 * duplicates - a bad state to be in.
	 * Does the readcfg.c code even check for dups?
	 */
	for (pRC = pRCList; (REMOTE *) 0 != pRC; pRC = pRC->pRCnext) {
	    if (0 != strcmp(pcArgs, pRC->rserver)) {
		continue;
	    }
	    ambiguous = buildString(pRC->rserver);
	    ambiguous = buildString(", ");
	    ++found;
	    pRCFound = pRC;
	}
	if (found == 0) {	/* Then look for substring matches */
	    for (i = 0; i < MAXGRP; ++i) {
		if (0 == aGroups[i].imembers)
		    continue;
		for (j = 0; j < aGroups[i].imembers; ++j) {
		    if (0 !=
			strncmp(pcArgs, aGroups[i].pCElist[j].server,
				strlen(pcArgs))) {
			continue;
		    }
		    prnum = ntohs(aGroups[i].port);
		    ambiguous = buildString(aGroups[i].pCElist[j].server);
		    ambiguous = buildString(", ");
		    ++found;
		}
	    }
	    /* look for a remote server */
	    /* again, looks for dups with local consoles */
	    for (pRC = pRCList; (REMOTE *) 0 != pRC; pRC = pRC->pRCnext) {
		if (0 != strncmp(pcArgs, pRC->rserver, strlen(pcArgs))) {
		    continue;
		}
		ambiguous = buildString(pRC->rserver);
		ambiguous = buildString(", ");
		++found;
		pRCFound = pRC;
	    }
	}
	switch (found) {
	    case 0:
		sprintf(acOut, "console `%s' not found\r\n", pcArgs);
		break;
	    case 1:
		if ((REMOTE *) 0 != pRCFound) {
		    sprintf(acOut, "@%s\r\n", pRCFound->rhost);
		} else {
		    sprintf(acOut, "%u\r\n", prnum);
		}
		break;
	    default:
		found = strlen(ambiguous);
		ambiguous[found - 2] = '\000';
		sprintf(acOut,
			"ambiguous console abbreviation, `%s'\r\n\tchoices are %s\r\n",
			pcArgs, ambiguous);
		break;
	}
	buildString((char *)0);	/* we're done - clean up */
	ambiguous = (char *)0;
	(void)fileWrite(csocket, acOut, -1);
	(void)fileClose(csocket);
	exit(EX_OK);
    }
}
