/*
 *  $Id: master.c,v 5.36 2001-06-15 09:12:01-07 bryan Exp $
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
#include <access.h>
#include <master.h>
#include <readcfg.h>
#include <version.h>
#include <main.h>
#include <output.h>



static sig_atomic_t fSawQuit, fSawHUP, fSawUSR1, fSawCHLD;


static RETSIGTYPE
FlagSawCHLD(sig)
	int sig;
{
	fSawCHLD = 1;
#if !HAVE_SIGACTION
	(void)signal(SIGCHLD, FlagSawCHLD);
#endif
}

/* check all the kids and respawn as needed.				(fine)
 * Called when master process receives SIGCHLD
 */
static void
FixKids()
{
	register int i, pid;
	auto time_t tyme;
	auto int UWbuf;
	char styme[26];

#if HAVE_WAIT3
	while (-1 != (pid = wait3(& UWbuf, WNOHANG, (struct rusage *)0))) {
#else
	while (-1 != (pid = wait(& UWbuf))) {
#endif
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

			/* this kid kid is dead, start another
			 */
			Spawn(& aGroups[i]);
			tyme = time((time_t *)0);
			(void)strcpy(styme, ctime(&tyme));
			styme[24] = '\000';
			Info("%s: exit(%d), restarted %s", aGroups[i].pCElist[0].server, WEXITSTATUS(UWbuf), styme);
		}
	}
}

/* kill all the kids and exit.
 * Called when master process receives SIGTERM
 */
static RETSIGTYPE
QuitIt(arg)
	int arg;
{
	fSawQuit = 1;
}

static RETSIGTYPE
FlagSawHUP(arg)
	int arg;
{
	fSawHUP = 1;
#if !HAVE_SIGACTION
	(void)signal(SIGHUP, FlagSawHUP);
#endif
}

static RETSIGTYPE
FlagSawUSR1(arg)
	int arg;
{
	fSawUSR1 = 1;
#if !HAVE_SIGACTION
	(void)signal(SIGUSR1, FlagSawUSR1);
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
		if (0 == aGroups[i].imembers)
			continue;
		if (-1 == kill(aGroups[i].pid, arg)) {
		    Error("%s: kill: %s", strerror(errno));
		}
	}
}


/* this routine is used by the master console server process		(ksb)
 */
void
Master(pRCUniq)
REMOTE
	*pRCUniq;		/* list of uniq console servers		*/
{
	register char *pcArgs;
	register int i, j, cfd;
	register REMOTE *pRC, *pRCFound;
	register int nr, prnum = 0, found, msfd;
	register struct hostent *hpPeer;
	auto char cType;
	auto int so;
	auto fd_set rmask, rmaster;
	auto char acIn[1024], acOut[BUFSIZ];
	auto struct sockaddr_in master_port, response_port;
	int true = 1;

	/* set up signal handler */
#if defined(SIGPOLL)
	signal(SIGPOLL, SIG_IGN);
#endif
	Set_signal(SIGCHLD, FlagSawCHLD);
	Set_signal(SIGTERM, QuitIt);
	Set_signal(SIGUSR1, FlagSawUSR1);
	Set_signal(SIGHUP, FlagSawHUP);

	/* set up port for master to listen on
	 */
#if HAVE_MEMSET
        (void)memset((void *)&master_port, 0, sizeof(master_port));
#else
	(void)bzero((char *)&master_port, sizeof(master_port));
#endif
	master_port.sin_family = AF_INET;
	*(u_long *)&master_port.sin_addr = INADDR_ANY;
#if defined(SERVICENAME)
	{
		struct servent *pSE;
		if ((struct servent *)0 == (pSE = getservbyname(acService, "tcp"))) {
			Error("%s: getservbyname: %s: %s", acService, strerror(errno));
			return;
		}
		master_port.sin_port = pSE->s_port;
	}
#else
# if defined(PORTNUMBER)
	master_port.sin_port = htons((u_short)PORTNUMBER);
# else
	Error("%s: no port or service compiled in?");
# endif
#endif

	if ((msfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		Error("%s: socket: %s", strerror(errno));
		return;
	}
#if  HAVE_SETSOCKOPT
	if (setsockopt(msfd, SOL_SOCKET, SO_REUSEADDR, (char *)&true, sizeof(true))<0) {
		Error("%s: setsockopt: %s", strerror(errno));
		return;
	}
#endif
	if (bind(msfd, (struct sockaddr *)&master_port, sizeof(master_port))<0) {
		Error("%s: bind: %s", strerror(errno));
		return;
	}
	if (listen(msfd, SOMAXCONN) < 0) {
		Error("%s: listen: %s", strerror(errno));
	}

	FD_ZERO(&rmaster);
	FD_SET(msfd, &rmaster);
	for (fSawQuit = 0; !fSawQuit; /* can't close here :-( */) {
	        if (fSawCHLD) {
		    fSawCHLD = 0;
		    FixKids();
		}
		if (fSawHUP) {
		    fSawHUP = 0;
		    SignalKids(SIGHUP);
		}
		if (fSawUSR1) {
		    fSawUSR1 = 0;
		    SignalKids(SIGUSR1);
		}

		rmask = rmaster;

		if (-1 == select(msfd+1, &rmask, (fd_set *)0, (fd_set *)0, (struct timeval *)0)) {
			if ( errno != EINTR ) {
			    Error("%s: select: %s", strerror(errno));
			}
			continue;
		}
		if (!FD_ISSET(msfd, &rmask)) {
			continue;
		}
		so = sizeof(response_port);
		cfd = accept(msfd, (struct sockaddr *)&response_port, (socklen_t *)&so);
		if (cfd < 0) {
			Error("%s: accept: %s", strerror(errno));
			continue;
		}


		so = sizeof(in_port);
		if (-1 == getpeername(cfd, (struct sockaddr *)&in_port, (socklen_t *)&so)) {
			CSTROUT(cfd, "getpeername failed\r\n");
			(void)close(cfd);
			continue;
		}
		so = sizeof(in_port.sin_addr);
		if ((struct hostent *)0 == (hpPeer = gethostbyaddr((char *)&in_port.sin_addr, so, AF_INET))) {
			CSTROUT(cfd, "unknown peer name\r\n");
			(void)close(cfd);
			continue;
		}
		if ('r' == (cType = AccType(hpPeer))) {
			CSTROUT(cfd, "access from your host refused\r\n");
			(void)close(cfd);
			continue;
		}

#if TEST_FORK
		/* we should fork here, or timeout
		 */
		switch(fork()) {
		default:
			(void)close(cfd);
			continue;
		case -1:
			CSTROUT(cfd, "fork failed, try again\r\n");
			(void)close(cfd);
			continue;
		case 0:
			thepid = getpid();
			break;
		}
#endif
		/* handle the connection
		 * (port lookup, who, users, or quit)
		 */
		CSTROUT(cfd, "ok\r\n");
		for (i = 0; i < sizeof(acIn); /* i+=nr */) {
			if (0 >= (nr = read(cfd, &acIn[i], sizeof(acIn)-1-i))) {
				i = 0;
				break;
			}
			i += nr;
			if ('\n' == acIn[i-1]) {
				acIn[i] = '\000';
				--i;
				break;
			}
		}
		if (i > 0 && '\n' == acIn[i-1]) {
			acIn[--i] = '\000';
		}
		if (i > 0 && '\r' == acIn[i-1]) {
			acIn[--i] = '\000';
		}
		if (0 == i) {
			Error("%s: lost connection");
			(void)close(cfd);
#if TEST_FORK
			exit(1);
#else
			continue;
#endif
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
			register char **ppc;
			for (ppc = apcHelp; (char *)0 != *ppc; ++ppc) {
				(void)write(cfd, *ppc, strlen(*ppc));
			}
			(void)close(cfd);
#if TEST_FORK
			exit(0);
#else
			continue;
#endif
		}
		if (0 == strcmp(acIn, "quit")) {
			register struct passwd *pwd;

			if ('t' == cType) {
				CSTROUT(cfd, "trusted -- terminated\r\n");
#if TEST_FORK
				kill(getppid(), SIGTERM);
#else
				fSawQuit = 1;
#endif
			} else if ((char *)0 == pcArgs) {
				CSTROUT(cfd, "must be trusted to terminate\r\n");
			} else if ((struct passwd *)0 == (pwd = getpwuid(0))) {
				CSTROUT(cfd, "no root passwd?\r\n");
			} else if (0 == CheckPass(pwd, (char *)0, pcArgs)) {
				CSTROUT(cfd, "Sorry.\r\n");
			} else {
				CSTROUT(cfd, "ok -- terminated\r\n");
#if TEST_FORK
				kill(getppid(), SIGTERM);
#else
				fSawQuit = 1;
#endif
			}
			(void)close(cfd);
#if TEST_FORK
			exit(0);
#else
			continue;
#endif
		}
		if (0 == strcmp(acIn, "pid")) {
#if TEST_FORK
			sprintf(acOut, "%d\r\n", (int)getppid());
			(void)write(cfd, acOut, strlen(acOut));
			exit(0);
#else
			sprintf(acOut, "%d\r\n", (int)getpid());
			(void)write(cfd, acOut, strlen(acOut));
			(void)close(cfd);
			continue;
#endif
		}
		if (0 == strcmp(acIn, "groups")) {
			register int iSep = 1;

			for (i = 0; i < MAXGRP; ++i) {
				if (0 == aGroups[i].imembers)
					continue;
				sprintf(acOut, ":%d"+iSep, ntohs((u_short)aGroups[i].port));
				(void)write(cfd, acOut, strlen(acOut));
				iSep = 0;
			}
			CSTROUT(cfd, "\r\n");
			(void)close(cfd);
#if TEST_FORK
			exit(0);
#else
			continue;
#endif
		}
		if (0 == strcmp(acIn, "master")) {
			register int iSep = 1;

			if (0 != iLocal) {
				sprintf(acOut, "@%s", acMyHost);
				(void)write(cfd, acOut, strlen(acOut));
				iSep = 0;
			}
			for (pRC = pRCUniq; (REMOTE *)0 != pRC; pRC = pRC->pRCuniq) {
				sprintf(acOut, ":@%s"+iSep, pRC->rhost);
				(void)write(cfd, acOut, strlen(acOut));
				iSep = 0;
			}
			CSTROUT(cfd, "\r\n");
			(void)close(cfd);
#if TEST_FORK
			exit(0);
#else
			continue;
#endif
		}
		if (0 == strcmp(acIn, "version")) {
			sprintf(acOut, "version `%s\'\r\n", THIS_VERSION);
			(void)write(cfd, acOut, strlen(acOut));
			(void)close(cfd);
#if TEST_FORK
			exit(0);
#else
			continue;
#endif
		}
		if (0 != strcmp(acIn, "call")) {
			CSTROUT(cfd, "unknown command\r\n");
			(void)close(cfd);
#if TEST_FORK
			exit(0);
#else
			continue;
#endif
		}

		if ((char *)0 == pcArgs) {
			CSTROUT(cfd, "call requires argument\r\n");
			(void)close(cfd);
#if TEST_FORK
			exit(0);
#else
			continue;
#endif
		}

		/* look up the machine to call
		 */
		found = 0;
		pRCFound = (REMOTE *)0;
		/* look for a local machine */
		for (i = 0; i < MAXGRP; ++i) {
			if (0 == aGroups[i].imembers)
				continue;
			for (j = 0; j < aGroups[i].imembers; ++j) {
				if (0 != strcmp(pcArgs, aGroups[i].pCElist[j].server)) {
					continue;
				}
				prnum = ntohs((u_short)aGroups[i].port);
				++found;
			}
		}
		/* Purposefully hunt for another match - this will detect
		 * duplicates - a bad state to be in.
		 * Does the readcfg.c code even check for dups?
		 */
		for (pRC = pRCList; (REMOTE *)0 != pRC; pRC = pRC->pRCnext) {
			if (0 != strcmp(pcArgs, pRC->rserver)) {
				continue;
			}
			++found;
			pRCFound = pRC;
		}
		if ( found == 0 ) {	/* Then look for substring matches */
		    for (i = 0; i < MAXGRP; ++i) {
			    if (0 == aGroups[i].imembers)
				    continue;
			    for (j = 0; j < aGroups[i].imembers; ++j) {
				if (0 != strncmp(pcArgs, aGroups[i].pCElist[j].server, strlen(pcArgs))) {
					continue;
				}
				prnum = ntohs((u_short)aGroups[i].port);
				++found;
			}
		    }
		    /* look for a remote server */
		    /* again, looks for dups with local consoles */
		    for (pRC = pRCList; (REMOTE *)0 != pRC; pRC = pRC->pRCnext) {
			    if (0 != strncmp(pcArgs, pRC->rserver, strlen(pcArgs))) {
				    continue;
			    }
			    ++found;
			    pRCFound = pRC;
		    }
		}
		switch (found) {
		case 0:
			sprintf(acOut, "server %s not found\r\n", pcArgs);
			break;
		case 1:
			if ((REMOTE *)0 != pRCFound) {
				sprintf(acOut, "@%s\r\n", pRCFound->rhost);
			} else {
				sprintf(acOut, "%d\r\n", prnum);
			}
			break;
		default:
			sprintf(acOut, "ambiguous server abbreviation, %s\r\n", pcArgs);
			break;
		}
		(void)write(cfd, acOut, strlen(acOut));
		(void)close(cfd);
#if TEST_FORK
		exit(0);
#endif
	}
}
