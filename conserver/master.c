/*
 *  $Id: master.c,v 5.23 1999-01-26 20:35:17-08 bryan Exp $
 *
 *  Copyright GNAC, Inc., 1998
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@gnac.com)
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
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>

#include "cons.h"
#include "port.h"
#include "consent.h"
#include "client.h"
#include "group.h"
#include "access.h"
#include "master.h"
#include "readcfg.h"
#include "version.h"
#include "main.h"

#if USE_STRINGS
#include <strings.h>
#else
#include <string.h>
#endif

#if USE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#include <sys/resource.h>

extern char *crypt();
extern time_t time();


/* check all the kids and respawn as needed.				(fine)
 * Called when master process receives SIGCHLD
 */
static SIGRETS
FixKids(arg)
	int arg;
{
	register int i, pid;
	auto long tyme;
	auto WAIT_T UWbuf;

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
			tyme = time((long *)0);
			printf("%s: %s: exit(%d), restarted %s", progname, aGroups[i].pCElist[0].server, WEXITSTATUS(UWbuf), ctime(&tyme));
		}
	}
}

static int fSawQuit;

/* kill all the kids and exit.
 * Called when master process receives SIGTERM
 */
static SIGRETS
QuitIt(arg)
	int arg;
{
	++fSawQuit;
}

/* Signal all the kids...
 */
static SIGRETS
SignalKids(arg)
	int arg;
{
	int i;
	for (i = 0; i < MAXGRP; ++i) {
		if (0 == aGroups[i].imembers)
			continue;
		if (-1 == kill(aGroups[i].pid, arg)) {
		    fprintf(stderr, "%s: kill: %s\n", progname, strerror(errno));
		}
	}
	(void)signal(SIGUSR1, SignalKids);
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
	register int nr, prnum, found, msfd;
	register struct hostent *hpPeer;
	auto char cType;
	auto int so;
	auto fd_set rmask, rmaster;
	auto char acIn[1024], acOut[BUFSIZ];
	auto struct sockaddr_in master_port, response_port;
	int true = 1;

	/* set up signal handler */
	(void)signal(SIGCHLD, FixKids);
	(void)signal(SIGTERM, QuitIt);
	(void)signal(SIGUSR1, SignalKids);
	(void)signal(SIGHUP, SignalKids);

	/* set up port for master to listen on
	 */
#if USE_STRINGS
	(void)bzero((char *)&master_port, sizeof(master_port));
#else
        (void)memset((void *)&master_port, 0, sizeof(master_port));
#endif
	master_port.sin_family = AF_INET;
	*(u_long *)&master_port.sin_addr = INADDR_ANY;
#if defined(SERVICE)
	{
		struct servent *pSE;
		if ((struct servent *)0 == (pSE = getservbyname(acService, "tcp"))) {
			fprintf(stderr, "%s: getservbyname: %s: %s\n", progname, acService, strerror(errno));
			return;
		}
		master_port.sin_port = pSE->s_port;
	}
#else
#if defined(PORT)
	master_port.sin_port = htons((u_short)PORT);
#else
	fprintf(stderr, "%s: no port or service compiled in?\n", progname);
#endif
#endif

	if ((msfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "%s: socket: %s\n", progname, strerror(errno));
		return;
	}
#if  HAVE_SETSOCKOPT
	if (setsockopt(msfd, SOL_SOCKET, SO_REUSEADDR, (char *)&true, sizeof(true))<0) {
		fprintf(stderr, "%s: setsockopt: %s\n", progname, strerror(errno));
		return;
	}
#endif
	if (bind(msfd, (struct sockaddr *)&master_port, sizeof(master_port))<0) {
		fprintf(stderr, "%s: bind: %s\n", progname, strerror(errno));
		return;
	}
	if (listen(msfd, SOMAXCONN) < 0) {
		fprintf(stderr, "%s: listen: %s\n", progname, strerror(errno));
	}

	FD_ZERO(&rmaster);
	FD_SET(msfd, &rmaster);
	for (fSawQuit = 0; !fSawQuit; /* can't close here :-( */) {
		rmask = rmaster;

		if (-1 == select(msfd+1, &rmask, (fd_set *)0, (fd_set *)0, (struct timeval *)0)) {
			if ( errno != EINTR ) {
			    fprintf(stderr, "%s: select: %s\n", progname, strerror(errno));
			}
			continue;
		}
		if (!FD_ISSET(msfd, &rmask)) {
			continue;
		}
		so = sizeof(response_port);
		cfd = accept(msfd, (struct sockaddr *)&response_port, &so);
		if (cfd < 0) {
			fprintf(stderr, "%s: accept: %s\n", progname, strerror(errno));
			continue;
		}


		so = sizeof(in_port);
		if (-1 == getpeername(cfd, (struct sockaddr *)&in_port, &so)) {
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
			fprintf(stderr, "%s: lost connection\n", progname);
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
			sprintf(acOut, "%d\r\n", getppid());
			(void)write(cfd, acOut, strlen(acOut));
			exit(0);
#else
			sprintf(acOut, "%d\r\n", getpid());
			(void)write(cfd, acOut, strlen(acOut));
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
			sprintf(acOut, "version `%s\'\r\n", GNAC_VERSION);
			(void)write(cfd, acOut, strlen(acOut));
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
		}
		/* look for a remote server */
		for (pRC = pRCList; (REMOTE *)0 != pRC; pRC = pRC->pRCnext) {
			if (0 != strncmp(pcArgs, pRC->rserver, strlen(pcArgs))) {
				continue;
			}
			++found;
			pRCFound = pRC;
		}
		switch (found) {
		case 0:
			sprintf(acOut, "server %s not found\r\n", pcArgs);
			break;
		case 1:
			if ((REMOTE *)0 != pRCFound) {
				sprintf(acOut, "@%s\r\n", pRCFound->rhost, pcArgs);
			} else {
				sprintf(acOut, "%d\r\n", prnum);
			}
			break;
		default:
			sprintf(acOut, "ambigous server abbreviation, %s\r\n", pcArgs);
			break;
		}
		(void)write(cfd, acOut, strlen(acOut));
		(void)close(cfd);
#if TEST_FORK
		exit(0);
#endif
	}
}
