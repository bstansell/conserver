/*
 *  $Id: master.c,v 5.113 2003-09-19 08:58:18-07 bryan Exp $
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
static CONSCLIENT *pCLfree = (CONSCLIENT *)0;
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
static unsigned long dmallocMarkClientConnection = 0;
#endif


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

	for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
	    if (0 == pGE->imembers)
		continue;
	    if (pid != pGE->pid)
		continue;

	    /* A couple ways to shut down the whole system */
	    if (WIFEXITED(UWbuf) && (WEXITSTATUS(UWbuf) == EX_UNAVAILABLE)) {
		Msg("child pid %lu: exit(%d), shutting down",
		    (unsigned long)pGE->pid, WEXITSTATUS(UWbuf));
		fSawQuit = 1;
		/* So we don't kill something that's dead */
		pGE->pid = -1;
		break;
	    }
	    if (WIFSIGNALED(UWbuf) && (WTERMSIG(UWbuf) == SIGTERM)) {
		Msg("child pid %lu: signal(%d), shutting down",
		    (unsigned long)pGE->pid, WTERMSIG(UWbuf));
		fSawQuit = 1;
		/* So we don't kill something that's dead */
		pGE->pid = -1;
		break;
	    }

	    /* If not, then just a simple restart of the child */
	    if (WIFEXITED(UWbuf))
		Msg("child pid %lu: exit(%d), restarting", pGE->pid,
		    WEXITSTATUS(UWbuf));

	    if (WIFSIGNALED(UWbuf))
		Msg("child pid %lu: signal(%d), restarting", pGE->pid,
		    WTERMSIG(UWbuf));

	    /* this kid kid is dead, start another
	     */
	    Spawn(pGE);
	    Verbose("group #%d pid %lu on port %hu", pGE->id,
		    (unsigned long)pGE->pid, pGE->port);
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

    for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
	if (0 == pGE->imembers || -1 == pGE->pid)
	    continue;
	CONDDEBUG((1, "SignalKids(): sending pid %lu signal %d",
		   (unsigned long)pGE->pid, arg));
	if (-1 == kill(pGE->pid, arg)) {
	    Error("SignalKids(): kill(%lu): %s", (unsigned long)pGE->pid,
		  strerror(errno));
	}
    }
}

void
#if PROTOTYPES
CommandCall(CONSCLIENT *pCL, char *args)
#else
CommandCall(pCL, args)
    CONSCLIENT *pCL;
    char *args;
#endif
{
    int found;
    REMOTE *pRC, *pRCFound;
    unsigned short prnum = 0;
    char *ambiguous = (char *)0;
    CONSENT *pCE;
    GRPENT *pGE;

    found = 0;
    pRCFound = (REMOTE *)0;
    ambiguous = BuildTmpString((char *)0);
    /* look for a local machine */
    for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
	if (pGE->imembers == 0)
	    continue;
	if ((pCE = FindConsoleName(pGE->pCElist, args)) != (CONSENT *)0) {
	    prnum = pGE->port;
	    ambiguous = BuildTmpString(pCE->server);
	    ambiguous = BuildTmpString(", ");
	    ++found;
	}
    }
    if (found == 0) {		/* Then look for substring matches */
	NAMES *name = (NAMES *)0;
	int foundOne = 0;
	for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
	    if (0 == pGE->imembers)
		continue;
	    for (pCE = pGE->pCElist; pCE != (CONSENT *)0;
		 pCE = pCE->pCEnext) {
		foundOne = 0;
		if (strncasecmp(args, pCE->server, strlen(args)) == 0) {
		    prnum = pGE->port;
		    ambiguous = BuildTmpString(pCE->server);
		    ambiguous = BuildTmpString(", ");
		    ++foundOne;
		}
		for (name = pCE->aliases; name != (NAMES *)0;
		     name = name->next) {
		    if (strncasecmp(args, name->name, strlen(args))
			!= 0)
			continue;
		    prnum = pGE->port;
		    ambiguous = BuildTmpString(name->name);
		    ambiguous = BuildTmpString(", ");
		    ++foundOne;
		}
		if (foundOne)
		    ++found;
	    }
	}
	/* look for a remote server if redirect is enabled or if
	 * redirect is not enabled and we haven't found a unique
	 * console match */
	if (config->redirect == FLAGTRUE ||
	    (config->redirect != FLAGTRUE && found != 1)) {
	    for (pRC = pRCList; (REMOTE *)0 != pRC; pRC = pRC->pRCnext) {
		foundOne = 0;
		if (strncasecmp(args, pRC->rserver, strlen(args))
		    == 0) {
		    pRCFound = pRC;
		    ambiguous = BuildTmpString(pRC->rserver);
		    ambiguous = BuildTmpString(", ");
		    ++foundOne;
		}
		for (name = pRC->aliases; name != (NAMES *)0;
		     name = name->next) {
		    if (strncasecmp(args, name->name, strlen(args))
			!= 0)
			continue;
		    pRCFound = pRC;
		    ambiguous = BuildTmpString(name->name);
		    ambiguous = BuildTmpString(", ");
		    ++foundOne;
		}
		if (foundOne)
		    ++found;
	    }
	}
    }
    switch (found) {
	case 0:
	    FilePrint(pCL->fd, "console `%s' not found\r\n", args);
	    break;
	case 1:
	    if ((REMOTE *)0 != pRCFound) {
		if (config->redirect != FLAGTRUE) {
		    FilePrint(pCL->fd,
			      "automatic redirection disabled - console on master `%s'\r\n",
			      pRCFound->rhost);
		} else {
		    FilePrint(pCL->fd, "@%s\r\n", pRCFound->rhost);
		}
	    } else {
		FilePrint(pCL->fd, "%hu\r\n", prnum);
	    }
	    break;
	default:
	    found = strlen(ambiguous);
	    ambiguous[found - 2] = '\000';
	    FilePrint(pCL->fd,
		      "ambiguous console abbreviation, `%s'\r\n\tchoices are %s\r\n",
		      args, ambiguous);
	    break;
    }
    BuildTmpString((char *)0);	/* we're done - clean up */
    ambiguous = (char *)0;
}

void
#if PROTOTYPES
DropMasterClient(CONSCLIENT *pCLServing, FLAG force)
#else
DropMasterClient(pCLServing, force)
    CONSCLIENT *pCLServing;
    FLAG force;
#endif
{
    /* if we have data buffered and aren't forced to close,
     * we can't close quite yet
     */
    if (force != FLAGTRUE && !FileBufEmpty(pCLServing->fd)) {
	pCLServing->ioState = ISFLUSHING;
	return;
    }

    if (pCLServing->iState == S_NORMAL)
	Verbose("<master> logout %s", pCLServing->acid->string);

    /* drop a connection */
    FD_CLR(FileFDNum(pCLServing->fd), &rinit);
    FD_CLR(FileFDNum(pCLServing->fd), &winit);
    FileClose(&pCLServing->fd);
    pCLServing->ioState = ISDISCONNECTED;

    /* remove from the "all" list */
    if ((CONSCLIENT *)0 != pCLServing->pCLscan) {
	pCLServing->pCLscan->ppCLbscan = pCLServing->ppCLbscan;
    }
    *(pCLServing->ppCLbscan) = pCLServing->pCLscan;
    /* put on the free list */
    pCLServing->pCLnext = pCLfree;
    pCLfree = pCLServing;

    /* we didn't touch pCLServing->pCLscan so the loop works */
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
    CONDDEBUG((1, "Master(): dmalloc / MarkClientConnection"));
    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
}

void
#if PROTOTYPES
DoNormalRead(CONSCLIENT *pCLServing)
#else
DoNormalRead(pCLServing)
    CONSCLIENT *pCLServing;
#endif
{
    char *pcCmd;
    char *pcArgs;
    int nr, i;
    unsigned char acIn[BUFSIZ];

    /* read connection */
    if ((nr = FileRead(pCLServing->fd, acIn, sizeof(acIn))) < 0) {
	DropMasterClient(pCLServing, FLAGFALSE);
	return;
    }

    for (i = 0; i < nr; ++i) {
	if ('\n' != acIn[i]) {
	    BuildStringChar(acIn[i], pCLServing->accmd);
	    continue;
	}
	if ((pCLServing->accmd->used > 1) &&
	    ('\r' ==
	     pCLServing->accmd->string[pCLServing->accmd->used - 2])) {
	    pCLServing->accmd->string[pCLServing->accmd->used - 2] =
		'\000';
	    pCLServing->accmd->used--;
	}

	/* process password here...before we corrupt accmd */
	if (pCLServing->iState == S_PASSWD) {
	    if (CheckPasswd(pCLServing, pCLServing->accmd->string) !=
		AUTH_SUCCESS) {
		FileWrite(pCLServing->fd, "invalid password\r\n", -1);
		BuildString((char *)0, pCLServing->accmd);
		DropMasterClient(pCLServing, FLAGFALSE);
		return;
	    }
	    Verbose("<master> login %s", pCLServing->acid->string);
	    FileWrite(pCLServing->fd, "ok\r\n", -1);
	    pCLServing->iState = S_NORMAL;
	    BuildString((char *)0, pCLServing->accmd);
	    continue;
	}

	if ((char *)0 != (pcArgs = strchr(pCLServing->accmd->string, ':'))) {
	    *pcArgs++ = '\000';
	} else if ((char *)0 !=
		   (pcArgs = strchr(pCLServing->accmd->string, ' '))) {
	    *pcArgs++ = '\000';
	}
	if (pcArgs != (char *)0)
	    pcArgs = PruneSpace(pcArgs);
	pcCmd = PruneSpace(pCLServing->accmd->string);
	if (strcmp(pcCmd, "help") == 0) {
	    static char *apcHelp1[] = {
		"exit   disconnect\r\n",
		"help   this help message\r\n",
		"login  log in\r\n",
#if HAVE_OPENSSL
		"ssl    start ssl session\r\n",
#endif
		(char *)0
	    };
	    static char *apcHelp2[] = {
		"call      provide port for given console\r\n",
		"exit      disconnect\r\n",
		"groups    provide ports for group leaders\r\n",
		"help      this help message\r\n",
		"master    provide a list of master servers\r\n",
		"pid       provide pid of master process\r\n",
		"quit*     terminate conserver (SIGTERM)\r\n",
		"restart*  restart conserver (SIGHUP)\r\n",
		"version   provide version info for server\r\n",
		"* = requires admin privileges\r\n",
		(char *)0
	    };
	    char **ppc;
	    for (ppc =
		 (pCLServing->iState == S_IDENT ? apcHelp1 : apcHelp2);
		 (char *)0 != *ppc; ++ppc) {
		FileWrite(pCLServing->fd, *ppc, -1);
	    }
	} else if (strcmp(pcCmd, "exit") == 0) {
	    FileWrite(pCLServing->fd, "goodbye\r\n", -1);
	    DropMasterClient(pCLServing, FLAGFALSE);
	    return;
#if HAVE_OPENSSL
	} else if (pCLServing->iState == S_IDENT &&
		   strcmp(pcCmd, "ssl") == 0) {
	    FileWrite(pCLServing->fd, "ok\r\n", -1);
	    if (!AttemptSSL(pCLServing)) {
		DropMasterClient(pCLServing, FLAGFALSE);
		return;
	    }
#endif
	} else if (pCLServing->iState == S_IDENT &&
		   strcmp(pcCmd, "login") == 0) {
#if HAVE_OPENSSL
	    if (config->sslrequired == FLAGTRUE &&
		FileGetType(pCLServing->fd) != SSLSocket) {
		FileWrite(pCLServing->fd, "encryption required\r\n", -1);
	    } else {
#endif
		if (pcArgs == (char *)0) {
		    FileWrite(pCLServing->fd,
			      "login requires argument\r\n", -1);
		} else {
		    BuildString((char *)0, pCLServing->username);
		    BuildString((char *)0, pCLServing->acid);
		    BuildString(pcArgs, pCLServing->username);
		    BuildString(pcArgs, pCLServing->acid);
		    BuildStringChar('@', pCLServing->acid);
		    BuildString(pCLServing->peername->string,
				pCLServing->acid);
		    if (pCLServing->caccess == 't' ||
			CheckPasswd(pCLServing, "") == AUTH_SUCCESS) {
			pCLServing->iState = S_NORMAL;
			Verbose("<master> login %s",
				pCLServing->acid->string);
			FileWrite(pCLServing->fd, "ok\r\n", -1);
		    } else {
			FileWrite(pCLServing->fd, "passwd?\r\n", -1);
			pCLServing->iState = S_PASSWD;
		    }
		}
#if HAVE_OPENSSL
	    }
#endif
	} else if (pCLServing->iState == S_NORMAL &&
		   strcmp(pcCmd, "master") == 0) {
	    int iSep = 1;

	    if ((GRPENT *)0 != pGroups) {
		struct sockaddr_in lcl;
		socklen_t so = sizeof(lcl);
		if (-1 ==
		    getsockname(FileFDNum(pCLServing->fd),
				(struct sockaddr *)&lcl, &so)) {
		    FileWrite(pCLServing->fd,
			      "getsockname failed, try again later\r\n",
			      -1);
		    Error("Master(): getsockname(%u): %s",
			  FileFDNum(pCLServing->fd), strerror(errno));
		    Bye(EX_OSERR);
		}
		FilePrint(pCLServing->fd, "@%s", inet_ntoa(lcl.sin_addr));
		iSep = 0;
	    }
	    if (config->redirect == FLAGTRUE) {
		REMOTE *pRC;
		for (pRC = pRCUniq; (REMOTE *)0 != pRC; pRC = pRC->pRCuniq) {
		    FilePrint(pCLServing->fd, ":@%s" + iSep, pRC->rhost);
		    iSep = 0;
		}
	    }
	    FileWrite(pCLServing->fd, "\r\n", -1);
	} else if (pCLServing->iState == S_NORMAL &&
		   strcmp(pcCmd, "pid") == 0) {
	    FilePrint(pCLServing->fd, "%lu\r\n", (unsigned long)thepid);
	} else if (pCLServing->iState == S_NORMAL &&
		   strcmp(pcCmd, "version") == 0) {
	    FilePrint(pCLServing->fd, "version `%s'\r\n", THIS_VERSION);
	} else if (pCLServing->iState == S_NORMAL &&
		   strcmp(pcCmd, "quit") == 0) {
	    if (ConsentFindUser(pADList, pCLServing->username->string) !=
		(CONSENTUSERS *)0 ||
		ConsentFindUser(pADList, "*") != (CONSENTUSERS *)0) {
		Verbose("quit command by %s", pCLServing->acid->string);
		FileWrite(pCLServing->fd, "ok -- terminated\r\n", -1);
		DropMasterClient(pCLServing, FLAGFALSE);
		kill(thepid, SIGTERM);
		return;
	    } else
		FileWrite(pCLServing->fd, "unauthorized command\r\n", -1);
	} else if (pCLServing->iState == S_NORMAL &&
		   strcmp(pcCmd, "restart") == 0) {
	    if (ConsentFindUser(pADList, pCLServing->username->string) !=
		(CONSENTUSERS *)0 ||
		ConsentFindUser(pADList, "*") != (CONSENTUSERS *)0) {
		FileWrite(pCLServing->fd, "ok -- restarting\r\n", -1);
		Verbose("restart command by %s", pCLServing->acid->string);
		kill(thepid, SIGHUP);
	    } else
		FileWrite(pCLServing->fd, "unauthorized command\r\n", -1);
	} else if (pCLServing->iState == S_NORMAL &&
		   strcmp(pcCmd, "groups") == 0) {
	    int iSep = 1;
	    GRPENT *pGE;

	    for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
		if (0 == pGE->imembers)
		    continue;
		FilePrint(pCLServing->fd, ":%hu" + iSep, pGE->port);
		iSep = 0;
	    }
	    FileWrite(pCLServing->fd, "\r\n", -1);
	} else if (pCLServing->iState == S_NORMAL &&
		   strcmp(pcCmd, "call") == 0) {
	    if (pcArgs == (char *)0)
		FileWrite(pCLServing->fd, "call requires argument\r\n",
			  -1);
	    else
		CommandCall(pCLServing, pcArgs);
	} else {
	    FileWrite(pCLServing->fd, "unknown command\r\n", -1);
	}
	BuildString((char *)0, pCLServing->accmd);
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
    int cfd;
    int msfd;
    socklen_t so;
    fd_set rmask, wmask;
    struct sockaddr_in master_port;
    int true = 1;
    FILE *fp;
    CONSCLIENT *pCLServing = (CONSCLIENT *)0;
    CONSCLIENT *pCL = (CONSCLIENT *)0;
    CONSCLIENT *pCLall = (CONSCLIENT *)0;


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

    /* prime the free connection slots */
    if ((pCLfree = (CONSCLIENT *)calloc(1, sizeof(CONSCLIENT)))
	== (CONSCLIENT *)0)
	OutOfMem();
    pCLfree->accmd = AllocString();
    pCLfree->peername = AllocString();
    pCLfree->username = AllocString();
    pCLfree->acid = AllocString();

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

    if (!SetFlags(msfd, O_NONBLOCK, 0))
	return;

    if (bind(msfd, (struct sockaddr *)&master_port, sizeof(master_port)) <
	0) {
	Error("Master(): bind(%hu): %s", ntohs(master_port.sin_port),
	      strerror(errno));
	return;
    }
    if (listen(msfd, SOMAXCONN) < 0) {
	Error("Master(): listen(%hu): %s", ntohs(master_port.sin_port),
	      strerror(errno));
	return;
    }

    fp = fopen(PIDFILE, "w");
    if (fp) {
	fprintf(fp, "%lu\n", (unsigned long)getpid());
	fclose(fp);
    } else {
	Error("Master(): can't write pid to %s: %s", PIDFILE,
	      strerror(errno));
    }

    FD_ZERO(&rinit);
    FD_SET(msfd, &rinit);
    maxfd = msfd + 1;

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
	    ReReadCfg(msfd);
	    /* fix up the client descriptors since ReReadCfg() doesn't
	     * see them like it can in the child processes */
	    for (pCL = pCLall; pCL != (CONSCLIENT *)0; pCL = pCL->pCLscan) {
		FD_SET(FileFDNum(pCL->fd), &rinit);
		if (maxfd < FileFDNum(pCL->fd) + 1)
		    maxfd = FileFDNum(pCL->fd) + 1;
		if (!FileBufEmpty(pCL->fd))
		    FD_SET(FileFDNum(pCL->fd), &winit);
	    }
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

	/* anything on a connection? */
	for (pCLServing = pCLall; (CONSCLIENT *)0 != pCLServing;
	     pCLServing = pCLServing->pCLscan) {
	    switch (pCLServing->ioState) {
#if HAVE_OPENSSL
		case INSSLACCEPT:
		    if (FileCanSSLAccept(pCLServing->fd, &rmask, &wmask)) {
			int r;
			if ((r = FileSSLAccept(pCLServing->fd)) < 0)
			    DropMasterClient(pCLServing, FLAGFALSE);
			else if (r == 1)
			    pCLServing->ioState = ISNORMAL;
		    }
		    break;
#endif
		case ISNORMAL:
		    if (FileCanRead(pCLServing->fd, &rmask, &wmask))
			DoNormalRead(pCLServing);
		    /* fall through to ISFLUSHING for buffered data */
		case ISFLUSHING:
		    if (!FileBufEmpty(pCLServing->fd) &&
			FileCanWrite(pCLServing->fd, &rmask, &wmask)) {
			CONDDEBUG((1, "Master(): flushing fd %d",
				   FileFDNum(pCLServing->fd)));
			if (FileWrite(pCLServing->fd, (char *)0, 0) < 0) {
			    DropMasterClient(pCLServing, FLAGTRUE);
			    break;
			}
		    }
		    if ((pCLServing->ioState == ISFLUSHING) &&
			FileBufEmpty(pCLServing->fd))
			DropMasterClient(pCLServing, FLAGFALSE);
		    break;
		default:
		    /* this really can't ever happen */
		    Error
			("Master(): client socket state == %d -- THIS IS A BUG",
			 pCLServing->ioState);
		    DropMasterClient(pCLServing, FLAGFALSE);
		    break;
	    }
	}

	/* if nothing on control line, get more */
	if (!FD_ISSET(msfd, &rmask))
	    continue;

	/* accept new connections and deal with them
	 */
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	dmallocMarkClientConnection = dmalloc_mark();
#endif

	so = sizeof(struct sockaddr_in);
	for (cfd = 0; cfd == 0;) {
	    cfd =
		accept(msfd, (struct sockaddr *)&pCLfree->cnct_port, &so);
	    if (cfd < 0 && errno == EINTR)
		cfd = 0;
	}
	if (cfd < 0) {
	    Error("Master(): accept(%u): %s", msfd, strerror(errno));
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	    CONDDEBUG((1, "Master(): dmalloc / MarkClientConnection"));
	    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
	    continue;
	}

	/* set to non-blocking and wrap in a File object */
	if (SetFlags(cfd, O_NONBLOCK, 0))
	    pCLfree->fd = FileOpenFD(cfd, simpleSocket);
	else
	    pCLfree->fd = (CONSFILE *)0;

	if ((CONSFILE *)0 == pCLfree->fd) {
	    Error("Master(): FileOpenFD(%u): %s", cfd, strerror(errno));
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	    CONDDEBUG((1, "Master(): dmalloc / MarkClientConnection"));
	    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
	    continue;
	}

	/* remove from the free list */
	pCL = pCLfree;
	pCLfree = pCL->pCLnext;

	/* add another if we ran out */
	if (pCLfree == (CONSCLIENT *)0) {
	    if ((pCLfree = (CONSCLIENT *)calloc(1, sizeof(CONSCLIENT)))
		== (CONSCLIENT *)0)
		OutOfMem();
	    pCLfree->accmd = AllocString();
	    pCLfree->peername = AllocString();
	    pCLfree->username = AllocString();
	    pCLfree->acid = AllocString();
	}

	/* link into all clients list */
	pCL->pCLscan = pCLall;
	pCL->ppCLbscan = &pCLall;
	if ((CONSCLIENT *)0 != pCL->pCLscan) {
	    pCL->pCLscan->ppCLbscan = &pCL->pCLscan;
	}
	pCLall = pCL;

	FD_SET(cfd, &rinit);
	if (maxfd < cfd + 1)
	    maxfd = cfd + 1;

	/* init the fsm */
	pCL->iState = S_IDENT;
	BuildString((char *)0, pCL->accmd);
	BuildString((char *)0, pCL->peername);
	BuildString((char *)0, pCL->username);
	BuildString((char *)0, pCL->acid);

	if (ClientAccessOk(pCL)) {
	    pCL->ioState = ISNORMAL;
	    /* say hi to start */
	    FileWrite(pCL->fd, "ok\r\n", -1);
	} else
	    DropMasterClient(pCL, FLAGFALSE);
    }

    /* clean up the free list */
    while (pCLfree != (CONSCLIENT *)0) {
	pCL = pCLfree->pCLnext;
	DestroyClient(pCLfree);
	pCLfree = pCL;
    }

    unlink(PIDFILE);
}
