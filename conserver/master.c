/*
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

#include <cutil.h>
#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <master.h>
#include <readcfg.h>
#include <main.h>


static sig_atomic_t fSawQuit = 0, fSawHUP = 0, fSawUSR2 = 0, fSawUSR1 =
    0, fSawCHLD = 0;
CONSCLIENT *pCLmfree = (CONSCLIENT *)0;
CONSCLIENT *pCLmall = (CONSCLIENT *)0;
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
static unsigned long dmallocMarkClientConnection = 0;
#endif


static void
FlagSawCHLD(int sig)
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
FixKids(int msfd)
{
    pid_t pid;
    int UWbuf;
    GRPENT *pGE;

    while (-1 != (pid = waitpid(-1, &UWbuf, WNOHANG | WUNTRACED))) {
	if (0 == pid) {
	    break;
	}
	/* stopped child is just continuted
	 */
	if (WIFSTOPPED(UWbuf) && 0 == kill(pid, SIGCONT)) {
	    Msg("child pid %lu: stopped, sending SIGCONT",
		(unsigned long)pid);
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
	    Spawn(pGE, msfd);
	    Verbose("group #%d pid %lu on port %hu", pGE->id,
		    (unsigned long)pGE->pid, pGE->port);
	}
    }
}

/* kill all the kids and exit.
 * Called when master process receives SIGTERM
 */
static void
FlagQuitIt(int arg)
{
    fSawQuit = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGTERM, FlagQuitIt);
#endif
}

/* yes, this is basically the same as FlagQuitIt but we *may*
 * want to do something special on SIGINT at some point.
 */
static void
FlagSawINT(int arg)
{
    fSawQuit = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGINT, FlagSawINT);
#endif
}

static void
FlagSawHUP(int arg)
{
    fSawHUP = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGHUP, FlagSawHUP);
#endif
}

static void
FlagSawUSR2(int arg)
{
    fSawUSR2 = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGUSR2, FlagSawUSR2);
#endif
}

static void
FlagSawUSR1(int arg)
{
    fSawUSR1 = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGUSR1, FlagSawUSR1);
#endif
}

/* Signal all the kids...
 */
void
SignalKids(int arg)
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

REMOTE *
FindRemoteConsole(char *args)
{
    REMOTE *pRC;
    NAMES *name;

    for (pRC = pRCList; (REMOTE *)0 != pRC; pRC = pRC->pRCnext) {
	if (strcasecmp(args, pRC->rserver) == 0)
	    return pRC;
	for (name = pRC->aliases; name != (NAMES *)0; name = name->next) {
	    if (strcasecmp(args, name->name) == 0)
		return pRC;
	}
    }
    return pRC;
}

void
CommandCall(CONSCLIENT *pCL, char *args)
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
    if (config->redirect == FLAGTRUE ||
	(config->redirect != FLAGTRUE && found == 0)) {
	if ((pRC = FindRemoteConsole(args)) != (REMOTE *)0) {
	    ambiguous = BuildTmpString(pRC->rserver);
	    ambiguous = BuildTmpString(", ");
	    ++found;
	    pRCFound = pRC;
	}
    }
    if (found == 0 && config->autocomplete == FLAGTRUE) {
	/* Then look for substring matches */
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
	    FilePrint(pCL->fd, FLAGFALSE, "console `%s' not found\r\n",
		      args);
	    break;
	case 1:
	    if ((REMOTE *)0 != pRCFound) {
		if (config->redirect != FLAGTRUE) {
		    FilePrint(pCL->fd, FLAGFALSE,
			      "automatic redirection disabled - console on master `%s'\r\n",
			      pRCFound->rhost);
		} else {
		    FilePrint(pCL->fd, FLAGFALSE, "@%s\r\n",
			      pRCFound->rhost);
		}
	    } else {
		FilePrint(pCL->fd, FLAGFALSE, "%hu\r\n", prnum);
	    }
	    break;
	default:
	    found = strlen(ambiguous);
	    ambiguous[found - 2] = '\000';
	    FilePrint(pCL->fd, FLAGFALSE,
		      "ambiguous console abbreviation, `%s'\r\n\tchoices are %s\r\n",
		      args, ambiguous);
	    break;
    }
    BuildTmpString((char *)0);	/* we're done - clean up */
    ambiguous = (char *)0;
}

void
DropMasterClient(CONSCLIENT *pCLServing, FLAG force)
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
    pCLServing->pCLnext = pCLmfree;
    pCLmfree = pCLServing;

    /* we didn't touch pCLServing->pCLscan so the loop works */
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
    CONDDEBUG((1, "Master(): dmalloc / MarkClientConnection"));
    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
}

void
DoNormalRead(CONSCLIENT *pCLServing)
{
    char *pcCmd;
    char *pcArgs;
    int nr, i, l;
    unsigned char acIn[BUFSIZ];

    /* read connection */
    if ((nr = FileRead(pCLServing->fd, acIn, sizeof(acIn))) < 0) {
	DropMasterClient(pCLServing, FLAGFALSE);
	return;
    }

    while ((l = ParseIACBuf(pCLServing->fd, acIn, &nr)) >= 0) {
	if (l == 0)		/* we ignore special OB_IAC stuff */
	    continue;
	for (i = 0; i < l; ++i) {
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
		if (CheckPasswd
		    (pCLServing, pCLServing->accmd->string, FLAGFALSE)
		    != AUTH_SUCCESS) {
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "invalid password\r\n", -1);
		    BuildString((char *)0, pCLServing->accmd);
		    DropMasterClient(pCLServing, FLAGFALSE);
		    return;
		}
		Verbose("<master> login %s", pCLServing->acid->string);
		FileWrite(pCLServing->fd, FLAGFALSE, "ok\r\n", 4);
		pCLServing->iState = S_NORMAL;
		BuildString((char *)0, pCLServing->accmd);
		continue;
	    }

	    if ((char *)0 !=
		(pcArgs = strchr(pCLServing->accmd->string, ':'))) {
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
#if HAVE_GSSAPI
		    "gssapi log in with gssapi\r\n",
#endif
		    (char *)0
		};
		static char *apcHelp2[] = {
		    "call       provide port for given console\r\n",
		    "exit       disconnect\r\n",
		    "groups     provide ports for group leaders\r\n",
		    "help       this help message\r\n",
		    "master     provide a list of master servers\r\n",
		    "newlogs*   close and open all logfiles (SIGUSR2)\r\n",
		    "pid        provide pid of master process\r\n",
		    "quit*      terminate conserver (SIGTERM)\r\n",
		    "restart*   restart conserver (SIGHUP) - deprecated\r\n",
		    "reconfig*  reread config file (SIGHUP)\r\n",
		    "version    provide version info for server\r\n",
		    "up*        bring up all downed consoles (SIGUSR1)\r\n",
		    "* = requires admin privileges\r\n",
		    (char *)0
		};
		char **ppc;
		for (ppc =
		     (pCLServing->iState == S_IDENT ? apcHelp1 : apcHelp2);
		     (char *)0 != *ppc; ++ppc) {
		    FileWrite(pCLServing->fd, FLAGTRUE, *ppc, -1);
		}
		FileWrite(pCLServing->fd, FLAGFALSE, (char *)0, 0);
	    } else if (strcmp(pcCmd, "exit") == 0) {
		FileWrite(pCLServing->fd, FLAGFALSE, "goodbye\r\n", -1);
		DropMasterClient(pCLServing, FLAGFALSE);
		return;
#if HAVE_OPENSSL
	    } else if (pCLServing->iState == S_IDENT &&
		       strcmp(pcCmd, "ssl") == 0) {
		FileWrite(pCLServing->fd, FLAGFALSE, "ok\r\n", -1);
		if (!AttemptSSL(pCLServing)) {
		    DropMasterClient(pCLServing, FLAGFALSE);
		    return;
		}
#endif
#if HAVE_GSSAPI
	    } else if (pCLServing->iState == S_IDENT &&
		       strcmp(pcCmd, "gssapi") == 0) {
		FileWrite(pCLServing->fd, FLAGFALSE, "ok\r\n", -1);
		/* Change the I/O mode right away, we'll do the read
		 * and accept when the select gets back to us */
		pCLServing->ioState = INGSSACCEPT;
#endif
	    } else if (pCLServing->iState == S_IDENT &&
		       strcmp(pcCmd, "login") == 0) {
#if HAVE_OPENSSL
		if (config->sslrequired == FLAGTRUE &&
		    FileGetType(pCLServing->fd) != SSLSocket) {
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "encryption required\r\n", -1);
		} else {
#endif
		    if (pcArgs == (char *)0) {
			FileWrite(pCLServing->fd, FLAGFALSE,
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
			    CheckPasswd(pCLServing, "",
					FLAGTRUE) == AUTH_SUCCESS) {
			    pCLServing->iState = S_NORMAL;
			    Verbose("<master> login %s",
				    pCLServing->acid->string);
			    FileWrite(pCLServing->fd, FLAGFALSE, "ok\r\n",
				      4);
			} else {
			    FilePrint(pCLServing->fd, FLAGFALSE,
				      "passwd? %s\r\n", myHostname);
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
#if USE_IPV6 || !USE_UNIX_DOMAIN_SOCKETS
		    SOCKADDR_STYPE lcl;

		    socklen_t so = sizeof(lcl);
		    if (-1 ==
			getsockname(FileFDNum(pCLServing->fd),
				    (struct sockaddr *)&lcl, &so)) {
			FileWrite(pCLServing->fd, FLAGFALSE,
				  "getsockname failed, try again later\r\n",
				  -1);
			Error("Master(): getsockname(%u): %s",
			      FileFDNum(pCLServing->fd), strerror(errno));
			iSep = -1;
		    } else {
# if USE_IPV6
			int error;
			char addr[NI_MAXHOST];
			error =
			    getnameinfo((struct sockaddr *)&lcl, so, addr,
					sizeof(addr), NULL, 0,
					NI_NUMERICHOST);
			if (!error)
			    FilePrint(pCLServing->fd, FLAGTRUE, "@%s",
				      addr);
# else
			FilePrint(pCLServing->fd, FLAGTRUE, "@%s",
				  inet_ntoa(lcl.sin_addr));
# endif
			iSep = 0;
		    }
#else
		    FilePrint(pCLServing->fd, FLAGTRUE, "@0");
		    iSep = 0;
#endif
		}
		if (iSep >= 0) {
		    if (config->redirect == FLAGTRUE) {
			REMOTE *pRC;
			char *s;
			for (pRC = pRCUniq; (REMOTE *)0 != pRC;
			     pRC = pRC->pRCuniq) {
			    s = ":@%s";
			    s += iSep;
			    FilePrint(pCLServing->fd, FLAGTRUE, s,
				      pRC->rhost);
			    iSep = 0;
			}
		    }
		    FileWrite(pCLServing->fd, FLAGFALSE, "\r\n", -1);
		}
	    } else if (pCLServing->iState == S_NORMAL &&
		       strcmp(pcCmd, "pid") == 0) {
		FilePrint(pCLServing->fd, FLAGFALSE, "%lu\r\n",
			  (unsigned long)thepid);
	    } else if (pCLServing->iState == S_NORMAL &&
		       strcmp(pcCmd, "version") == 0) {
		FilePrint(pCLServing->fd, FLAGFALSE, "version `%s'\r\n",
			  MyVersion());
	    } else if (pCLServing->iState == S_NORMAL &&
		       strcmp(pcCmd, "quit") == 0) {
		if (ConsentUserOk(pADList, pCLServing->username->string) ==
		    1) {
		    Verbose("quit command by %s",
			    pCLServing->acid->string);
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "ok -- terminated\r\n", -1);
		    DropMasterClient(pCLServing, FLAGFALSE);
		    kill(thepid, SIGTERM);
		    return;
		} else
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "unauthorized command\r\n", -1);
	    } else if (pCLServing->iState == S_NORMAL &&
		       strcmp(pcCmd, "restart") == 0) {
		if (ConsentUserOk(pADList, pCLServing->username->string) ==
		    1) {
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "ok -- restarting\r\n", -1);
		    Verbose("restart command by %s",
			    pCLServing->acid->string);
		    kill(thepid, SIGHUP);
		} else
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "unauthorized command\r\n", -1);
	    } else if (pCLServing->iState == S_NORMAL &&
		       strcmp(pcCmd, "reconfig") == 0) {
		if (ConsentUserOk(pADList, pCLServing->username->string) ==
		    1) {
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "ok -- reconfiguring\r\n", -1);
		    Verbose("reconfig command by %s",
			    pCLServing->acid->string);
		    kill(thepid, SIGHUP);
		} else
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "unauthorized command\r\n", -1);
	    } else if (pCLServing->iState == S_NORMAL &&
		       strcmp(pcCmd, "up") == 0) {
		if (ConsentUserOk(pADList, pCLServing->username->string) ==
		    1) {
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "ok -- bringing up consoles\r\n", -1);
		    Verbose("up command by %s", pCLServing->acid->string);
		    kill(thepid, SIGUSR1);
		} else
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "unauthorized command\r\n", -1);
	    } else if (pCLServing->iState == S_NORMAL &&
		       strcmp(pcCmd, "newlogs") == 0) {
		if (ConsentUserOk(pADList, pCLServing->username->string) ==
		    1) {
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "ok -- opening new logfiles\r\n", -1);
		    Verbose("newlogs command by %s",
			    pCLServing->acid->string);
		    kill(thepid, SIGUSR2);
		} else
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "unauthorized command\r\n", -1);
	    } else if (pCLServing->iState == S_NORMAL &&
		       strcmp(pcCmd, "groups") == 0) {
		int iSep = 1;
		GRPENT *pGE;
		char *s;

		for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
		    if (0 == pGE->imembers)
			continue;
		    s = ":%hu";
		    s += iSep;
		    FilePrint(pCLServing->fd, FLAGTRUE, s, pGE->port);
		    iSep = 0;
		}
		FileWrite(pCLServing->fd, FLAGFALSE, "\r\n", 2);
	    } else if (pCLServing->iState == S_NORMAL &&
		       strcmp(pcCmd, "call") == 0) {
		if (pcArgs == (char *)0)
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "call requires argument\r\n", -1);
		else
		    CommandCall(pCLServing, pcArgs);
	    } else {
		FileWrite(pCLServing->fd, FLAGFALSE, "unknown command\r\n",
			  -1);
	    }
	    BuildString((char *)0, pCLServing->accmd);
	}
	nr -= l;
	MemMove(acIn, acIn + l, nr);
    }
}

/* this routine is used by the master console server process		(ksb)
 */
void
Master(void)
{
    int cfd;
    int msfd;
    socklen_t so;
    fd_set rmask, wmask;
#if USE_IPV6 || !USE_UNIX_DOMAIN_SOCKETS
# if USE_IPV6
    struct addrinfo *rp;
# else
    struct sockaddr_in master_port;
# endif
# if HAVE_SETSOCKOPT
    int sock_opt_true = 1;
# endif
#else
    struct sockaddr_un master_port;
    static STRING *portPath = (STRING *)0;
#endif
    FILE *fp;
    CONSCLIENT *pCLServing = (CONSCLIENT *)0;
    CONSCLIENT *pCL = (CONSCLIENT *)0;


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
#if defined(SIGXFSZ)
    SimpleSignal(SIGXFSZ, SIG_IGN);
#endif
    SimpleSignal(SIGCHLD, FlagSawCHLD);
    SimpleSignal(SIGTERM, FlagQuitIt);
    SimpleSignal(SIGUSR1, FlagSawUSR1);
    SimpleSignal(SIGHUP, FlagSawHUP);
    SimpleSignal(SIGUSR2, FlagSawUSR2);
    SimpleSignal(SIGINT, FlagSawINT);

    /* prime the free connection slots */
    if ((pCLmfree = (CONSCLIENT *)calloc(1, sizeof(CONSCLIENT)))
	== (CONSCLIENT *)0)
	OutOfMem();
    pCLmfree->accmd = AllocString();
    pCLmfree->peername = AllocString();
    pCLmfree->username = AllocString();
    pCLmfree->acid = AllocString();

    /* set up port for master to listen on
     */
#if !USE_IPV6
# if HAVE_MEMSET
    memset((void *)&master_port, 0, sizeof(master_port));
# else
    bzero((char *)&master_port, sizeof(master_port));
# endif
#endif

#if USE_IPV6
    for (rp = bindAddr; rp != NULL; rp = rp->ai_next) {
	if ((msfd =
	     socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0)
	    continue;

# if HAVE_SETSOCKOPT
	if (setsockopt
	    (msfd, SOL_SOCKET, SO_REUSEADDR, (char *)&sock_opt_true,
	     sizeof(sock_opt_true)) < 0)
	    goto fail;
# endif
	if (!SetFlags(msfd, O_NONBLOCK, 0))
	    goto fail;

	if (bind(msfd, rp->ai_addr, rp->ai_addrlen) == 0)
	    break;

      fail:
	close(msfd);
    }

    if (listen(msfd, SOMAXCONN) < 0) {
	Error("Master(): listen(): %s", strerror(errno));
	return;
    }

    /* save addrlen for accept */
    so = rp->ai_addrlen;
#elif USE_UNIX_DOMAIN_SOCKETS
    master_port.sun_family = AF_UNIX;

    if (portPath == (STRING *)0)
	portPath = AllocString();
    BuildStringPrint(portPath, "%s/0", interface);
    if (portPath->used > sizeof(master_port.sun_path)) {
	Error("Master(): path to socket too long: %s", portPath->string);
	return;
    }
    StrCpy(master_port.sun_path, portPath->string,
	   sizeof(master_port.sun_path));

    if ((msfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	Error("Master(): socket(AF_UNIX,SOCK_STREAM): %s",
	      strerror(errno));
	return;
    }

    if (!SetFlags(msfd, O_NONBLOCK, 0))
	return;

    if (bind(msfd, (struct sockaddr *)&master_port, sizeof(master_port)) <
	0) {
	Error("Master(): bind(%s): %s", master_port.sun_path,
	      strerror(errno));
	return;
    }
    if (listen(msfd, SOMAXCONN) < 0) {
	Error("Master(): listen(%s): %s", master_port.sun_path,
	      strerror(errno));
	return;
    }
# ifdef TRUST_UDS_CRED
    /* Allow everyone to connect, but we later auth them via SO_PEERCRED */
    chmod(master_port.sun_path, 0666);
# endif

#else
    master_port.sin_family = AF_INET;
    master_port.sin_addr.s_addr = bindAddr;
    master_port.sin_port = htons(bindPort);

    if ((msfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	Error("Master(): socket(AF_INET,SOCK_STREAM): %s",
	      strerror(errno));
	return;
    }
# if HAVE_SETSOCKOPT
    if (setsockopt
	(msfd, SOL_SOCKET, SO_REUSEADDR, (char *)&sock_opt_true,
	 sizeof(sock_opt_true)) < 0) {
	Error("Master(): setsockopt(%u,SO_REUSEADDR): %s", msfd,
	      strerror(errno));
	return;
    }
# endif

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
#endif

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
	    FixKids(msfd);
	}
	if (fSawHUP) {
	    fSawHUP = 0;
	    Msg("processing SIGHUP");
	    ReopenLogfile();
	    ReopenUnifiedlog();
	    SignalKids(SIGHUP);
	    ReReadCfg(msfd, msfd);
	    /* fix up the client descriptors since ReReadCfg() doesn't
	     * see them like it can in the child processes */
	    for (pCL = pCLmall; pCL != (CONSCLIENT *)0; pCL = pCL->pCLscan) {
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
	    ReopenUnifiedlog();
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
	for (pCLServing = pCLmall; (CONSCLIENT *)0 != pCLServing;
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
#if HAVE_GSSAPI
		case INGSSACCEPT:
		    {
			int r;
			if ((r = AttemptGSSAPI(pCLServing)) < 0)
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
			if (FileWrite
			    (pCLServing->fd, FLAGFALSE, (char *)0, 0)
			    < 0) {
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

#if !USE_IPV6
	so = sizeof(struct sockaddr_in);
#endif
	for (cfd = 0; cfd == 0;) {
	    cfd =
		accept(msfd, (struct sockaddr *)&pCLmfree->cnct_port, &so);
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
	if (SetFlags(cfd, O_NONBLOCK, 0)) {
	    pCLmfree->fd = FileOpenFD(cfd, simpleSocket);
	    FileSetQuoteIAC(pCLmfree->fd, FLAGTRUE);
	} else
	    pCLmfree->fd = (CONSFILE *)0;

	if ((CONSFILE *)0 == pCLmfree->fd) {
	    Error("Master(): FileOpenFD(%u): %s", cfd, strerror(errno));
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	    CONDDEBUG((1, "Master(): dmalloc / MarkClientConnection"));
	    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
	    continue;
	}

	/* remove from the free list */
	pCL = pCLmfree;
	pCLmfree = pCL->pCLnext;

	/* add another if we ran out */
	if (pCLmfree == (CONSCLIENT *)0) {
	    if ((pCLmfree = (CONSCLIENT *)calloc(1, sizeof(CONSCLIENT)))
		== (CONSCLIENT *)0)
		OutOfMem();
	    pCLmfree->accmd = AllocString();
	    pCLmfree->peername = AllocString();
	    pCLmfree->username = AllocString();
	    pCLmfree->acid = AllocString();
	}

	/* link into all clients list */
	pCL->pCLscan = pCLmall;
	pCL->ppCLbscan = &pCLmall;
	if ((CONSCLIENT *)0 != pCL->pCLscan) {
	    pCL->pCLscan->ppCLbscan = &pCL->pCLscan;
	}
	pCLmall = pCL;

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
	    FileWrite(pCL->fd, FLAGFALSE, "ok\r\n", 4);
	} else
	    DropMasterClient(pCL, FLAGFALSE);
    }

    close(msfd);
#if USE_UNIX_DOMAIN_SOCKETS
    unlink(master_port.sun_path);
#endif

    /* clean up the free list */
    while (pCLmfree != (CONSCLIENT *)0) {
	pCL = pCLmfree->pCLnext;
	DestroyClient(pCLmfree);
	pCLmfree = pCL;
    }

    unlink(PIDFILE);
}
