/*
 *  $Id: group.c,v 5.126 2001-07-26 11:50:13-07 bryan Exp $
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
 *
 *
 * Copyright 1992 Purdue Research Foundation, West Lafayette, Indiana
 * 47907.  All rights reserved.
 *
 * Recoded by Kevin S Braunsdorf, ksb@cc.purdue.edu, purdue!ksb
 *
 * This software is not subject to any license of the American Telephone
 * and Telegraph Company or the Regents of the University of California.
 *
 * Permission is granted to anyone to use this software for any purpose on
 * any computer system, and to alter it and redistribute it freely, subject
 * to the following restrictions:
 *
 * 1. Neither the authors nor Purdue University are responsible for any
 *    consequences of the use of this software.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Credit to the authors and Purdue
 *    University must appear in documentation and sources.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 *
 * 4. This notice may not be removed or altered.
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
#include <varargs.h>
#define TELCMDS
#define TELOPTS
#include <arpa/telnet.h>

#include <compat.h>
#include <port.h>
#include <util.h>

#include <consent.h>
#include <client.h>
#include <access.h>
#include <group.h>
#include <version.h>
#include <readcfg.h>
#include <main.h>


/* flags that a signal has occurred */
static sig_atomic_t fSawReOpen = 0, fSawReUp = 0, fSawMark =
    0, fSawGoAway = 0, fSawReapVirt = 0;

/* Is this passwd a match for this user's passwd? 		(gregf/ksb)
 * look up passwd in shadow file if we have to, if we are
 * given a special epass try it first.
 */
int
CheckPass(pwd, pcEPass, pcWord)
    struct passwd *pwd;
    char *pcEPass, *pcWord;
{
#if HAVE_GETSPNAM
    struct spwd *spwd;
#endif

    if ((char *)0 != pcEPass && '\000' != pcEPass[0]) {
	if (0 == strcmp(pcEPass, crypt(pcWord, pcEPass))) {
	    return 1;
	}
    }
#if HAVE_GETSPNAM
    if ('x' == pwd->pw_passwd[0] && '\000' == pwd->pw_passwd[1]) {
	if ((struct spwd *)0 != (spwd = getspnam(pwd->pw_name)))
	    return 0 == strcmp(spwd->sp_pwdp,
			       crypt(pcWord, spwd->sp_pwdp));
	return 0;
    }
#endif
    return 0 == strcmp(pwd->pw_passwd, crypt(pcWord, pwd->pw_passwd));
}

/* This returns a string with the current time in ascii form.
 * (same as ctime() but without the \n)
 * optionally returns the time in time_t form (pass in NULL if you don't care).
 * It's overwritten each time, so use it and forget it.
 */
char curtime[25];

const char *
strtime(ltime)
    time_t *ltime;
{
    time_t tyme;

    tyme = time((time_t *) 0);
    (void)strcpy(curtime, ctime(&tyme));
    curtime[24] = '\000';
    if (ltime != NULL)
	*ltime = tyme;
    return (const char *)curtime;
}

/* on an HUP close and re-open log files so lop can trim them		(ksb)
 * lucky for us: log file fd's can change async from the group driver!
 */
static RETSIGTYPE
FlagReOpen(sig)
    int sig;
{
    fSawReOpen = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGHUP, FlagReOpen);
#endif
}

static void
ReOpen(pGE, prinit)
    GRPENT *pGE;
    fd_set *prinit;
{
    int i;
    CONSENT *pCE;

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    for (i = 0, pCE = pGE->pCElist; i < pGE->imembers; ++i, ++pCE) {
	if ((CONSFILE *) 0 == pCE->fdlog) {
	    continue;
	}
	(void)fileClose(pCE->fdlog);
	if ((CONSFILE *) 0 ==
	    (pCE->fdlog =
	     fileOpen(pCE->lfile, O_RDWR | O_CREAT | O_APPEND, 0666))) {
	    Error("Cannot reopen log file: %s", pCE->lfile);
	    continue;
	}
    }
}

static RETSIGTYPE
FlagReUp(sig)
    int sig;
{
    fSawReUp = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGUSR1, FlagReUp);
#endif
}

static void
ReUp(pGE, prinit)
    GRPENT *pGE;
    fd_set *prinit;
{
    int i;
    CONSENT *pCE;

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    for (i = 0, pCE = pGE->pCElist; i < pGE->imembers; ++i, ++pCE) {
	if (pCE->fup) {
	    continue;
	}
	if (fNoinit)
	    continue;
	ConsInit(pCE, prinit, 1);
    }
}

static RETSIGTYPE
FlagMark(sig)
    int sig;
{
    fSawMark = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGALRM, FlagMark);
#endif
}

void
tagLogfile(pCE, fmt, va_alist)
    const CONSENT *pCE;
    const char *fmt;
    va_dcl
{
    char ac[BUFSIZ];
    char acOut[BUFSIZ];
    va_list ap;
    va_start(ap);

    if ((pCE == (CONSENT *) 0) || (pCE->fdlog == (CONSFILE *) 0) ||
	(pCE->activitylog == 0))
	return;

    vsprintf(ac, fmt, ap);
    sprintf(acOut, "[-- %s -- %s]\r\n", ac, strtime(NULL));
    (void)fileWrite(pCE->fdlog, acOut, -1);
    va_end(ap);
}

static void
Mark(pGE, prinit)
    GRPENT *pGE;
    fd_set *prinit;
{
    char acOut[BUFSIZ];
    time_t tyme;
    int i;
    CONSENT *pCE;

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    /* [-- MARK -- `date`] */
    sprintf(acOut, "[-- MARK -- %s]\r\n", strtime(&tyme));

    for (i = 0, pCE = pGE->pCElist; i < pGE->imembers; ++i, ++pCE) {
	if ((CONSFILE *) 0 == pCE->fdlog) {
	    continue;
	}
	if ((pCE->nextMark > 0) && (tyme >= pCE->nextMark)) {
	    Debug("[-- MARK --] stamp added to %s", pCE->lfile);
	    (void)fileWrite(pCE->fdlog, acOut, -1);
	    pCE->nextMark = tyme + pCE->mark;
	}
    }
    alarm(ALARMTIME);
}

void
writeLog(pCE, s, len)
    CONSENT *pCE;
    char *s;
    int len;
{
    char acOut[BUFSIZ];
    int i = 0;
    int j;

    if ((CONSFILE *) 0 == pCE->fdlog) {
	return;
    }
    if (pCE->mark >= 0) {	/* no line marking */
	(void)fileWrite(pCE->fdlog, s, len);
	return;
    }
    acOut[0] = '\000';
    for (j = 0; j < len; j++) {
	if (s[j] == '\n') {
	    Debug("Found newline for %s (nextMark=%d, mark=%d)",
		  pCE->server, pCE->nextMark, pCE->mark);
	    (void)fileWrite(pCE->fdlog, s + i, j - i + 1);
	    i = j + 1;
	    if (acOut[0] == '\000') {
		sprintf(acOut, "[%s]", strtime(NULL));
	    }
	    (void)fileWrite(pCE->fdlog, acOut, -1);
	}
    }
    if (i < j) {
	(void)fileWrite(pCE->fdlog, s + i, j - i);
    }
}

void
SendClientsMsg(pGE, message)
    GRPENT *pGE;
    char *message;
{
    CONSCLIENT *pCL;

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    for (pCL = pGE->pCLall; (CONSCLIENT *) 0 != pCL; pCL = pCL->pCLscan) {
	if (pCL->fcon) {
	    (void)fileWrite(pCL->fd, message, -1);
	}
    }
}

void
SendShutdownMsg(pGE)
    GRPENT *pGE;
{
    SendClientsMsg(pGE, "[-- Console server shutting down --]\r\n");
}

static RETSIGTYPE
FlagGoAway(sig)
    int sig;
{
    fSawGoAway = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGTERM, FlagGoAway);
#endif
}

/* yep, basically the same...ah well, maybe someday */
static RETSIGTYPE
FlagGoAwayAlso(sig)
    int sig;
{
    fSawGoAway = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGINT, FlagGoAwayAlso);
#endif
}

#if HAVE_SIGACTION
static
#endif
  RETSIGTYPE
FlagReapVirt(sig)
    int sig;
{
    fSawReapVirt = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGCHLD, FlagReapVirt);
#endif
}

/* on a TERM we have to cleanup utmp entries (ask ptyd to do it)	(ksb)
 */
static void
DeUtmp(pGE, prinit)
    GRPENT *pGE;
    fd_set *prinit;
{
    int i;
    CONSENT *pCE;

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    SendShutdownMsg(pGE);

    for (i = 0, pCE = pGE->pCElist; i < pGE->imembers; ++i, ++pCE) {
	ConsDown(pCE, prinit);
    }
    exit(EX_OK);
}

/* virtual console procs are our kids, when they die we get a CHLD	(ksb)
 * which will send us here to clean up the exit code.  The lack of a
 * reader on the pseudo will cause us to notice the death in Kiddie...
 */
static void
ReapVirt(pGE, prinit)
    GRPENT *pGE;
    fd_set *prinit;
{
    int pid;
    int UWbuf;
    int i;
    CONSENT *pCE;

    while (-1 != (pid = waitpid(-1, &UWbuf, WNOHANG))) {
	if (0 == pid) {
	    break;
	}
	/* stopped child is just continued
	 */
	if (WIFSTOPPED(UWbuf) && 0 == kill(pid, SIGCONT)) {
	    continue;
	}

	if ((GRPENT *) 0 == pGE) {
	    continue;
	}

	for (i = 0, pCE = pGE->pCElist; i < pGE->imembers; ++i, ++pCE) {

	    if (pid != pCE->ipid)
		continue;

	    if (WIFEXITED(UWbuf))
		Info("%s: exit(%d) [%s]", pCE->server, WEXITSTATUS(UWbuf),
		     strtime(NULL));
	    if (WIFSIGNALED(UWbuf))
		Info("%s: signal(%d) [%s]", pCE->server, WTERMSIG(UWbuf),
		     strtime(NULL));

	    /* If someone was writing, they fall back to read-only */
	    if (pCE->pCLwr != (CONSCLIENT *) 0) {
		pCE->pCLwr->fwr = 0;
		tagLogfile(pCE, "%s detached",
			   pCE->pCLwr->acid);
		pCE->pCLwr = (CONSCLIENT *) 0;
	    }

	    ConsDown(pCE, prinit);
	}
    }
}

static char acStop[] = {	/* buffer for oob stop command          */
    OB_SUSP, 0
};

int
CheckPasswd(pCLServing, pw_string)
    CONSCLIENT *pCLServing;
    char *pw_string;
{
    struct passwd *pwd;
    FILE *fp;
    char buf[BUFSIZ];
    char *server, *servers, *this_pw, *user;
    char username[64];		/* same as acid */
#if HAVE_GETSPNAM
    struct spwd *spwd;
#endif

    strcpy(username, pCLServing->acid);
    if ((user = strchr(username, '@')))
	*user = '\000';

    if ((fp = fopen(pcPasswd, "r")) == NULL) {
	Info("Cannot open passwd file %s: %s", pcPasswd, strerror(errno));

	if ((struct passwd *)0 == (pwd = getpwuid(0))) {
	    fileWrite(pCLServing->fd, "no root passwd?\r\n", -1);
	    return 0;
	}
	if (0 != CheckPass(pwd, pw_string, pCLServing->accmd)) {
	    if (fVerbose) {
		Info("User %s logging into server %s via root or console passwd", pCLServing->acid, pCLServing->pCEwant->server);
	    }
	    return 1;
	}
    } else {
	while (fgets(buf, sizeof(buf), fp) != NULL) {
	    user = strtok(buf, ":\n");
	    if (user == NULL)
		continue;
	    if (!
		(strcmp(user, "*any*") == 0 ||
		 strcmp(user, username) == 0))
		continue;
	    this_pw = strtok(NULL, ":\n");
	    if (strcmp(this_pw, "*passwd*") == 0) {
		this_pw = NULL;
		if ((struct passwd *)0 != (pwd = getpwnam(username))) {
#if HAVE_GETSPNAM
		    if ('x' == pwd->pw_passwd[0] &&
			'\000' == pwd->pw_passwd[1]) {
			if ((struct spwd *)0 !=
			    (spwd = getspnam(pwd->pw_name))) {
			    this_pw = spwd->sp_pwdp;
			}
		    } else {
			this_pw = pwd->pw_passwd;
		    }
#else
		    this_pw = pwd->pw_passwd;
#endif
		}
	    }
	    if (this_pw == NULL)
		break;
	    servers = strtok(NULL, ":\n");
	    if (servers == NULL)
		break;

	    /*
	       printf("Got servers <%s> passwd <%s> user <%s>, want <%s>\n",
	       servers, this_pw, user,
	       pCLServing->pCEwant->server);
	     */

	    if (strcmp(this_pw, crypt(pCLServing->accmd, this_pw)) == 0) {
		server = strtok(servers, ", \t\n");
		while (server) {	/* For each server */
		    if (strcmp(server, "any") == 0) {
			if (fVerbose) {
			    Info("User %s logging into server %s",
				 pCLServing->acid,
				 pCLServing->pCEwant->server);
			}
			fclose(fp);
			return 1;
		    } else {
			char *p;
			int max;
			max = strlen(server);
			p = pCLServing->pCEwant->server;
			while (strlen(p) >= max) {
			    if (strcmp(server, p) == 0) {
				if (fVerbose) {
				    Info("User %s logging into server %s",
					 pCLServing->acid,
					 pCLServing->pCEwant->server);
				}
				fclose(fp);
				return 1;
			    }
			    if (domainHack) {
				p = strchr(p, '.');
				if ((char *)0 == p) {
				    break;
				}
				++p;
			    } else {
				break;
			    }
			}
		    }
		    server = strtok(NULL, ", \t\n");
		}
	    }
	    fclose(fp);
	    return 0;
	}
	fclose(fp);
    }

    return 0;
}

static char *
IdleTyme(tyme)
    long tyme;
{
    static char timestr[256];	/* Don't want to overrun the array... */
    long hours, minutes;

    minutes = tyme / 60;
    hours = minutes / 60;
    minutes = minutes % 60;

    if (hours < 24)
	sprintf(timestr, "%2ld:%02ld", hours, minutes);
    else if (hours < 48)
	sprintf(timestr, "%ld day", hours / 24);
    else
	sprintf(timestr, "%lddays", hours / 24);

    return timestr;
}

/* routine used by the child processes.				   (ksb/fine)
 * Most of it is escape sequence parsing.
 * fine:
 *	All of it is squirrely code, for which I most humbly apologize
 * ksb:
 *	Note the states a client can be in, all of the client processing
 *	is done one character at a time, we buffer and shift a lot -- this
 *	stops the denial of services attack where a user telnets to the
 *	group port and just hangs it (by not following the protocol).  I've
 *	repaired this by letting all new clients on a bogus console that is
 *	a kinda control line for the group. They have to use the `;'
 *	command to shift to a real console before they can get any (real)
 *	thrills.
 *
 *	If you were not awake in your finite state machine course this code 
 *	should scare the shit out of you; but there are a few invarients:
 *		- the fwr (I can write) bit always is set *after* the
 *		  notification that to the console (and reset before)
 *		- we never look at more than one character at a time, even
 *		  when we read a hunk from the MUX we string it out in a loop
 *		- look at the output (x, u, w) and attach (a, f, ;) commands
 *		  for more clues
 *
 *	NB: the ZZZ markers below indicate places where I didn't have time
 *	    (machine?) to test some missing bit of tty diddling, I'd love
 *	    patches for other ioctl/termio/termios stuff -- ksb
 *		
 */
static void
Kiddie(pGE, sfd)
    GRPENT *pGE;
    CONSFILE *sfd;
{
    CONSCLIENT *pCL,		/* console we must scan/notify          */
     *pCLServing,		/* client we are serving                */
     *pCLFree;			/* head of free list                    */
    CONSENT *pCEServing,	/* console we are talking to            */
     *pCE;			/* the base of our console list         */
    int iConsole;
    int i, nr;
    struct hostent *hpPeer;
    long tyme;
    int fd;
    CONSENT CECtl;		/* our control `console'        */
    char cType;
    int maxfd, so;
    fd_set rmask, rinit;
    unsigned char acOut[BUFSIZ], acIn[BUFSIZ], acInOrig[BUFSIZ],
	acNote[132 * 2];
    CONSCLIENT dude[MAXMEMB];	/* alloc one set per console    */
#if HAVE_TERMIOS_H
    struct termios sbuf;
#else
# if HAVE_SGTTY_H
    struct sgttyb sty;
# endif
#endif

    /* turn off signals that master() might have turned on
     * (only matters if respawned)
     */
    simpleSignal(SIGURG, SIG_DFL);
    simpleSignal(SIGTERM, FlagGoAway);
    simpleSignal(SIGCHLD, FlagReapVirt);
    if (!fDaemon)
	simpleSignal(SIGINT, FlagGoAwayAlso);

    /* setup our local data structures and fields, and control line
     */
    pCE = pGE->pCElist;
    for (iConsole = 0; iConsole < pGE->imembers; ++iConsole) {
	pCE[iConsole].fup = 0;
	pCE[iConsole].pCLon = pCE[iConsole].pCLwr = (CONSCLIENT *) 0;
	pCE[iConsole].fdlog = (CONSFILE *) 0;
	pCE[iConsole].fdtty = -1;
    }
    sprintf(CECtl.server, "ctl_%d", pGE->port);
    CECtl.inamelen = strlen(CECtl.server);	/* bogus, of course     */
    CECtl.acline[CECtl.inamelen++] = ':';
    CECtl.acline[CECtl.inamelen++] = ' ';
    CECtl.iend = CECtl.inamelen;
    (void)strcpy(CECtl.dfile, strcpy(CECtl.lfile, "/dev/null"));
    /* below "" gets us the default parity and baud structs
     */
    CECtl.pbaud = FindBaud("");
    CECtl.pparity = FindParity("");
    CECtl.fdlog = (CONSFILE *) 0;
    CECtl.fdtty = -1;
    CECtl.fup = 0;
    CECtl.pCLon = CECtl.pCLwr = (CONSCLIENT *) 0;

    /* set up stuff for the select() call once, then just copy it
     * rinit is all the fd's we might get data on, we copy it
     * to rmask before we call select, this saves lots of prep work
     * we used to do in the loop, but we have to mod rinit whenever
     * we add a connection or drop one...   (ksb)
     */
    maxfd = maxfiles();
    FD_ZERO(&rinit);
    FD_SET(fileFDNum(sfd), &rinit);
    /* open all the files we need for the consoles in our group
     * if we can't get one (bitch and) flag as down
     */
    if (!fNoinit)
	for (iConsole = 0; iConsole < pGE->imembers; ++iConsole) {
	    ConsInit(&pCE[iConsole], &rinit, 1);
	}

    /* set up the list of free connection slots, we could just calloc
     * them, but the stack pages are already in core...
     */
    pCLFree = dude;
    for (i = 0; i < MAXMEMB - 1; ++i) {
	dude[i].pCLnext = &dude[i + 1];
    }
    dude[MAXMEMB - 1].pCLnext = (CONSCLIENT *) 0;

    /* on a SIGHUP we should close and reopen our log files
     */
    simpleSignal(SIGHUP, FlagReOpen);

    /* on a SIGUSR1 we try to bring up all downed consoles */
    simpleSignal(SIGUSR1, FlagReUp);

    /* on a SIGALRM we should mark log files */
    simpleSignal(SIGALRM, FlagMark);
    alarm(ALARMTIME);

    /* the MAIN loop a group server
     */
    pGE->pCLall = (CONSCLIENT *) 0;
    while (1) {
	/* check signal flags */
	if (fSawGoAway) {
	    fSawGoAway = 0;
	    DeUtmp(pGE, &rinit);
	}
	if (fSawReapVirt) {
	    fSawReapVirt = 0;
	    ReapVirt(pGE, &rinit);
	}
	if (fSawReOpen) {
	    fSawReOpen = 0;
	    reopenLogfile();
	    ReOpen(pGE, &rinit);
	}
	if (fSawReUp) {
	    fSawReUp = 0;
	    ReUp(pGE, &rinit);
	}
	if (fSawMark) {
	    fSawMark = 0;
	    Mark(pGE, &rinit);
	}

	rmask = rinit;

	if (-1 ==
	    select(maxfd, &rmask, (fd_set *) 0, (fd_set *) 0,
		   (struct timeval *)0)) {
	    if (errno != EINTR) {
		Error("select: %s", strerror(errno));
	    }
	    continue;
	}

	/* anything from any console?
	 */
	for (iConsole = 0; iConsole < pGE->imembers; ++iConsole) {
	    pCEServing = pCE + iConsole;
	    if (!pCEServing->fup || !FD_ISSET(pCEServing->fdtty, &rmask)) {
		continue;
	    }
	    /* read terminal line */
	    if ((nr =
		 read(pCEServing->fdtty, acInOrig,
		      sizeof(acInOrig))) <= 0) {
		/* carrier lost */
		Error("lost carrier on %s (%s)!", pCEServing->server,
		      pCEServing->fvirtual ? pCEServing->
		      acslave : pCEServing->dfile);

		/* If someone was writing, they fall back to read-only */
		if (pCEServing->pCLwr != (CONSCLIENT *) 0) {
		    pCEServing->pCLwr->fwr = 0;
		    tagLogfile(pCEServing, "%s detached",
			       pCEServing->pCLwr->acid);
		    pCEServing->pCLwr = (CONSCLIENT *) 0;
		}

		/*ConsInit(pCEServing, &rinit, 0); */
		ConsDown(pCEServing, &rinit);

		continue;
	    }
	    Debug("Read %d bytes from fd %d", nr, pCEServing->fdtty);

	    if (pCEServing->isNetworkConsole) {
		/* Do a little Telnet Protocol interpretation
		 * state = 0: normal
		 *       = 1: Saw a IAC char
		 *       = 2: Saw a DONT/DO/WONT/WILL command
		 *       = 5: Saw a \r
		 */
		int new = 0, state;
		state = pCEServing->telnetState;
		for (i = 0; i < nr; ++i) {
		    if (state == 0 && acInOrig[i] == IAC) {
			Debug("%s: Got telnet `IAC'", pCEServing->server);
			state = 1;
		    } else if (state == 1 && acInOrig[i] != IAC) {
			if (TELCMD_OK(acInOrig[i]))
			    Debug("%s: Got telnet cmd `%s'",
				  pCEServing->server, TELCMD(acInOrig[i]));
			else
			    Debug("%s: Got unknown telnet cmd `%u'",
				  pCEServing->server, acInOrig[i]);
			if (acInOrig[i] == DONT || acInOrig[i] == DO ||
			    acInOrig[i] == WILL || acInOrig[i] == WONT)
			    state = 2;
			else
			    state = 0;
		    } else if (state == 2) {
			if (TELOPT_OK(acInOrig[i]))
			    Debug("%s: Got telnet option `%s'",
				  pCEServing->server, TELOPT(acInOrig[i]));
			else
			    Debug("%s: Got unknown telnet option `%u'",
				  pCEServing->server, acInOrig[i]);
			state = 0;
		    } else {
			if (state == 5) {
			    state = 0;
			    if (acInOrig[i] == '\000')
				continue;
			}
			if (acInOrig[i] == IAC)
			    Debug("%s: Quoted `IAC'", pCEServing->server);
			if (fStrip)
			    acIn[new++] = acInOrig[i] & 127;
			else
			    acIn[new++] = acInOrig[i];
			if (acInOrig[i] == '\r')
			    state = 5;
			else
			    state = 0;
		    }
		}
		pCEServing->telnetState = state;
		nr = new;
	    } else {
		for (i = 0; i < nr; ++i) {
		    if (fStrip)
			acIn[i] = acInOrig[i] & 127;
		    else
			acIn[i] = acInOrig[i];
		}
	    }
	    if (nr == 0)
		continue;

	    /* log it and write to all connections on this server
	     */
	    if (!pCEServing->nolog) {
		(void)writeLog(pCEServing, acIn, nr);
	    }

	    /* output all console info nobody is attached
	     */
	    if (fAll && (CONSCLIENT *) 0 == pCEServing->pCLwr) {
		/* run through the console ouptut,
		 * add each character to the output line
		 * drop and reset if we have too much
		 * or are at the end of a line (ksb)
		 */
		for (i = 0; i < nr; ++i) {
		    pCEServing->acline[pCEServing->iend++] = acIn[i];
		    if (pCEServing->iend < sizeof(pCEServing->acline) &&
			'\n' != acIn[i]) {
			continue;
		    }
		    write(1, pCEServing->acline, pCEServing->iend);
		    pCEServing->iend = pCEServing->inamelen;
		}
	    }

	    /* write console info to clients (not suspended)
	     */
	    for (pCL = pCEServing->pCLon; (CONSCLIENT *) 0 != pCL;
		 pCL = pCL->pCLnext) {
		if (pCL->fcon) {
		    (void)fileWrite(pCL->fd, acIn, nr);
		}
	    }
	}


	/* anything from a connection?
	 */
	for (pCLServing = pGE->pCLall; (CONSCLIENT *) 0 != pCLServing;
	     pCLServing = pCLServing->pCLscan) {
	    if (!FD_ISSET(fileFDNum(pCLServing->fd), &rmask)) {
		continue;
	    }
	    pCEServing = pCLServing->pCEto;

	    /* read connection */
	    if ((nr = fileRead(pCLServing->fd, acIn, sizeof(acIn))) == 0) {
		/* reached EOF - close connection */
	      drop:
		/* re-entry point to drop a connection
		 * (for any other reason)
		 * log it, drop from select list,
		 * close gap in table, restart loop
		 */
		if (&CECtl != pCEServing) {
		    Info("%s: logout %s [%s]", pCEServing->server,
			 pCLServing->acid, strtime(NULL));
		}
		if (fNoinit &&
		    (CONSCLIENT *) 0 == pCLServing->pCEto->pCLon->pCLnext)
		    ConsDown(pCLServing->pCEto, &rinit);

		FD_CLR(fileFDNum(pCLServing->fd), &rinit);
		(void)fileClose(pCLServing->fd);
		pCLServing->fd = (CONSFILE *) 0;

		/* mark as not writer, if he is
		 * and turn logging back on...
		 */
		if (pCLServing->fwr) {
		    pCLServing->fwr = 0;
		    pCLServing->fwantwr = 0;
		    tagLogfile(pCEServing, "%s detached",
			       pCLServing->acid);
		    if (pCEServing->nolog) {
			pCEServing->nolog = 0;
			sprintf(acOut,
				"[Console logging restored (logout)]\r\n");
			(void)fileWrite(pCEServing->fdlog, acOut, -1);
		    }
		    pCEServing->pCLwr = FindWrite(pCEServing->pCLon);
		}

		/* mark as unconnected and remove from both
		 * lists (all clients, and this console)
		 */
		pCLServing->fcon = 0;
		if ((CONSCLIENT *) 0 != pCLServing->pCLnext) {
		    pCLServing->pCLnext->ppCLbnext = pCLServing->ppCLbnext;
		}
		*(pCLServing->ppCLbnext) = pCLServing->pCLnext;
		if ((CONSCLIENT *) 0 != pCLServing->pCLscan) {
		    pCLServing->pCLscan->ppCLbscan = pCLServing->ppCLbscan;
		}
		*(pCLServing->ppCLbscan) = pCLServing->pCLscan;

		/* the continue below will advance to a (ksb)
		 * legal client, even though we are now closed
		 * and in the fre list becasue pCLscan is used
		 * for the free list
		 */
		pCLServing->pCLnext = pCLFree;
		pCLFree = pCLServing;
		continue;
	    }

	    /* update last keystroke time
	     */
	    pCLServing->typetym = tyme = time((time_t *) 0);

	    for (i = 0; i < nr; ++i) {
		acInOrig[i] = acIn[i];
		if (fStrip) {
		    acIn[i] &= 127;
		}
	    }

	    for (i = 0; i < nr; ++i)
		switch (pCLServing->iState) {
		    case S_BCAST:
			/* gather message */
			if (pCLServing->icursor == sizeof(pCLServing->msg)) {
			    fileWrite(pCLServing->fd,
				      "Message too long.\r\n", -1);
			    goto drop;
			}
			if (&CECtl != pCLServing->pCEto) {
			    fileWrite(pCLServing->fd, &acIn[i], 1);
			}
			if ('\n' != acIn[i]) {
			    pCLServing->msg[pCLServing->icursor++] =
				acIn[i];
			    continue;
			}
			pCLServing->msg[pCLServing->icursor] = '\000';
			if ((pCLServing->icursor > 0) &&
			    ('\r' ==
			     pCLServing->msg[pCLServing->icursor - 1])) {
			    pCLServing->msg[pCLServing->icursor - 1] =
				'\000';
			}
			pCLServing->icursor = 0;

			sprintf(acOut, "[Broadcast: %s]\r\n",
				pCLServing->msg);
			SendClientsMsg(pGE, acOut);

			pCLServing->iState = S_NORMAL;
			continue;

		    case S_IDENT:
			/* append chars to acid until [\r]\n
			 */
			if (pCLServing->icursor ==
			    sizeof(pCLServing->acid)) {
			    fileWrite(pCLServing->fd, "Name too long.\r\n",
				      -1);
			    goto drop;
			}
			if ('\n' != acIn[i]) {
			    pCLServing->acid[pCLServing->icursor++] =
				acIn[i];
			    continue;
			}
			pCLServing->acid[pCLServing->icursor] = '\000';
			if ((pCLServing->icursor > 0) &&
			    ('\r' ==
			     pCLServing->acid[pCLServing->icursor - 1])) {
			    pCLServing->acid[--pCLServing->icursor] =
				'\000';
			}
			if (pCLServing->icursor <
			    (sizeof(pCLServing->acid) - 1)) {
			    int j;

			    pCLServing->acid[pCLServing->icursor++] = '@';
			    for (j = 0;
				 pCLServing->icursor <
				 (sizeof(pCLServing->acid) - 1) &&
				 pCLServing->peername[iConsole] !=
				 '\000';) {
				pCLServing->acid[pCLServing->icursor++] =
				    pCLServing->peername[j++];
			    }
			    pCLServing->acid[pCLServing->icursor] = '\000';
			}
			Debug("Client acid reinitialized to `%s'",
			      pCLServing->acid);
			pCLServing->icursor = 0;
			fileWrite(pCLServing->fd, "host:\r\n", -1);
			pCLServing->iState = S_HOST;
			continue;

		    case S_HOST:
			/* append char to buffer, check for \n
			 * continue if incomplete
			 * else swtich to new host
			 */
			if (pCLServing->icursor ==
			    sizeof(pCLServing->accmd)) {
			    fileWrite(pCLServing->fd, "Host too long.\r\n",
				      -1);
			    goto drop;
			}
			if ('\n' != acIn[i]) {
			    pCLServing->accmd[pCLServing->icursor++] =
				acIn[i];
			    continue;
			}
			pCLServing->accmd[pCLServing->icursor] = '\000';
			if ((pCLServing->icursor > 0) &&
			    ('\r' ==
			     pCLServing->accmd[pCLServing->icursor - 1])) {
			    pCLServing->accmd[pCLServing->icursor - 1] =
				'\000';
			}
			pCLServing->icursor = 0;

			/* try to move to the given console
			 */
			pCLServing->pCEwant = (CONSENT *) 0;
			for (iConsole = 0; iConsole < pGE->imembers;
			     ++iConsole) {
			    if (0 ==
				strcmp(pCLServing->accmd,
				       pCE[iConsole].server)) {
				pCLServing->pCEwant = &pCE[iConsole];
				break;
			    }
			}
			if ((CONSENT *) 0 == pCLServing->pCEwant) {
			    for (iConsole = 0; iConsole < pGE->imembers;
				 ++iConsole) {
				if (0 ==
				    strncmp(pCLServing->accmd,
					    pCE[iConsole].server,
					    strlen(pCLServing->accmd))) {
				    pCLServing->pCEwant = &pCE[iConsole];
				    break;
				}
			    }
			}
			if ((CONSENT *) 0 == pCLServing->pCEwant) {
			    sprintf(acOut, "%s: no such console\r\n",
				    pCLServing->accmd);
			    (void)fileWrite(pCLServing->fd, acOut, -1);
			    goto drop;
			}

			if ('t' == pCLServing->caccess) {
			    goto shift_console;
			}
			fileWrite(pCLServing->fd, "passwd:\r\n", -1);
			pCLServing->iState = S_PASSWD;
			continue;

		    case S_PASSWD:
			/* gather passwd, check and drop or
			 * set new state
			 */
			if (pCLServing->icursor ==
			    sizeof(pCLServing->accmd)) {
			    fileWrite(pCLServing->fd,
				      "Passwd too long.\r\n", -1);
			    goto drop;
			}
			if ('\n' != acIn[i]) {
			    pCLServing->accmd[pCLServing->icursor++] =
				acIn[i];
			    continue;
			}
			pCLServing->accmd[pCLServing->icursor] = '\000';
			if ((pCLServing->icursor > 0) &&
			    ('\r' ==
			     pCLServing->accmd[pCLServing->icursor - 1])) {
			    pCLServing->accmd[pCLServing->icursor - 1] =
				'\000';
			}
			pCLServing->icursor = 0;

			if (0 == CheckPasswd(pCLServing, pGE->passwd)) {
			    fileWrite(pCLServing->fd, "Sorry.\r\n", -1);
			    Info("%s: %s: bad passwd",
				 pCLServing->pCEwant->server,
				 pCLServing->acid);
			    goto drop;
			}
		      shift_console:
			/* remove from current host
			 */
			if ((CONSCLIENT *) 0 != pCLServing->pCLnext) {
			    pCLServing->pCLnext->ppCLbnext =
				pCLServing->ppCLbnext;
			}
			*(pCLServing->ppCLbnext) = pCLServing->pCLnext;
			if (pCLServing->fwr) {
			    pCLServing->fwr = 0;
			    pCLServing->fwantwr = 0;
			    tagLogfile(pCEServing, "%s detached",
				       pCLServing->acid);
			    pCEServing->pCLwr =
				FindWrite(pCEServing->pCLon);
			}

			/* inform operators of the change
			 */
/*				if (fVerbose) { */
			if (&CECtl == pCEServing) {
			    Info("%s: login %s [%s]",
				 pCLServing->pCEwant->server,
				 pCLServing->acid, strtime(NULL));
			} else {
			    Info("%s moves from %s to %s [%s]",
				 pCLServing->acid, pCEServing->server,
				 pCLServing->pCEwant->server,
				 strtime(NULL));
			}
/*				} */

			/* set new host and link into new host list
			 */
			pCEServing = pCLServing->pCEwant;
			pCLServing->pCEto = pCEServing;
			pCLServing->pCLnext = pCEServing->pCLon;
			pCLServing->ppCLbnext = &pCEServing->pCLon;
			if ((CONSCLIENT *) 0 != pCLServing->pCLnext) {
			    pCLServing->pCLnext->ppCLbnext =
				&pCLServing->pCLnext;
			}
			pCEServing->pCLon = pCLServing;

			if (fNoinit && !pCEServing->fup)
			    ConsInit(pCEServing, &rinit, 0);

			/* try for attach on new console
			 */
			if (!pCEServing->fup) {
			    fileWrite(pCLServing->fd,
				      "line to host is down]\r\n", -1);
			} else if (pCEServing->fronly) {
			    fileWrite(pCLServing->fd,
				      "host is read-only]\r\n", -1);
			} else if ((CONSCLIENT *) 0 == pCEServing->pCLwr) {
			    pCEServing->pCLwr = pCLServing;
			    pCLServing->fwr = 1;
			    fileWrite(pCLServing->fd, "attached]\r\n", -1);
			    /* this keeps the ops console neat */
			    pCEServing->iend = pCEServing->inamelen;
			    tagLogfile(pCEServing, "%s attached",
				       pCLServing->acid);
			} else {
			    fileWrite(pCLServing->fd, "spy]\r\n", -1);
			}
			pCLServing->fcon = 1;
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_QUOTE:	/* send octal code              */
			/* must type in 3 octal digits */
			if (isdigit((int)(acIn[i]))) {
			    pCLServing->accmd[0] *= 8;
			    pCLServing->accmd[0] += acIn[i] - '0';
			    if (++(pCLServing->icursor) < 3) {
				fileWrite(pCLServing->fd, &acIn[i], 1);
				continue;
			    }
			    pCLServing->accmd[1] = acIn[i];
			    pCLServing->accmd[2] = ']';
			    fileWrite(pCLServing->fd,
				      pCLServing->accmd + 1, 2);
			    (void)write(pCEServing->fdtty,
					pCLServing->accmd, 1);
			} else {
			    fileWrite(pCLServing->fd, " aborted]\r\n", -1);
			}
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_SUSP:
			if (!pCEServing->fup) {
			    fileWrite(pCLServing->fd, " -- line down]\r\n",
				      -1);
			} else if (pCEServing->fronly) {
			    fileWrite(pCLServing->fd, " -- read-only]\r\n",
				      -1);
			} else if ((CONSCLIENT *) 0 == pCEServing->pCLwr) {
			    pCEServing->pCLwr = pCLServing;
			    pCLServing->fwr = 1;
			    if (pCEServing->nolog) {
				fileWrite(pCLServing->fd,
					  " -- attached (nologging)]\r\n",
					  -1);
			    } else {
				fileWrite(pCLServing->fd,
					  " -- attached]\r\n", -1);
			    }
			    tagLogfile(pCEServing, "%s attached",
				       pCLServing->acid);
			} else {
			    fileWrite(pCLServing->fd, " -- spy mode]\r\n",
				      -1);
			}
			pCLServing->fcon = 1;
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_NORMAL:
			/* if it is an escape sequence shift states
			 */
			if (acInOrig[i] == pCLServing->ic[0]) {
			    pCLServing->iState = S_ESC1;
			    continue;
			}
			/* if we can write, write to slave tty
			 */
			if (pCLServing->fwr) {
			    (void)write(pCEServing->fdtty, &acIn[i], 1);
			    continue;
			}
			/* if the client is stuck in spy mode
			 * give them a clue as to how to get out
			 * (LLL nice to put chars out as ^Ec, rather
			 * than octal escapes, but....)
			 */
			if ('\r' == acIn[i] || '\n' == acIn[i]) {
			    static char acA1[16], acA2[16];
			    sprintf(acOut,
				    "[read-only -- use %s %s ? for help]\r\n",
				    FmtCtl(pCLServing->ic[0], acA1),
				    FmtCtl(pCLServing->ic[1], acA2));
			    (void)fileWrite(pCLServing->fd, acOut, -1);
			}
			continue;

		    case S_HALT1:	/* halt sequence? */
			pCLServing->iState = S_NORMAL;
			if (acIn[i] != '1') {
			    fileWrite(pCLServing->fd, "aborted]\r\n", -1);
			    continue;
			}

			/* send a break
			 */
			if (pCEServing->isNetworkConsole) {
			    char haltseq[2];

			    haltseq[0] = IAC;
			    haltseq[1] = BREAK;
			    write(pCEServing->fdtty, haltseq, 2);
			} else {
#if HAVE_TERMIO_H
			    if (-1 ==
				ioctl(pCEServing->fdtty, TCSBRK,
				      (char *)0)) {
				fileWrite(pCLServing->fd, "failed]\r\n",
					  -1);
				continue;
			    }
#else
# if HAVE_TCSENDBREAK
			    if (-1 == tcsendbreak(pCEServing->fdtty, 0)) {
				fileWrite(pCLServing->fd, "failed]\r\n",
					  -1);
				continue;
			    }
# else
#  if HAVE_TERMIOS_H
			    if (-1 ==
				ioctl(pCEServing->fdtty, TIOCSBRK,
				      (char *)0)) {
				fileWrite(pCLServing->fd, "failed]\r\n",
					  -1);
				continue;
			    }
			    fileWrite(pCLServing->fd, "- ", -1);
			    sleep(1);
			    if (-1 ==
				ioctl(pCEServing->fdtty, TIOCCBRK,
				      (char *)0)) {
				fileWrite(pCLServing->fd, "failed]\r\n",
					  -1);
				continue;
			    }
#  endif
# endif
#endif
			}
			fileWrite(pCLServing->fd, "sent]\r\n", -1);
			continue;

		    case S_CATTN:	/* redef escape sequence? */
			pCLServing->ic[0] = acInOrig[i];
			sprintf(acOut, "%s ",
				FmtCtl(acInOrig[i], pCLServing->accmd));
			(void)fileWrite(pCLServing->fd, acOut, -1);
			pCLServing->iState = S_CESC;
			continue;

		    case S_CESC:	/* escape sequent 2 */
			pCLServing->ic[1] = acInOrig[i];
			pCLServing->iState = S_NORMAL;
			sprintf(acOut, "%s  ok]\r\n",
				FmtCtl(acInOrig[i], pCLServing->accmd));
			(void)fileWrite(pCLServing->fd, acOut, -1);
			continue;

		    case S_ESC1:	/* first char in escape sequence */
			if (acInOrig[i] == pCLServing->ic[1]) {
			    if (pCLServing->fecho)
				fileWrite(pCLServing->fd, "\r\n[", -1);
			    else
				fileWrite(pCLServing->fd, "[", -1);
			    pCLServing->iState = S_CMD;
			    continue;
			}
			/* ^E^Ec or ^_^_^[
			 * pass (possibly stripped) first ^E (^_) and
			 * stay in same state
			 */
			if (acInOrig[i] == pCLServing->ic[0]) {
			    if (pCLServing->fwr) {
				(void)write(pCEServing->fdtty, &acIn[i],
					    1);
			    }
			    continue;
			}
			/* ^Ex or ^_x
			 * pass both characters to slave tty (possibly stripped)
			 */
			pCLServing->iState = S_NORMAL;
			if (pCLServing->fwr) {
			    char c = pCLServing->ic[0];
			    if (fStrip)
				c = c & 127;
			    (void)write(pCEServing->fdtty, &c, 1);
			    (void)write(pCEServing->fdtty, &acIn[i], 1);
			}
			continue;

		    case S_CMD:	/* have 1/2 of the escape sequence */
			pCLServing->iState = S_NORMAL;
			switch (acIn[i]) {
			    case '+':
			    case '-':
				if (0 !=
				    (pCLServing->fecho = '+' == acIn[i]))
				    fileWrite(pCLServing->fd,
					      "drop line]\r\n", -1);
				else
				    fileWrite(pCLServing->fd,
					      "no drop line]\r\n", -1);
				break;

			    case ';':	/* ;login: */
				if (&CECtl != pCLServing->pCEto) {
				    goto unknown;
				}
				fileWrite(pCLServing->fd, "login:\r\n",
					  -1);
				pCLServing->iState = S_IDENT;
				break;

			    case 'b':	/* broadcast message */
			    case 'B':
				if (&CECtl != pCLServing->pCEto) {
				    goto unknown;
				}
				fileWrite(pCLServing->fd,
					  "Enter message]\r\n", -1);
				pCLServing->iState = S_BCAST;
				break;

			    case 'a':	/* attach */
			    case 'A':
				if (&CECtl == pCEServing) {
				    sprintf(acOut, "no -- on ctl]\r\n");
				} else if (!pCEServing->fup) {
				    sprintf(acOut,
					    "line to host is down]\r\n");
				} else if (pCEServing->fronly) {
				    sprintf(acOut,
					    "host is read-only]\r\n");
				} else if ((CONSCLIENT *) 0 ==
					   (pCL = pCEServing->pCLwr)) {
				    pCEServing->pCLwr = pCLServing;
				    pCLServing->fwr = 1;
				    if (pCEServing->nolog) {
					sprintf(acOut,
						"attached (nologging)]\r\n");
				    } else {
					sprintf(acOut, "attached]\r\n");
				    }
				    tagLogfile(pCEServing, "%s attached",
					       pCLServing->acid);
				} else if (pCL == pCLServing) {
				    if (pCEServing->nolog) {
					sprintf(acOut,
						"ok (nologging)]\r\n");
				    } else {
					sprintf(acOut, "ok]\r\n");
				    }
				} else {
				    pCLServing->fwantwr = 1;
				    sprintf(acOut,
					    "no, %s is attached]\r\n",
					    pCL->acid);
				}
				(void)fileWrite(pCLServing->fd, acOut, -1);
				break;

			    case 'c':
			    case 'C':
				if (pCEServing->isNetworkConsole) {
				    continue;
				}
				if (pCEServing->fvirtual) {
				    continue;
				}
#if HAVE_TERMIOS_H
				if (-1 ==
				    tcgetattr(pCEServing->fdtty, &sbuf)) {
				    fileWrite(pCLServing->fd,
					      "failed]\r\n", -1);
				    continue;
				}
				if (0 != (sbuf.c_iflag & IXOFF)) {
				    sbuf.c_iflag &= ~(IXOFF | IXON);
				    fileWrite(pCLServing->fd,
					      "flow OFF]\r\n", -1);
				} else {
				    sbuf.c_iflag |= IXOFF | IXON;
				    fileWrite(pCLServing->fd,
					      "flow ON]\r\n", -1);
				}
				if (-1 ==
				    tcsetattr(pCEServing->fdtty, TCSANOW,
					      &sbuf)) {
				    fileWrite(pCLServing->fd,
					      "failed]\r\n", -1);
				    continue;
				}
#else
				if (-1 ==
				    ioctl(pCEServing->fdtty, TIOCGETP,
					  (char *)&sty)) {
				    fileWrite(pCLServing->fd,
					      "failed]\r\n", -1);
				    break;
				}
				if (0 != (sty.sg_flags & TANDEM)) {
				    sty.sg_flags &= ~TANDEM;
				    fileWrite(pCLServing->fd,
					      "flow OFF]\r\n", -1);
				} else {
				    sty.sg_flags |= TANDEM;
				    fileWrite(pCLServing->fd,
					      "flow ON]\r\n", -1);
				}
				(void)ioctl(pCEServing->fdtty, TIOCSETP,
					    (char *)&sty);
#endif
				break;

			    case 'd':	/* down a console       */
			    case 'D':
				if (&CECtl == pCEServing) {
				    fileWrite(pCLServing->fd,
					      "no -- on ctl]\r\n", -1);
				    continue;
				}
				if (!pCLServing->fwr &&
				    !pCEServing->fronly) {
				    fileWrite(pCLServing->fd,
					      "attach to down line]\r\n",
					      -1);
				    break;
				}
				if (!pCEServing->fup) {
				    fileWrite(pCLServing->fd, "ok]\r\n",
					      -1);
				    break;
				}

				pCLServing->fwr = 0;
				pCEServing->pCLwr = (CONSCLIENT *) 0;
				tagLogfile(pCEServing, "%s detached",
					   pCLServing->acid);
				ConsDown(pCEServing, &rinit);
				fileWrite(pCLServing->fd, "line down]\r\n",
					  -1);

				/* tell all who closed it */
				sprintf(acOut, "[line down by %s]\r\n",
					pCLServing->acid);
				for (pCL = pCEServing->pCLon;
				     (CONSCLIENT *) 0 != pCL;
				     pCL = pCL->pCLnext) {
				    if (pCL == pCLServing)
					continue;
				    if (pCL->fcon) {
					(void)fileWrite(pCL->fd, acOut,
							-1);
				    }
				}
				break;

			    case 'e':	/* redefine escape keys */
			    case 'E':
				pCLServing->iState = S_CATTN;
				fileWrite(pCLServing->fd, "redef: ", -1);
				break;

			    case 'f':	/* force attach */
			    case 'F':
				if (&CECtl == pCEServing) {
				    fileWrite(pCLServing->fd,
					      "no -- on ctl]\r\n", -1);
				    continue;
				} else if (pCEServing->fronly) {
				    fileWrite(pCLServing->fd,
					      "host is read-only]\r\n",
					      -1);
				    continue;
				} else if (!pCEServing->fup) {
				    fileWrite(pCLServing->fd,
					      "line to host is down]\r\n",
					      -1);
				    continue;
				}
				if (pCEServing->nolog) {
				    sprintf(acOut,
					    "attached (nologging)]\r\n");
				} else {
				    sprintf(acOut, "attached]\r\n");
				}
				if ((CONSCLIENT *) 0 !=
				    (pCL = pCEServing->pCLwr)) {
				    if (pCL == pCLServing) {
					if (pCEServing->nolog) {
					    fileWrite(pCLServing->fd,
						      "ok (nologging)]\r\n",
						      -1);
					} else {
					    fileWrite(pCLServing->fd,
						      "ok]\r\n", -1);
					}
					break;
				    }
				    pCL->fwr = 0;
				    pCL->fwantwr = 1;
				    if (pCEServing->nolog) {
					sprintf(acOut,
						"bumped %s (nologging)]\r\n",
						pCL->acid);
				    } else {
					sprintf(acOut, "bumped %s]\r\n",
						pCL->acid);
				    }
				    sprintf(acNote,
					    "\r\n[forced to `spy\' mode by %s]\r\n",
					    pCLServing->acid);
				    (void)fileWrite(pCL->fd, acNote, -1);
				    tagLogfile(pCEServing, "%s bumped %s",
					       pCLServing->acid,
					       pCL->acid);
				} else {
				    tagLogfile(pCEServing, "%s attached",
					       pCLServing->acid);
				}
				pCEServing->pCLwr = pCLServing;
				pCLServing->fwr = 1;
				(void)fileWrite(pCLServing->fd, acOut, -1);
				break;

			    case 'g':	/* group info */
			    case 'G':
				/* we do not show the ctl console
				 * else we'd get the client always
				 */
				sprintf(acOut, "group %s]\r\n",
					CECtl.server);
				(void)fileWrite(pCLServing->fd, acOut, -1);
				for (pCL = pGE->pCLall;
				     (CONSCLIENT *) 0 != pCL;
				     pCL = pCL->pCLscan) {
				    if (&CECtl == pCL->pCEto)
					continue;
				    sprintf(acOut,
					    " %-24.24s %c %-7.7s %5s %.32s\r\n",
					    pCL->acid,
					    pCL == pCLServing ? '*' : ' ',
					    pCL->fcon ? (pCL->
							 fwr ? "attach" :
							 "spy") :
					    "stopped",
					    IdleTyme(tyme - pCL->typetym),
					    pCL->pCEto->server);
				    (void)fileWrite(pCLServing->fd, acOut,
						    -1);
				}
				break;

			    case 'P':	/* DEC vt100 pf1 */
			    case 'h':	/* help                 */
			    case 'H':
			    case '?':
				HelpUser(pCLServing);
				break;

			    case 'L':
				if (pCLServing->fwr) {
				    pCEServing->nolog = !pCEServing->nolog;
				    if (pCEServing->nolog) {
					fileWrite(pCLServing->fd,
						  "logging off]\r\n", -1);
					sprintf(acOut,
						"[Console logging disabled by %s]\r\n",
						pCLServing->acid);
					(void)fileWrite(pCEServing->fdlog,
							acOut, -1);
				    } else {
					fileWrite(pCLServing->fd,
						  "logging on]\r\n", -1);
					sprintf(acOut,
						"[Console logging restored by %s]\r\n",
						pCLServing->acid);
					(void)fileWrite(pCEServing->fdlog,
							acOut, -1);
				    }
				} else {
				    static char acA1[16], acA2[16];
				    sprintf(acOut,
					    "read-only -- use %s %s ? for help]\r\n",
					    FmtCtl(pCLServing->ic[0],
						   acA1),
					    FmtCtl(pCLServing->ic[1],
						   acA2));
				    (void)fileWrite(pCLServing->fd, acOut,
						    -1);
				}
				break;

			    case 'l':	/* halt character 1     */
				if (pCEServing->fronly) {
				    fileWrite(pCLServing->fd,
					      "can\'t halt read-only host]\r\n",
					      -1);
				    continue;
				}
				if (!pCLServing->fwr) {
				    fileWrite(pCLServing->fd,
					      "attach to halt]\r\n", -1);
				    continue;
				}
				pCLServing->iState = S_HALT1;
				fileWrite(pCLServing->fd, "halt ", -1);
				break;

			    case 'o':	/* close and re-open line */
			    case 'O':
				if (&CECtl == pCEServing) {
				    fileWrite(pCLServing->fd,
					      "no -- on ctl]\r\n", -1);
				    continue;
				}
				/* with a close/re-open we might
				 * change fd's
				 */
				ConsInit(pCEServing, &rinit, 0);
				if (!pCEServing->fup) {
				    sprintf(acOut,
					    "line to host is down]\r\n");
				} else if (pCEServing->fronly) {
				    sprintf(acOut, "up read-only]\r\n");
				} else if ((CONSCLIENT *) 0 ==
					   (pCL = pCEServing->pCLwr)) {
				    pCEServing->pCLwr = pCLServing;
				    pCLServing->fwr = 1;
				    sprintf(acOut, "up -- attached]\r\n");
				    tagLogfile(pCEServing, "%s attached",
					       pCLServing->acid);
				} else if (pCL == pCLServing) {
				    sprintf(acOut, "up]\r\n");
				    tagLogfile(pCEServing, "%s attached",
					       pCLServing->acid);
				} else {
				    sprintf(acOut,
					    "up, %s is attached]\r\n",
					    pCL->acid);
				}
				(void)fileWrite(pCLServing->fd, acOut, -1);
				break;

			    case '\022':	/* ^R */
				fileWrite(pCLServing->fd, "^R]\r\n", -1);
				if (pCEServing->iend ==
				    pCEServing->inamelen) {
				    Replay(pCEServing->fdlog,
					   pCLServing->fd, 1);
				} else {
				    fileWrite(pCLServing->fd,
					      pCEServing->acline +
					      pCEServing->inamelen,
					      pCEServing->iend -
					      pCEServing->inamelen);
				}
				break;

			    case 'R':	/* DEC vt100 pf3 */
			    case 'r':	/* replay 20 lines */
				fileWrite(pCLServing->fd, "replay]\r\n",
					  -1);
				Replay(pCEServing->fdlog, pCLServing->fd,
				       20);
				break;

			    case 'p':	/* replay 60 lines */
				fileWrite(pCLServing->fd,
					  "long replay]\r\n", -1);
				Replay(pCEServing->fdlog, pCLServing->fd,
				       60);
				break;

			    case 'S':	/* DEC vt100 pf4 */
			    case 's':	/* spy mode */
				pCLServing->fwantwr = 0;
				if (!pCLServing->fwr) {
				    fileWrite(pCLServing->fd, "ok]\r\n",
					      -1);
				    break;
				}
				pCLServing->fwr = 0;
				tagLogfile(pCEServing, "%s detached",
					   pCLServing->acid);
				pCEServing->pCLwr =
				    FindWrite(pCEServing->pCLon);
				fileWrite(pCLServing->fd, "spying]\r\n",
					  -1);
				break;

			    case 'u':	/* hosts on server this */
			    case 'U':
				fileWrite(pCLServing->fd, "hosts]\r\n",
					  -1);
				for (iConsole = 0;
				     iConsole < pGE->imembers;
				     ++iConsole) {
				    sprintf(acOut,
					    " %-24.24s %c %-4.4s %-.40s\r\n",
					    pCE[iConsole].server,
					    pCE + iConsole ==
					    pCEServing ? '*' : ' ',
					    pCE[iConsole].
					    fup ? "up" : "down",
					    pCE[iConsole].
					    pCLwr ? pCE[iConsole].pCLwr->
					    acid : pCE[iConsole].
					    pCLon ? "<spies>" : "<none>");
				    (void)fileWrite(pCLServing->fd, acOut,
						    -1);
				}
				break;

			    case 'v':	/* version */
			    case 'V':
				sprintf(acOut, "version `%s\']\r\n",
					THIS_VERSION);
				(void)fileWrite(pCLServing->fd, acOut, -1);
				break;

			    case 'w':	/* who */
			    case 'W':
				sprintf(acOut, "who %s]\r\n",
					pCEServing->server);
				(void)fileWrite(pCLServing->fd, acOut, -1);
				for (pCL = pCEServing->pCLon;
				     (CONSCLIENT *) 0 != pCL;
				     pCL = pCL->pCLnext) {
				    sprintf(acOut,
					    " %-24.24s %c %-7.7s %5s %s\r\n",
					    pCL->acid,
					    pCL == pCLServing ? '*' : ' ',
					    pCL->fcon ? (pCL->
							 fwr ? "attach" :
							 "spy") :
					    "stopped",
					    IdleTyme(tyme - pCL->typetym),
					    pCL->actym);
				    (void)fileWrite(pCLServing->fd, acOut,
						    -1);
				}
				break;

			    case 'x':
			    case 'X':
				fileWrite(pCLServing->fd, "examine]\r\n",
					  -1);
				for (iConsole = 0;
				     iConsole < pGE->imembers;
				     ++iConsole) {
				    sprintf(acOut,
					    " %-24.24s on %-32.32s at %5.5s%c\r\n",
					    pCE[iConsole].server,
					    pCE[iConsole].
					    fvirtual ? pCE[iConsole].
					    acslave : pCE[iConsole].dfile,
					    pCE[iConsole].pbaud->acrate,
					    pCE[iConsole].pparity->ckey);
				    (void)fileWrite(pCLServing->fd, acOut,
						    -1);
				}
				break;

			    case 'z':	/* suspend the client */
			    case 'Z':
			    case '\032':
				if (1 !=
				    fileSend(pCLServing->fd, acStop, 1,
					     MSG_OOB)) {
				    break;
				}
				pCLServing->fcon = 0;
				pCLServing->iState = S_SUSP;
				if (pCEServing->pCLwr == pCLServing) {
				    pCLServing->fwr = 0;
				    pCLServing->fwantwr = 0;
				    pCEServing->pCLwr = (CONSCLIENT *) 0;
				    tagLogfile(pCEServing, "%s detached",
					       pCLServing->acid);
				}
				break;

			    case '\t':	/* toggle tab expand    */
				fileWrite(pCLServing->fd, "tabs]\r\n", -1);
#if HAVE_TERMIO_H
				/* ZZZ */
#else
# if HAVE_TERMIOS_H
				if (-1 ==
				    tcgetattr(pCEServing->fdtty, &sbuf)) {
				    fileWrite(pCLServing->fd,
					      "failed]\r\n", -1);
				    continue;
				}
#  if !defined(XTABS)		/* XXX hack */
#   define XTABS   TAB3
#  endif
				if (XTABS == (TABDLY & sbuf.c_oflag)) {
				    sbuf.c_oflag &= ~TABDLY;
				    sbuf.c_oflag |= TAB0;
				} else {
				    sbuf.c_oflag &= ~TABDLY;
				    sbuf.c_oflag |= XTABS;
				}
				if (-1 ==
				    tcsetattr(pCEServing->fdtty, TCSANOW,
					      &sbuf)) {
				    fileWrite(pCLServing->fd,
					      "failed]\r\n", -1);
				    continue;
				}
# else
				/* ZZZ */
# endif
#endif
				break;

			    case 'Q':	/* DEC vt100 PF2 */
			    case '.':	/* disconnect */
			    case '\004':
			    case '\003':
				fileWrite(pCLServing->fd,
					  "disconnect]\r\n", -1);
				nr = 0;
				if (!pCEServing->fup) {
				    goto drop;
				}
				if (pCEServing->isNetworkConsole) {
				    goto drop;
				}
				if (pCEServing->fvirtual) {
				    goto drop;
				}
#if HAVE_TERMIOS_H
				if (-1 ==
				    tcgetattr(pCEServing->fdtty, &sbuf)) {
				    fileWrite(pCLServing->fd,
					      "[failed]\r\n", -1);
				    continue;
				}
				if (0 == (sbuf.c_iflag & IXOFF)) {
				    sbuf.c_iflag |= IXOFF | IXON;
				    (void)tcsetattr(pCEServing->fdtty,
						    TCSANOW, &sbuf);
				}
#else
				if (-1 !=
				    ioctl(pCEServing->fdtty, TIOCGETP,
					  (char *)&sty) &&
				    0 == (sty.sg_flags & TANDEM)) {
				    sty.sg_flags |= TANDEM;
				    (void)ioctl(pCEServing->fdtty,
						TIOCSETP, (char *)&sty);
				}
#endif
				goto drop;

			    case ' ':	/* abort escape sequence */
			    case '\n':
			    case '\r':
				fileWrite(pCLServing->fd, "ignored]\r\n",
					  -1);
				break;

			    case '\\':	/* quote mode (send ^Q,^S) */
				if (pCEServing->fronly) {
				    fileWrite(pCLServing->fd,
					      "can\'t write to read-only host]\r\n",
					      -1);
				    continue;
				}
				if (!pCLServing->fwr) {
				    fileWrite(pCLServing->fd,
					      "attach to send character]\r\n",
					      -1);
				    continue;
				}
				pCLServing->icursor = 0;
				pCLServing->accmd[0] = '\000';
				pCLServing->iState = S_QUOTE;
				fileWrite(pCLServing->fd, "quote \\", -1);
				break;
			    default:	/* unknown sequence */
			      unknown:
				fileWrite(pCLServing->fd,
					  "unknown -- use `?\']\r\n", -1);
				break;
			}
			continue;
		}
	}


	/* if nothing on control line, get more
	 */
	if (!FD_ISSET(fileFDNum(sfd), &rmask)) {
	    continue;
	}

	/* accept new connections and deal with them
	 */
	so = sizeof(struct sockaddr_in);
	fd = accept(fileFDNum(sfd), (struct sockaddr *)&pCLFree->cnct_port,
		    (socklen_t *) & so);
	if (fd < 0) {
	    Error("accept: %s", strerror(errno));
	    continue;
	}
	pCLFree->fd = fileOpenFD(fd, simpleSocket);
	if (pCLFree->fd < 0) {
	    Error("fileOpenFD: %s", strerror(errno));
	    close(fd);
	    continue;
	}

	/* We use this information to verify                    (ksb)
	 * the source machine as being local.
	 */
	so = sizeof(in_port);
	if (-1 ==
	    getpeername(fd, (struct sockaddr *)&in_port,
			(socklen_t *) & so)) {
	    fileWrite(pCLFree->fd, "getpeername failed\r\n", -1);
	    (void)fileClose(pCLFree->fd);
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
	    fileWrite(pCLFree->fd, "access from your host refused\r\n",
		      -1);
	    (void)fileClose(pCLFree->fd);
	    continue;
	}

	/* save pCL so we can advance to the next free one
	 */
	pCL = pCLFree;
	pCLFree = pCL->pCLnext;

	/* init the identification stuff
	 */
	if (hpPeer == (struct hostent *)0) {
	    sprintf(pCL->peername, "%.*s",
		    (int)(sizeof(pCL->peername) - 1),
		    inet_ntoa(in_port.sin_addr));
	} else {
	    sprintf(pCL->peername, "%.*s",
		    (int)(sizeof(pCL->peername) - 1), hpPeer->h_name);
	}
	sprintf(pCL->acid, "<unknown>@%.*s", (int)(sizeof(pCL->acid) - 12),
		pCL->peername);
	Debug("Client acid initialized to `%s'", pCL->acid);
	(void)strcpy(pCL->actym, strtime(&(pCL->tym)));
	pCL->typetym = pCL->tym;

	/* link into the control list for the dummy console
	 */
	pCL->pCEto = &CECtl;
	pCL->pCLnext = CECtl.pCLon;
	pCL->ppCLbnext = &CECtl.pCLon;
	if ((CONSCLIENT *) 0 != pCL->pCLnext) {
	    pCL->pCLnext->ppCLbnext = &pCL->pCLnext;
	}
	CECtl.pCLon = pCL;

	/* link into all clients list
	 */
	pCL->pCLscan = pGE->pCLall;
	pCL->ppCLbscan = &pGE->pCLall;
	if ((CONSCLIENT *) 0 != pCL->pCLscan) {
	    pCL->pCLscan->ppCLbscan = &pCL->pCLscan;
	}
	pGE->pCLall = pCL;

	FD_SET(fileFDNum(pCL->fd), &rinit);

	/* init the fsm
	 */
	pCL->fecho = 0;
	pCL->iState = S_NORMAL;
	pCL->ic[0] = DEFATTN;
	pCL->ic[1] = DEFESC;
	pCL->caccess = cType;
	pCL->icursor = 0;

	/* mark as stopped (no output from console)
	 * and spy only (on chars to console)
	 */
	pCL->fcon = 0;
	pCL->fwr = 0;
	pCL->fwantwr = 0;
	fileWrite(pCL->fd, "ok\r\n", -1);

	/* remove from the free list
	 * if we ran out of static connections calloc some...
	 */
	if ((CONSCLIENT *) 0 == pCLFree) {
	    pCLFree = (CONSCLIENT *) calloc(2, sizeof(CONSCLIENT));
	    if ((CONSCLIENT *) 0 == pCLFree) {
		OutOfMem();
	    } else {
		pCLFree->pCLnext = &pCLFree[1];
	    }
	}
    }
}

/* create a child process:						(fine)
 * fork off a process for each group with an open socket for connections
 */
void
Spawn(pGE)
    GRPENT *pGE;
{
    int pid, sfd;
    int so;
    struct sockaddr_in lstn_port;
    int true = 1;
    int portInc = 0;
    CONSFILE *ssocket;

    /* get a socket for listening
     */
#if HAVE_MEMSET
    (void)memset((void *)&lstn_port, 0, sizeof(lstn_port));
#else
    (void)bzero((char *)&lstn_port, sizeof(lstn_port));
#endif
    lstn_port.sin_family = AF_INET;
    lstn_port.sin_addr.s_addr = bindAddr;
    lstn_port.sin_port = htons(bindBasePort);

    /* create a socket to listen on
     * (prepared by master so he can see the port number of the kid)
     */
    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	Error("socket: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
#if HAVE_SETSOCKOPT
    if (setsockopt
	(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&true, sizeof(true)) < 0) {
	Error("setsockopt: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
#endif

    while (bind(sfd, (struct sockaddr *)&lstn_port, sizeof(lstn_port)) < 0) {
	if (bindBasePort && (
#if defined(EADDRINUSE)
				(errno == EADDRINUSE) ||
#endif
				(errno == EACCES)) &&
	    (portInc++ < MAXGRP * 2)) {
	    lstn_port.sin_port = htons(bindBasePort + portInc);
	} else {
	    Error("bind: %s", strerror(errno));
	    exit(EX_UNAVAILABLE);
	}
    }
    so = sizeof(lstn_port);

    if (-1 ==
	getsockname(sfd, (struct sockaddr *)&lstn_port,
		    (socklen_t *) & so)) {
	Error("getsockname: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    pGE->port = lstn_port.sin_port;

    (void)fflush(stderr);
    (void)fflush(stdout);
    switch (pid = fork()) {
	case -1:
	    Error("fork: %s", strerror(errno));
	    exit(EX_UNAVAILABLE);
	default:
	    (void)close(sfd);
	    /* hmm...there seems to be a potential linux bug here as well.
	     * if you have a parent and child both sharing a socket and the
	     * parent is able to close it and create a new socket (same port
	     * request) before the child is able to listen() and you have
	     * been using SO_REUSEADDR, then you get two processes listening
	     * to the same port - only one appears to get the connections.
	     * sleeping a bit not only throttles startup impact (a bit) but
	     * it gives the child a chance to listen() before the parent
	     * possibly opens another socket to the port.  this really is only
	     * an issue if you use the same port with -p and -b, i think.
	     */
	    usleep(750000);	/* pause 0.75 sec to throttle startup a bit */
	    pGE->pid = pid;
	    return;
	case 0:
	    thepid = getpid();
	    break;
    }
    if (listen(sfd, SOMAXCONN) < 0) {
	Error("listen: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    ssocket = fileOpenFD(sfd, simpleSocket);
    if (ssocket < 0) {
	Error("fileOpenFD: %s", strerror(errno));
	close(sfd);
	exit(EX_UNAVAILABLE);
    }
    Kiddie(pGE, ssocket);

    /* should never get here...
     */
    (void)fileClose(ssocket);
    Error("internal flow error");
    exit(EX_UNAVAILABLE);
}
