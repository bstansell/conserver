/*
 *  $Id: group.c,v 5.186 2002-09-23 11:40:35-07 bryan Exp $
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
#if USE_ANSI_PROTO
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <arpa/telnet.h>
#if HAVE_POSIX_REGCOMP
#include <regex.h>
#endif
#if HAVE_PAM
#include <security/pam_appl.h>
#endif

#if defined(USE_LIBWRAP)
#include <syslog.h>
#include <tcpd.h>
#endif

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

void
#if USE_ANSI_PROTO
SendClientsMsg(CONSENT * pCE, char *message)
#else
SendClientsMsg(pCE, message)
    CONSENT *pCE;
    char *message;
#endif
{
    CONSCLIENT *pCL;

    if ((CONSENT *) 0 == pCE) {
	return;
    }

    for (pCL = pCE->pCLon; (CONSCLIENT *) 0 != pCL; pCL = pCL->pCLnext) {
	if (pCL->fcon) {
	    (void)fileWrite(pCL->fd, message, -1);
	}
    }
}

void
#if USE_ANSI_PROTO
SendAllClientsMsg(GRPENT * pGE, char *message)
#else
SendAllClientsMsg(pGE, message)
    GRPENT *pGE;
    char *message;
#endif
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
#if USE_ANSI_PROTO
destroyClient(CONSCLIENT * pCL)
#else
destroyClient(pCL)
    CONSCLIENT *pCL;
#endif
{
    destroyString(&pCL->acid);
    destroyString(&pCL->peername);
    destroyString(&pCL->accmd);
    destroyString(&pCL->msg);
    fileClose(&pCL->fd);
    free(pCL);
}

void
#if USE_ANSI_PROTO
destroyConsent(GRPENT * pGE, CONSENT * pCE)
#else
destroyConsent(pGE, pCE)
    GRPENT *pGE;
    CONSENT *pCE;
#endif
{
    CONSCLIENT *pCL;
    CONSENT **ppCE;

    if (pCE == (CONSENT *) 0)
	return;

    Debug(1, "Destroying console (%s)", pCE->server.string);

    /* must loop using pCLall and pCLscan for the same reason as the
     * drop: code.  this is basically the same set of code, but modified
     * since we know we're going to nuke the console itself.
     */
    for (pCL = pGE->pCLall; pCL != (CONSCLIENT *) 0; pCL = pCL->pCLscan) {
	if (pCL->pCEto != pCE)
	    continue;
	if (pCL->fcon) {
	    (void)fileWrite(pCL->fd,
			    "[-- Conserver reconfigured - console has been (re)moved --]\r\n",
			    -1);
	}
	Info("%s: logout %s [%s]", pCE->server.string, pCL->acid.string,
	     strtime(NULL));
	FD_CLR(fileFDNum(pCL->fd), &pGE->rinit);
	fileClose(&pCL->fd);
	if (pCL->fwr) {
	    tagLogfile(pCE, "%s detached", pCL->acid.string);
	    if (pCE->nolog) {
		pCE->nolog = 0;
		filePrint(pCE->fdlog,
			  "[-- Console logging restored (logout) -- %s]\r\n",
			  strtime(NULL));
	    }
	}
	/* mark as unconnected and remove from both
	 * lists (all clients, and this console)
	 */
	if ((CONSCLIENT *) 0 != pCL->pCLnext) {
	    pCL->pCLnext->ppCLbnext = pCL->ppCLbnext;
	}
	*(pCL->ppCLbnext) = pCL->pCLnext;
	if ((CONSCLIENT *) 0 != pCL->pCLscan) {
	    pCL->pCLscan->ppCLbscan = pCL->ppCLbscan;
	}
	*(pCL->ppCLbscan) = pCL->pCLscan;

	pCL->pCLnext = pGE->pCLfree;
	pGE->pCLfree = pCL;
    }

    ConsDown(pCE, &pGE->rinit);

    for (ppCE = &(pGE->pCElist); *ppCE != (CONSENT *) 0;
	 ppCE = &((*ppCE)->pCEnext)) {
	if (*ppCE == pCE) {
	    *ppCE = pCE->pCEnext;
	    break;
	}
    }

    destroyString(&pCE->server);
    destroyString(&pCE->dfile);
    destroyString(&pCE->lfile);
    destroyString(&pCE->networkConsoleHost);
    destroyString(&pCE->acslave);
    destroyString(&pCE->pccmd);
    fileClose(&pCE->fdlog);
    free(pCE);

    pGE->imembers--;
}

void
#if USE_ANSI_PROTO
destroyGroup(GRPENT * pGE)
#else
destroyGroup(pGE)
    GRPENT *pGE;
#endif
{
    CONSENT *pCEtmp, *pCE;
    CONSCLIENT *pCLtmp, *pCL;

    if (pGE == (GRPENT *) 0)
	return;

    Debug(1, "Destroying group (%d members)", pGE->imembers);

    /* nuke each console (which kicks off clients) */
    destroyConsent(pGE, pGE->pCEctl);
    pCE = pGE->pCElist;
    while (pCE != (CONSENT *) 0) {
	pCEtmp = pCE->pCEnext;
	destroyConsent(pGE, pCE);
	pCE = pCEtmp;
    }

    /* now we can nuke the client structures */
    pCL = pGE->pCLall;
    while (pCL != (CONSCLIENT *) 0) {
	pCLtmp = pCL->pCLscan;
	destroyClient(pCL);
	pCL = pCLtmp;
    }
    pCL = pGE->pCLfree;
    while (pCL != (CONSCLIENT *) 0) {
	pCLtmp = pCL->pCLnext;
	destroyClient(pCL);
	pCL = pCLtmp;
    }

    free(pGE);
}

#if HAVE_PAM
int
#if USE_ANSI_PROTO
quiet_conv(int num_msg, struct pam_message **msg,
	   struct pam_response **resp, void *appdata_ptr)
#else
quiet_conv(num_msg, msg, resp, appdata_ptr)
    int num_msg;
    struct pam_message **msg;
    struct pam_response **resp;
    void *appdata_ptr;
#endif
{
    int i;
    struct pam_response *response = NULL;
    char *pcUser;
    char *pcWord;
    pcUser = ((char **)appdata_ptr)[0];
    pcWord = ((char **)appdata_ptr)[1];

    if (num_msg <= 0)
	return PAM_CONV_ERR;

    response =
	(struct pam_response *)calloc(num_msg,
				      sizeof(struct pam_response));

    if (response == (struct pam_response *)0)
	return PAM_CONV_ERR;

    for (i = 0; i < num_msg; i++) {
	response[i].resp_retcode = PAM_SUCCESS;
	switch (msg[i]->msg_style) {
	    case PAM_PROMPT_ECHO_ON:
		response[i].resp =
		    (pcUser != (char *)0 ? strdup(pcUser) : (char *)0);
		break;

	    case PAM_PROMPT_ECHO_OFF:
		response[i].resp =
		    (pcWord != (char *)0 ? strdup(pcWord) : (char *)0);
		break;

	    case PAM_TEXT_INFO:
	    case PAM_ERROR_MSG:
		/* Ignore it... */
		response[i].resp = NULL;
		break;

	    default:
		/* Must be an error of some sort... */
		free(response);
		return PAM_CONV_ERR;
	}
    }

    *resp = response;
    return PAM_SUCCESS;
}
#endif

/* Is this passwd a match for this user's passwd? 		(gregf/ksb)
 * look up passwd in shadow file if we have to, if we are
 * given a special epass try it first.
 */
int
#if USE_ANSI_PROTO
CheckPass(char *pcUser, char *pcWord)
#else
CheckPass(pcUser, pcWord)
    char *pcUser;
    char *pcWord;
#endif
{
#if HAVE_PAM
    int pam_error;
    char *appdata[2];
    static pam_handle_t *pamh = (pam_handle_t *) 0;
    struct pam_conv conv;
    appdata[0] = pcUser;
    appdata[1] = pcWord;
    conv.conv = &quiet_conv;
    conv.appdata_ptr = (void *)&appdata;

    Debug(1, "PAM: pam_start(conserver,%s,...)", pcUser);
    pam_error = pam_start("conserver", pcUser, &conv, &pamh);

    if (pam_error == PAM_SUCCESS) {
	pam_set_item(pamh, PAM_RHOST, "IHaveNoIdeaHowIGotHere");
	Debug(1, "PAM: pam_authenticate()", pcUser);
	pam_error = pam_authenticate(pamh, PAM_SILENT);
	if (pam_error == PAM_SUCCESS) {
	    Debug(1, "PAM: pam_acct_mgmt()", pcUser);
	    pam_error = pam_acct_mgmt(pamh, PAM_SILENT);
	    if (pam_error != PAM_SUCCESS) {
		Error("PAM(%s): %s", "conserver",
		      pam_strerror(pamh, pam_error));
	    }
	} else if (pam_error != PAM_AUTH_ERR) {
	    Error("PAM(%s): %s", "conserver",
		  pam_strerror(pamh, pam_error));
	}
	Debug(1, "PAM: pam_end()", pcUser);
	pam_end(pamh, pam_error);
	if (pam_error == PAM_ABORT)	/* things just got real bad */
	    fSawGoAway = 1;
    } else {
	Error("PAM(%s): %s", "conserver", pam_strerror(pamh, pam_error));
    }
    if (pam_error == PAM_SUCCESS)
	return AUTH_SUCCESS;
    if (pam_error == PAM_USER_UNKNOWN)
	return AUTH_NOUSER;
    return AUTH_INVALID;
#else /* getpw*() */
#if HAVE_GETSPNAM
    struct passwd *pwd;
    struct spwd *spwd;
    int retval = AUTH_SUCCESS;
#endif

    if (pcWord == (char *)0) {
	pcWord = "";
    }
    if ((pwd = getpwnam(pcUser)) == (struct passwd *)0) {
	retval = AUTH_NOUSER;
    } else {
#if HAVE_GETSPNAM
	if ('x' == pwd->pw_passwd[0] && '\000' == pwd->pw_passwd[1]) {
	    if ((spwd = getspnam(pwd->pw_name)) == (struct spwd *)0) {
		retval = AUTH_NOUSER;
	    } else {
		if ((spwd->sp_pwdp[0] != '\000' || pcWord[0] != '\000') &&
		    (strcmp(spwd->sp_pwdp, crypt(pcWord, spwd->sp_pwdp)) !=
		     0)) {
		    retval = AUTH_INVALID;
		}
	    }
	} else
#endif
	    if ((pwd->pw_passwd[0] != '\000' || pcWord[0] != '\000') &&
		(strcmp(pwd->pw_passwd, crypt(pcWord, pwd->pw_passwd))
		 != 0)) {
	    retval = AUTH_INVALID;
	}
    }
    endpwent();
    return retval;
#endif /* getpw*() */
}

/* This returns a string with the current time in ascii form.
 * (same as ctime() but without the \n)
 * optionally returns the time in time_t form (pass in NULL if you don't care).
 * It's overwritten each time, so use it and forget it.
 */
const char *
#if USE_ANSI_PROTO
strtime(time_t * ltime)
#else
strtime(ltime)
    time_t *ltime;
#endif
{
    static char curtime[25];
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
#if USE_ANSI_PROTO
FlagReOpen(int sig)
#else
FlagReOpen(sig)
    int sig;
#endif
{
    fSawReOpen = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGHUP, FlagReOpen);
#endif
}

static void
#if USE_ANSI_PROTO
ReOpen(GRPENT * pGE)
#else
ReOpen(pGE)
    GRPENT *pGE;
#endif
{
    CONSENT *pCE;

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	if ((CONSFILE *) 0 == pCE->fdlog) {
	    continue;
	}
	(void)fileClose(&pCE->fdlog);
	if ((CONSFILE *) 0 ==
	    (pCE->fdlog =
	     fileOpen(pCE->lfile.string, O_RDWR | O_CREAT | O_APPEND,
		      0666))) {
	    Error("Cannot reopen log file: %s", pCE->lfile.string);
	    continue;
	}
    }
}

static RETSIGTYPE
#if USE_ANSI_PROTO
FlagReUp(int sig)
#else
FlagReUp(sig)
    int sig;
#endif
{
    fSawReUp = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGUSR1, FlagReUp);
#endif
}

static void
#if USE_ANSI_PROTO
ReUp(GRPENT * pGE, short int automatic)
#else
ReUp(pGE, automatic)
    GRPENT *pGE;
    short int automatic;
#endif
{
    CONSENT *pCE;

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	if (pCE->fup || fNoinit || (automatic == 1 && !pCE->autoReUp))
	    continue;
	if (automatic)
	    Info("%s: automatic reinitialization [%s]", pCE->server.string,
		 strtime(NULL));
	ConsInit(pCE, &pGE->rinit, 1);
	if (pCE->fup)
	    pCE->pCLwr = FindWrite(pCE->pCLon);
    }
}

static RETSIGTYPE
#if USE_ANSI_PROTO
FlagMark(int sig)
#else
FlagMark(sig)
    int sig;
#endif
{
    fSawMark = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGALRM, FlagMark);
#endif
}

/* various areas of the code (sometimes not even our own) mess with
 * the alarm signal, so this function is here to reset it to what
 * we need.  We do not actually set an alarm here, but set the flag
 * that will call Mark() which will set the next alarm.
 */
void
#if USE_ANSI_PROTO
resetMark(void)
#else
resetMark()
#endif
{
    simpleSignal(SIGALRM, FlagMark);
    fSawMark = 1;
}

void
#if USE_ANSI_PROTO
tagLogfile(const CONSENT * pCE, const char *fmt, ...)
#else
tagLogfile(pCE, fmt, va_alist)
    const CONSENT *pCE;
    const char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if USE_ANSI_PROTO
    va_start(ap, fmt);
#else
    va_start(ap);
#endif

    if ((pCE == (CONSENT *) 0) || (pCE->fdlog == (CONSFILE *) 0) ||
	(pCE->activitylog == 0))
	return;

    (void)fileWrite(pCE->fdlog, "[-- ", -1);
    fileVwrite(pCE->fdlog, fmt, ap);
    filePrint(pCE->fdlog, " -- %s]\r\n", strtime(NULL));
    va_end(ap);
}

static void
#if USE_ANSI_PROTO
Mark(GRPENT * pGE)
#else
Mark(pGE)
    GRPENT *pGE;
#endif
{
    char acOut[100];		/* MARK spec ~ 40 chars */
    time_t tyme;
    int i;
    CONSENT *pCE;

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    /* [-- MARK -- `date`] */
    sprintf(acOut, "[-- MARK -- %s]\r\n", strtime(&tyme));

    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	if ((CONSFILE *) 0 == pCE->fdlog) {
	    continue;
	}
	if ((pCE->nextMark > 0) && (tyme >= pCE->nextMark)) {
	    Debug(1, "[-- MARK --] stamp added to %s", pCE->lfile.string);
	    (void)fileWrite(pCE->fdlog, acOut, -1);
	    /* Add as many pCE->mark values as necessary so that we move
	     * beyond the current time.
	     */
	    pCE->nextMark +=
		(((tyme - pCE->nextMark) / pCE->mark) + 1) * pCE->mark;
	}
    }
    if ((i = (ALARMTIME - (tyme % 60))) <= 0) {
	i = 1;
    }
    alarm(i);
}

void
#if USE_ANSI_PROTO
writeLog(CONSENT * pCE, char *s, int len)
#else
writeLog(pCE, s, len)
    CONSENT *pCE;
    char *s;
    int len;
#endif
{
    char acOut[100];		/* [%s], time ~ 30 chars */
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
	if (pCE->nextMark == 0) {
	    (void)fileWrite(pCE->fdlog, s + i, j - i);
	    i = j;
	    if (acOut[0] == '\000') {
		sprintf(acOut, "[%s]", strtime(NULL));
	    }
	    (void)fileWrite(pCE->fdlog, acOut, -1);
	    pCE->nextMark = pCE->mark;
	}
	if (s[j] == '\n') {
	    Debug(1, "Found newline for %s (nextMark=%d, mark=%d)",
		  pCE->server.string, pCE->nextMark, pCE->mark);
	    pCE->nextMark++;
	}
    }
    if (i < j) {
	(void)fileWrite(pCE->fdlog, s + i, j - i);
    }
}

static RETSIGTYPE
#if USE_ANSI_PROTO
FlagGoAway(int sig)
#else
FlagGoAway(sig)
    int sig;
#endif
{
    fSawGoAway = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGTERM, FlagGoAway);
#endif
}

/* yep, basically the same...ah well, maybe someday */
static RETSIGTYPE
#if USE_ANSI_PROTO
FlagGoAwayAlso(int sig)
#else
FlagGoAwayAlso(sig)
    int sig;
#endif
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
#if USE_ANSI_PROTO
FlagReapVirt(int sig)
#else
FlagReapVirt(sig)
    int sig;
#endif
{
    fSawReapVirt = 1;
#if !HAVE_SIGACTION
    simpleSignal(SIGCHLD, FlagReapVirt);
#endif
}

/* on a TERM we have to cleanup utmp entries (ask ptyd to do it)	(ksb)
 */
static void
#if USE_ANSI_PROTO
DeUtmp(GRPENT * pGE)
#else
DeUtmp(pGE)
    GRPENT *pGE;
#endif
{
    CONSENT *pCE;

    if ((GRPENT *) 0 != pGE) {
	SendAllClientsMsg(pGE, "[-- Console server shutting down --]\r\n");

	for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	    ConsDown(pCE, &pGE->rinit);
	}
    }
    dumpDataStructures();
    exit(EX_OK);
}

/* virtual console procs are our kids, when they die we get a CHLD	(ksb)
 * which will send us here to clean up the exit code.  The lack of a
 * reader on the pseudo will cause us to notice the death in Kiddie...
 */
static void
#if USE_ANSI_PROTO
ReapVirt(GRPENT * pGE)
#else
ReapVirt(pGE)
    GRPENT *pGE;
#endif
{
    int pid;
    int UWbuf;
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

	for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	    if (pid != pCE->ipid)
		continue;

	    if (WIFEXITED(UWbuf))
		Info("%s: exit(%d) [%s]", pCE->server.string,
		     WEXITSTATUS(UWbuf), strtime(NULL));
	    if (WIFSIGNALED(UWbuf))
		Info("%s: signal(%d) [%s]", pCE->server.string,
		     WTERMSIG(UWbuf), strtime(NULL));

	    /* If someone was writing, they fall back to read-only */
	    if (pCE->pCLwr != (CONSCLIENT *) 0) {
		pCE->pCLwr->fwr = 0;
		pCE->pCLwr->fwantwr = 1;
		tagLogfile(pCE, "%s detached", pCE->pCLwr->acid.string);
		pCE->pCLwr = (CONSCLIENT *) 0;
	    }

	    if (fNoautoreup &&
		!(WIFEXITED(UWbuf) && WEXITSTATUS(UWbuf) == 0)) {
		ConsDown(pCE, &pGE->rinit);
	    } else {
		/* Try an initial reconnect */
		Info("%s: automatic reinitialization [%s]",
		     pCE->server.string, strtime(NULL));
		ConsInit(pCE, &pGE->rinit, 0);

		/* If we didn't succeed, try again later */
		if (!pCE->fup)
		    pCE->autoReUp = 1;
		else
		    pCE->pCLwr = FindWrite(pCE->pCLon);
	    }
	}
    }
}

static char acStop[] = {	/* buffer for oob stop command          */
    OB_SUSP
};

int
#if USE_ANSI_PROTO
CheckPasswd(CONSCLIENT * pCLServing, char *pw_string)
#else
CheckPasswd(pCLServing, pw_string)
    CONSCLIENT *pCLServing;
    char *pw_string;
#endif
{
    FILE *fp;
    int iLine = 0;
    char *server, *servers, *this_pw, *user;
    static STRING username = { (char *)0, 0, 0 };

    buildMyString((char *)0, &username);
    buildMyString(pCLServing->acid.string, &username);
    if ((user = strchr(username.string, '@')))
	*user = '\000';

    if ((fp = fopen(pcPasswd, "r")) == (FILE *) 0) {
	Info("Cannot open passwd file %s: %s", pcPasswd, strerror(errno));

	if (CheckPass("root", pw_string) == AUTH_SUCCESS) {
	    if (fVerbose)
		Info("User %s authenticated into server %s via root passwd", pCLServing->acid.string, pCLServing->pCEwant->server.string);
	    return AUTH_SUCCESS;
	}
    } else {
	char *wholeLine;
	STRING saveLine = { (char *)0, 0, 0 };

	while ((wholeLine = readLine(fp, &saveLine, &iLine)) != (char *)0) {
	    pruneSpace(wholeLine);
	    /*printf("whole=<%s>\n", wholeLine); */
	    if (wholeLine[0] == '\000')
		continue;

	    if ((char *)0 == (this_pw = strchr(wholeLine, ':')) ||
		(char *)0 == (servers = strchr(this_pw + 1, ':'))) {
		Error("%s(%d) bad password line `%s'", pcPasswd, iLine,
		      wholeLine);
		continue;
	    }
	    *this_pw++ = '\000';
	    *servers++ = '\000';
	    user = pruneSpace(wholeLine);
	    this_pw = pruneSpace(this_pw);
	    servers = pruneSpace(servers);

	    /*
	       printf
	       ("Got servers <%s> passwd <%s> user <%s>, want <%s>\n",
	       servers, this_pw, user, pCLServing->pCEwant->server.string);
	     */

	    if (strcmp(user, "*any*") != 0 &&
		strcmp(user, username.string) != 0)
		continue;

	    /* If one is empty and the other isn't, instant failure */
	    if ((*this_pw == '\000' && *pw_string != '\000') ||
		(*this_pw != '\000' && *pw_string == '\000')) {
		break;
	    }

	    if ((*this_pw == '\000' && *pw_string == '\000') ||
		((strcmp(this_pw, "*passwd*") ==
		  0) ? (CheckPass(username.string,
				  pw_string) ==
			AUTH_SUCCESS) : (strcmp(this_pw,
						crypt(pw_string,
						      this_pw)) == 0))) {
		server = strtok(servers, ", \t\n");
		while (server) {	/* For each server */
		    if (strcmp(server, "any") == 0) {
			if (fVerbose) {
			    Info("User %s authenticated into server %s",
				 pCLServing->acid.string,
				 pCLServing->pCEwant->server.string);
			}
			fclose(fp);
			return AUTH_SUCCESS;
		    } else {
			char *p;
			int status;
			static STRING tomatch = { (char *)0, 0, 0 };
#if HAVE_POSIX_REGCOMP
			regex_t re;
#endif
			buildMyString((char *)0, &tomatch);
#if HAVE_POSIX_REGCOMP
			buildMyStringChar('^', &tomatch);
			buildMyString(server, &tomatch);
			buildMyStringChar('$', &tomatch);
#else
			buildMyString(server, &tomatch);
#endif
			p = pCLServing->pCEwant->server.string;
			while (p != (char *)0) {
#if HAVE_POSIX_REGCOMP
			    if (regcomp(&re, tomatch.string, REG_NOSUB)
				!= 0) {
				Error
				    ("%s(%d) server name `%s' not a valid regular expression",
				     pcPasswd, iLine, server);
				break;
			    }
			    status = regexec(&re, p, 0, NULL, 0);
			    regfree(&re);
#else
			    status = strcmp(tomatch.string, p);
#endif
			    if (status == 0) {
				if (fVerbose) {
				    Info("User %s authenticated into server %s", pCLServing->acid.string, pCLServing->pCEwant->server.string);
				}
				fclose(fp);
				return AUTH_SUCCESS;
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
	    break;
	}
	fclose(fp);
    }

    return AUTH_INVALID;
}

static char *
#if USE_ANSI_PROTO
IdleTyme(long tyme)
#else
IdleTyme(tyme)
    long tyme;
#endif
{
    static char timestr[100];	/* Don't want to overrun the array... */
    long hours, minutes;

    minutes = tyme / 60;
    hours = minutes / 60;
    minutes = minutes % 60;

    if (hours < 24)
	sprintf(timestr, " %2ld:%02ld", hours, minutes);
    else if (hours < 24 * 2)
	sprintf(timestr, " 1 day");
    else if (hours < 24 * 10)
	sprintf(timestr, "%1ld days", hours / 24);
    else
	sprintf(timestr, "%2lddays", hours / 24);

    return timestr;
}

void
#if USE_ANSI_PROTO
putConsole(CONSENT * pCEServing, unsigned char c)
#else
putConsole(pCEServing, c)
    CONSENT *pCEServing;
    unsigned char c;
#endif
{
    if (pCEServing->isNetworkConsole && (c == IAC))
	(void)write(pCEServing->fdtty, &c, 1);
    (void)write(pCEServing->fdtty, &c, 1);
}

void
#if USE_ANSI_PROTO
sendRealBreak(CONSCLIENT * pCLServing, CONSENT * pCEServing)
#else
sendRealBreak(pCLServing, pCEServing)
    CONSCLIENT *pCLServing;
    CONSENT *pCEServing;
#endif
{
    Debug(1, "Sending a break to %s", pCEServing->server.string);
    if (pCEServing->isNetworkConsole) {
	unsigned char haltseq[2];

	haltseq[0] = IAC;
	haltseq[1] = BREAK;
	write(pCEServing->fdtty, haltseq, 2);
    } else {
#if HAVE_TERMIO_H
	if (-1 == ioctl(pCEServing->fdtty, TCSBRK, (char *)0)) {
	    fileWrite(pCLServing->fd, "failed]\r\n", -1);
	    return;
	}
#else
# if HAVE_TCSENDBREAK
	if (-1 == tcsendbreak(pCEServing->fdtty, 0)) {
	    fileWrite(pCLServing->fd, "failed]\r\n", -1);
	    return;
	}
# else
#  if HAVE_TERMIOS_H
	if (-1 == ioctl(pCEServing->fdtty, TIOCSBRK, (char *)0)) {
	    fileWrite(pCLServing->fd, "failed]\r\n", -1);
	    return;
	}
	fileWrite(pCLServing->fd, "- ", -1);
	usleep(999999);
	resetMark();
	if (-1 == ioctl(pCEServing->fdtty, TIOCCBRK, (char *)0)) {
	    fileWrite(pCLServing->fd, "failed]\r\n", -1);
	    return;
	}
#  endif
# endif
#endif
    }
}

void
#if USE_ANSI_PROTO
doBreakWork(CONSCLIENT * pCLServing, CONSENT * pCEServing, short int bt,
	    short int cleanup)
#else
doBreakWork(pCLServing, pCEServing, bt, cleanup)
    CONSCLIENT *pCLServing;
    CONSENT *pCEServing;
    short int bt;
    short int cleanup;
#endif
{
    char *p, s;
    short int backslash = 0, waszero = 0;
    short int cntrl;
    char oct[3];
    short int octs = -1;
    static STRING cleaned = { (char *)0, 0, 0 };

    buildMyString((char *)0, &cleaned);

    if (cleanup && (bt < 1 || bt > 9))
	return;
    if (bt < 0 || bt > 9) {
	if (!cleanup)
	    (void)fileWrite(pCLServing->fd, "aborted]\r\n", -1);
	return;
    }
    if (bt == 0) {
	bt = pCEServing->breakType;
	waszero = 1;
    }
    if (bt == 0 || breakList[bt - 1].used == 0) {
	if (!cleanup)
	    (void)fileWrite(pCLServing->fd, "undefined]\r\n", -1);
	return;
    }

    p = breakList[bt - 1].string;
    backslash = 0;
    cntrl = 0;
    while ((s = (*p++)) != '\000') {
	if (octs != -1) {
	    if (s >= '0' && s <= '7') {
		if (++octs < 3) {
		    oct[octs] = s;
		}
		continue;
	    } else {
		int i;
		if (octs > 2) {
		    Error("octal number too large in BREAK%d sequence",
			  bt);
		} else {
		    if (cleanup) {
			buildMyStringChar('\\', &cleaned);
			for (i = 0; i <= 1 - octs; i++)
			    buildMyStringChar('0', &cleaned);
			for (i = 0; i <= octs; i++)
			    buildMyStringChar(oct[i], &cleaned);
		    } else {
			char c = '\000';
			c = oct[0] - '0';
			for (i = 1; i <= octs; i++)
			    c = c * 8 + (oct[i] - '0');
			putConsole(pCEServing, c);
		    }
		}
		octs = -1;
	    }
	}
	if (s == '\\' && !cntrl) {
	    if (backslash) {
		if (cleanup)
		    buildMyString("\\\\", &cleaned);
		else
		    putConsole(pCEServing, s);
		backslash = 0;
	    } else
		backslash = 1;
	    continue;
	}
	if (backslash) {
	    char o = s;
	    if (s == 'a')
		s = '\a';
	    else if (s == 'b')
		s = '\b';
	    else if (s == 'f')
		s = '\f';
	    else if (s == 'n')
		s = '\n';
	    else if (s == 'r')
		s = '\r';
	    else if (s == 't')
		s = '\t';
	    else if (s == 'v')
		s = '\v';
	    else if (s == '^')
		s = '^';
	    else if (s == 'z') {
		if (cleanup)
		    buildMyString("\\z", &cleaned);
		else
		    (void)sendRealBreak(pCLServing, pCEServing);
		s = '\000';
	    } else if (s >= '0' && s <= '7') {
		if (++octs < 3) {
		    oct[octs] = s;
		}
		s = '\000';
	    } else {
		if (octs < 0) {
		    if (cleanup)
			buildMyStringChar(o, &cleaned);
		    else
			putConsole(pCEServing, s);
		    s = '\000';
		} else if (octs > 2) {
		    Error("octal number too large in BREAK%d sequence",
			  bt);
		    octs = -1;
		} else {
		    int i;
		    if (cleanup) {
			buildMyStringChar('\\', &cleaned);
			for (i = 0; i <= octs; i++)
			    buildMyStringChar(oct[i], &cleaned);
		    } else {
			char c = '\000';
			c = oct[0] - '0';
			for (i = 1; i <= octs; i++)
			    c = c * 8 + (oct[i] - '0');
			putConsole(pCEServing, c);
		    }
		    octs = -1;
		}
	    }
	    if (s != '\000') {
		if (cleanup) {
		    buildMyStringChar('\\', &cleaned);
		    buildMyStringChar(o, &cleaned);
		} else
		    putConsole(pCEServing, s);
	    }
	    backslash = 0;
	    continue;
	}
	if (s == '^') {
	    if (cntrl) {
		if (cleanup)
		    buildMyString("^^", &cleaned);
		else {
		    s = s & 0x1f;
		    putConsole(pCEServing, s);
		}
		cntrl = 0;
	    } else
		cntrl = 1;
	    continue;
	}
	if (cntrl) {
	    if (s == '?') {
		if (cleanup)
		    buildMyString("^?", &cleaned);
		else {
		    s = 0x7f;	/* delete */
		    putConsole(pCEServing, s);
		}
		continue;
	    }
	    if (cleanup) {
		buildMyStringChar('^', &cleaned);
		buildMyStringChar(s, &cleaned);
	    } else {
		s = s & 0x1f;
		putConsole(pCEServing, s);
	    }
	    cntrl = 0;
	    continue;
	}
	if (cleanup)
	    buildMyStringChar(s, &cleaned);
	else
	    putConsole(pCEServing, s);
    }

    if (octs > 2) {
	Error("octal number too large in BREAK%d sequence", bt);
    } else if (octs != -1) {
	int i;
	if (cleanup) {
	    buildMyStringChar('\\', &cleaned);
	    for (i = 0; i <= 1 - octs; i++)
		buildMyStringChar('0', &cleaned);
	    for (i = 0; i <= octs; i++)
		buildMyStringChar(oct[i], &cleaned);
	} else {
	    char c = '\000';
	    c = oct[0] - '0';
	    for (i = 1; i <= octs; i++)
		c = c * 8 + (oct[i] - '0');
	    putConsole(pCEServing, c);
	}
    }

    if (backslash)
	Error("trailing backslash ignored in BREAK%d sequence", bt);
    if (cntrl)
	Error("trailing circumflex ignored in BREAK%d sequence", bt);

    if (cleanup) {
	buildMyString((char *)0, &breakList[bt - 1]);
	buildMyString(cleaned.string, &breakList[bt - 1]);
    } else {
	fileWrite(pCLServing->fd, "sent]\r\n", -1);
	if (pCEServing->breaklog) {
	    if (waszero) {
		filePrint(pCEServing->fdlog,
			  "[-- break #0(%d) sent -- `%s' -- %s]\r\n", bt,
			  breakList[bt - 1].string, strtime(NULL));
	    } else {
		filePrint(pCEServing->fdlog,
			  "[-- break #%d sent -- `%s' -- %s]\r\n", bt,
			  breakList[bt - 1].string, strtime(NULL));
	    }
	}
    }
}

void
#if USE_ANSI_PROTO
sendBreak(CONSCLIENT * pCLServing, CONSENT * pCEServing, short int bt)
#else
sendBreak(pCLServing, pCEServing, bt)
    CONSCLIENT *pCLServing;
    CONSENT *pCEServing;
    short int bt;
#endif
{
    doBreakWork(pCLServing, pCEServing, bt, 0);
}

void
#if USE_ANSI_PROTO
cleanupBreak(short int bt)
#else
cleanupBreak(bt)
    short int bt;
#endif
{
    doBreakWork((CONSCLIENT *) 0, (CONSENT *) 0, bt, 1);
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
#if USE_ANSI_PROTO
Kiddie(GRPENT * pGE, CONSFILE * sfd)
#else
Kiddie(pGE, sfd)
    GRPENT *pGE;
    CONSFILE *sfd;
#endif
{
    CONSCLIENT *pCL,		/* console we must scan/notify          */
     *pCLServing;		/* client we are serving                */
    CONSENT *pCEServing,	/* console we are talking to            */
     *pCE;			/* the base of our console list         */
    GRPENT *pGEtmp;
    REMOTE *pRCtmp;
    int i, nr;
    struct hostent *hpPeer;
    time_t tyme;
    time_t lastup = time(NULL);	/* last time we tried to up all downed  */
    int fd;
    char cType;
    int maxfd;
    socklen_t so;
    fd_set rmask;
    unsigned char acOut[BUFSIZ], acIn[BUFSIZ], acInOrig[BUFSIZ];
#if HAVE_TERMIOS_H
    struct termios sbuf;
#else
# if HAVE_SGTTY_H
    struct sgttyb sty;
# endif
#endif

    /* nuke the other group lists - of no use in the child */
    while (pGroups != (GRPENT *) 0) {
	pGEtmp = pGroups->pGEnext;
	if (pGroups != pGE)
	    destroyGroup(pGroups);
	pGroups = pGEtmp;
    }
    pGroups = pGE;
    pGE->pGEnext = (GRPENT *) 0;

    /* nuke the remote consoles - of no use in the child */
    while (pRCList != (REMOTE *) 0) {
	pRCtmp = pRCList->pRCnext;
	destroyString(&pRCList->rserver);
	destroyString(&pRCList->rhost);
	free(pRCList);
	pRCList = pRCtmp;
    }

    pGE->pCEctl = (CONSENT *) calloc(1, sizeof(CONSENT));
    if (pGE->pCEctl == (CONSENT *) 0)
	OutOfMem();
    initString(&pGE->pCEctl->server);
    initString(&pGE->pCEctl->dfile);
    initString(&pGE->pCEctl->lfile);
    initString(&pGE->pCEctl->networkConsoleHost);
    initString(&pGE->pCEctl->acslave);

    /* turn off signals that master() might have turned on
     * (only matters if respawned)
     */
    simpleSignal(SIGQUIT, SIG_IGN);
    simpleSignal(SIGPIPE, SIG_IGN);
#if defined(SIGTTOU)
    simpleSignal(SIGTTOU, SIG_IGN);
#endif
#if defined(SIGTTIN)
    simpleSignal(SIGTTIN, SIG_IGN);
#endif
#if defined(SIGPOLL)
    simpleSignal(SIGPOLL, SIG_IGN);
#endif
    simpleSignal(SIGTERM, FlagGoAway);
    simpleSignal(SIGCHLD, FlagReapVirt);
    simpleSignal(SIGINT, FlagGoAwayAlso);

    sprintf((char *)acOut, "ctl_%d", pGE->port);
    buildMyString((char *)acOut, &pGE->pCEctl->server);
    pGE->pCEctl->iend = 0;
    buildMyString((char *)0, &pGE->pCEctl->lfile);
    buildMyString("/dev/null", &pGE->pCEctl->lfile);
    buildMyString((char *)0, &pGE->pCEctl->dfile);
    buildMyString("/dev/null", &pGE->pCEctl->dfile);
    /* below "" gets us the default parity and baud structs
     */
    pGE->pCEctl->pbaud = FindBaud("");
    pGE->pCEctl->pparity = FindParity("");
    pGE->pCEctl->fdlog = (CONSFILE *) 0;
    pGE->pCEctl->fdtty = pGE->pCEctl->ipid = -1;
    pGE->pCEctl->fup = 0;
    pGE->pCEctl->pCLon = pGE->pCEctl->pCLwr = (CONSCLIENT *) 0;

    /* set up stuff for the select() call once, then just copy it
     * rinit is all the fd's we might get data on, we copy it
     * to rmask before we call select, this saves lots of prep work
     * we used to do in the loop, but we have to mod rinit whenever
     * we add a connection or drop one...   (ksb)
     */
    maxfd = cmaxfiles();
    FD_ZERO(&pGE->rinit);
    FD_SET(fileFDNum(sfd), &pGE->rinit);
    /* open all the files we need for the consoles in our group
     * if we can't get one (bitch and) flag as down
     */
    if (!fNoinit)
	for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	    ConsInit(pCE, &pGE->rinit, 1);
	}

    /* set up the list of free connection slots
     */
    pGE->pCLfree = (CONSCLIENT *) calloc(cMaxMemb, sizeof(CONSCLIENT));
    if ((CONSCLIENT *) 0 == pGE->pCLfree)
	OutOfMem();
    for (i = 0; i < cMaxMemb - 1; ++i) {
	pGE->pCLfree[i].pCLnext = &pGE->pCLfree[i + 1];
    }

    /* on a SIGHUP we should close and reopen our log files
     */
    simpleSignal(SIGHUP, FlagReOpen);

    /* on a SIGUSR1 we try to bring up all downed consoles */
    simpleSignal(SIGUSR1, FlagReUp);

    /* on a SIGALRM we should mark log files */
    resetMark();

    /* the MAIN loop a group server
     */
    pGE->pCLall = (CONSCLIENT *) 0;
    while (1) {
	/* check signal flags */
	if (fSawGoAway) {
	    fSawGoAway = 0;
	    DeUtmp(pGE);
	}
	if (fSawReapVirt) {
	    fSawReapVirt = 0;
	    ReapVirt(pGE);
	}
	if (fSawReOpen) {
	    fSawReOpen = 0;
	    reopenLogfile();
	    ReReadCfg();
	    pGE = pGroups;
	    FD_SET(fileFDNum(sfd), &pGE->rinit);
	    ReOpen(pGE);
	    ReUp(pGE, 0);
	}
	if (fSawReUp) {
	    fSawReUp = 0;
	    ReUp(pGE, 0);

	    if (fReopenall) {
		lastup = time(NULL);
	    }
	}
	if (fSawMark) {
	    fSawMark = 0;
	    Mark(pGE);
	    ReUp(pGE, 1);
	}

	/* Is it time to reup everything? */
	if (fReopenall && ((time(NULL) - lastup) > (fReopenall * 60))) {
	    /* Note the new lastup time only after we finish.
	     */
	    ReUp(pGE, 2);
	    lastup = time(NULL);
	}

	rmask = pGE->rinit;

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
	for (pCEServing = pGE->pCElist; pCEServing != (CONSENT *) 0;
	     pCEServing = pCEServing->pCEnext) {
	    if (!pCEServing->fup || !FD_ISSET(pCEServing->fdtty, &rmask)) {
		continue;
	    }
	    /* read terminal line */
	    if ((nr =
		 read(pCEServing->fdtty, acInOrig,
		      sizeof(acInOrig))) <= 0) {
		/* carrier lost */
		Error("lost carrier on %s (%s)! [%s]",
		      pCEServing->server.string,
		      pCEServing->fvirtual ? pCEServing->acslave.
		      string : pCEServing->dfile.string, strtime(NULL));

		/* If someone was writing, they fall back to read-only */
		if (pCEServing->pCLwr != (CONSCLIENT *) 0) {
		    pCEServing->pCLwr->fwr = 0;
		    pCEServing->pCLwr->fwantwr = 1;
		    tagLogfile(pCEServing, "%s detached",
			       pCEServing->pCLwr->acid.string);
		    pCEServing->pCLwr = (CONSCLIENT *) 0;
		}

		if (fNoautoreup) {
		    ConsDown(pCEServing, &pGE->rinit);
		} else {
		    /* Try an initial reconnect */
		    Info("%s: automatic reinitialization [%s]",
			 pCEServing->server.string, strtime(NULL));
		    ConsInit(pCEServing, &pGE->rinit, 0);

		    /* If we didn't succeed, try again later */
		    if (!pCEServing->fup)
			pCEServing->autoReUp = 1;
		    else
			pCEServing->pCLwr = FindWrite(pCEServing->pCLon);
		}

		continue;
	    }
	    Debug(1, "Read %d bytes from fd %d", nr, pCEServing->fdtty);

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
			Debug(1, "%s: Got telnet `IAC'",
			      pCEServing->server.string);
			state = 1;
		    } else if (state == 1 && acInOrig[i] != IAC) {
			Debug(1, "%s: Got telnet cmd `%u'",
			      pCEServing->server.string, acInOrig[i]);
			if (acInOrig[i] == DONT || acInOrig[i] == DO ||
			    acInOrig[i] == WILL || acInOrig[i] == WONT)
			    state = 2;
			else
			    state = 0;
		    } else if (state == 2) {
			Debug(1, "%s: Got telnet option `%u'",
			      pCEServing->server.string, acInOrig[i]);
			state = 0;
		    } else {
			if (state == 5) {
			    state = 0;
			    if (acInOrig[i] == '\000')
				continue;
			}
			if (acInOrig[i] == IAC)
			    Debug(1, "%s: Quoted `IAC'",
				  pCEServing->server.string);
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
		(void)writeLog(pCEServing, (char *)acIn, nr);
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
		    if (pCEServing->server.used)
			write(1, pCEServing->server.string,
			      pCEServing->server.used - 1);
		    write(1, ": ", 2);
		    write(1, pCEServing->acline, pCEServing->iend);
		    pCEServing->iend = 0;
		}
	    }

	    /* write console info to clients (not suspended)
	     */
	    for (pCL = pCEServing->pCLon; (CONSCLIENT *) 0 != pCL;
		 pCL = pCL->pCLnext) {
		if (pCL->fcon) {
		    (void)fileWrite(pCL->fd, (char *)acIn, nr);
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
		if (pGE->pCEctl != pCEServing) {
		    Info("%s: logout %s [%s]", pCEServing->server.string,
			 pCLServing->acid.string, strtime(NULL));
		}
		if (fNoinit &&
		    (CONSCLIENT *) 0 == pCEServing->pCLon->pCLnext)
		    ConsDown(pCEServing, &pGE->rinit);

		FD_CLR(fileFDNum(pCLServing->fd), &pGE->rinit);
		fileClose(&pCLServing->fd);

		/* mark as not writer, if he is
		 * and turn logging back on...
		 */
		if (pCLServing->fwr) {
		    pCLServing->fwr = 0;
		    pCLServing->fwantwr = 0;
		    tagLogfile(pCEServing, "%s detached",
			       pCLServing->acid.string);
		    if (pCEServing->nolog) {
			pCEServing->nolog = 0;
			filePrint(pCEServing->fdlog,
				  "[-- Console logging restored (logout) -- %s]\r\n",
				  strtime(NULL));
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
		pCLServing->pCLnext = pGE->pCLfree;
		pGE->pCLfree = pCLServing;
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
			static STRING bcast = { (char *)0, 0, 0 };
			static STRING acA1 = { (char *)0, 0, 0 };
			static STRING acA2 = { (char *)0, 0, 0 };
		    case S_BCAST:
			/* gather message */
			if ('\r' != acIn[i]) {
			    if (acIn[i] == '\a' ||
				(acIn[i] >= ' ' && acIn[i] <= '~')) {
				buildMyStringChar(acIn[i],
						  &pCLServing->msg);
				if (pGE->pCEctl != pCEServing)
				    fileWrite(pCLServing->fd,
					      (char *)&acIn[i], 1);
			    } else if ((acIn[i] == '\b' || acIn[i] == 0x7f)
				       && pCLServing->msg.used > 1) {
				if (pCLServing->msg.
				    string[pCLServing->msg.used - 2] !=
				    '\a' && pGE->pCEctl != pCEServing) {
				    fileWrite(pCLServing->fd, "\b \b", 3);
				}
				pCLServing->msg.string[pCLServing->msg.
						       used - 2] = '\000';
				pCLServing->msg.used--;
			    }
			    continue;
			}
			fileWrite(pCLServing->fd, "]\r\n", 3);
			buildMyString((char *)0, &bcast);
			buildMyString("[", &bcast);
			if (pGE->pCEctl != pCEServing) {
			    buildMyString(pCLServing->acid.string, &bcast);
			    buildMyString(": ", &bcast);
			    buildMyString(pCLServing->msg.string, &bcast);
			} else {
			    char *msg;
			    if ((msg =
				 strchr(pCLServing->msg.string,
					':')) == (char *)0) {
				buildMyString(pCLServing->acid.string,
					      &bcast);
				msg = pCLServing->msg.string;
			    } else {
				*msg++ = '\000';
				buildMyString(pCLServing->msg.string,
					      &bcast);
				buildMyStringChar('@', &bcast);
				buildMyString(pCLServing->peername.string,
					      &bcast);
			    }
			    buildMyString("?: ", &bcast);
			    buildMyString(msg, &bcast);
			}
			buildMyString("]\r\n", &bcast);
			if (pGE->pCEctl != pCEServing)
			    SendClientsMsg(pCEServing, bcast.string);
			else
			    SendAllClientsMsg(pGE, bcast.string);

			buildMyString((char *)0, &pCLServing->msg);
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_IDENT:
			/* append chars to acid until [\r]\n
			 */
			if ('\n' != acIn[i]) {
			    buildMyStringChar(acIn[i], &pCLServing->acid);
			    continue;
			}
			if ((pCLServing->acid.used > 1) &&
			    ('\r' ==
			     pCLServing->acid.string[pCLServing->acid.
						     used - 2])) {
			    pCLServing->acid.string[pCLServing->acid.used -
						    2] = '\000';
			    pCLServing->acid.used--;
			}
			buildMyStringChar('@', &pCLServing->acid);
			buildMyString(pCLServing->peername.string,
				      &pCLServing->acid);
			Debug(1, "Client acid reinitialized to `%s'",
			      pCLServing->acid.string);
			buildMyString((char *)0, &pCLServing->accmd);
			fileWrite(pCLServing->fd, "host:\r\n", -1);
			pCLServing->iState = S_HOST;
			continue;

		    case S_HOST:
			/* append char to buffer, check for \n
			 * continue if incomplete
			 * else switch to new host
			 */
			if ('\n' != acIn[i]) {
			    buildMyStringChar(acIn[i], &pCLServing->accmd);
			    continue;
			}
			if ((pCLServing->accmd.used > 1) &&
			    ('\r' ==
			     pCLServing->accmd.string[pCLServing->accmd.
						      used - 2])) {
			    pCLServing->accmd.string[pCLServing->accmd.
						     used - 2] = '\000';
			    pCLServing->accmd.used--;
			}

			/* try to move to the given console
			 */
			pCLServing->pCEwant = (CONSENT *) 0;
			for (pCE = pGE->pCElist; pCE != (CONSENT *) 0;
			     pCE = pCE->pCEnext) {
			    if (0 ==
				strcmp(pCLServing->accmd.string,
				       pCE->server.string)) {
				pCLServing->pCEwant = pCE;
				buildMyString((char *)0,
					      &pCLServing->accmd);
				break;
			    }
			}
			if ((CONSENT *) 0 == pCLServing->pCEwant) {
			    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0;
				 pCE = pCE->pCEnext) {
				if (0 ==
				    strncmp(pCLServing->accmd.string,
					    pCE->server.string,
					    pCLServing->accmd.used - 1)) {
				    pCLServing->pCEwant = pCE;
				    buildMyString((char *)0,
						  &pCLServing->accmd);
				    break;
				}
			    }
			}
			if ((CONSENT *) 0 == pCLServing->pCEwant) {
			    filePrint(pCLServing->fd,
				      "%s: no such console\r\n",
				      pCLServing->accmd.string);
			    buildMyString((char *)0, &pCLServing->accmd);
			    goto drop;
			}
			buildMyString((char *)0, &pCLServing->accmd);

			if (('t' == pCLServing->caccess) ||
			    (CheckPasswd(pCLServing, "") ==
			     AUTH_SUCCESS)) {
			    goto shift_console;
			}
			fileWrite(pCLServing->fd, "passwd:\r\n", -1);
			pCLServing->iState = S_PASSWD;
			continue;

		    case S_PASSWD:
			/* gather passwd, check and drop or
			 * set new state
			 */
			if ('\n' != acIn[i]) {
			    buildMyStringChar(acIn[i], &pCLServing->accmd);
			    continue;
			}
			if ((pCLServing->accmd.used > 1) &&
			    ('\r' ==
			     pCLServing->accmd.string[pCLServing->accmd.
						      used - 2])) {
			    pCLServing->accmd.string[pCLServing->accmd.
						     used - 2] = '\000';
			    pCLServing->accmd.used--;
			}

			if (CheckPasswd
			    (pCLServing,
			     pCLServing->accmd.string) != AUTH_SUCCESS) {
			    fileWrite(pCLServing->fd, "Sorry.\r\n", -1);
			    Info("%s: %s: bad passwd",
				 pCLServing->pCEwant->server.string,
				 pCLServing->acid.string);
			    buildMyString((char *)0, &pCLServing->accmd);
			    goto drop;
			}
			buildMyString((char *)0, &pCLServing->accmd);
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
				       pCLServing->acid.string);
			    pCEServing->pCLwr =
				FindWrite(pCEServing->pCLon);
			}

			/* inform operators of the change
			 */
			if (pGE->pCEctl == pCEServing) {
			    Info("%s: login %s [%s]",
				 pCLServing->pCEwant->server.string,
				 pCLServing->acid.string, strtime(NULL));
			} else {
			    Info("%s moves from %s to %s [%s]",
				 pCLServing->acid.string,
				 pCEServing->server.string,
				 pCLServing->pCEwant->server.string,
				 strtime(NULL));
			}

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

			/* try to reopen line if specified at server startup
			 */
			if ((fNoinit || fReopen) && !pCEServing->fup)
			    ConsInit(pCEServing, &pGE->rinit, 0);

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
			    pCEServing->iend = 0;
			    tagLogfile(pCEServing, "%s attached",
				       pCLServing->acid.string);
			} else {
			    fileWrite(pCLServing->fd, "spy]\r\n", -1);
			}
			pCLServing->fcon = 1;
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_QUOTE:	/* send octal code              */
			/* must type in 3 octal digits */
			if (acIn[i] >= '0' && acIn[i] <= '7') {
			    buildMyStringChar(acIn[i], &pCLServing->accmd);
			    if (pCLServing->accmd.used < 4) {
				fileWrite(pCLServing->fd, (char *)&acIn[i],
					  1);
				continue;
			    }
			    fileWrite(pCLServing->fd, (char *)&acIn[i], 1);
			    fileWrite(pCLServing->fd, "]", 1);

			    pCLServing->accmd.string[0] =
				(((pCLServing->accmd.string[0] - '0') * 8 +
				  (pCLServing->accmd.string[1] -
				   '0')) * 8) +
				(pCLServing->accmd.string[2] - '0');
			    putConsole(pCEServing,
				       pCLServing->accmd.string[0]);
			    buildMyString((char *)0, &pCLServing->accmd);
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
				       pCLServing->acid.string);
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
			    putConsole(pCEServing, acIn[i]);
			    continue;
			}
			/* if the client is stuck in spy mode
			 * give them a clue as to how to get out
			 * (LLL nice to put chars out as ^Ec, rather
			 * than octal escapes, but....)
			 */
			if ('\r' == acIn[i] || '\n' == acIn[i]) {
			    filePrint(pCLServing->fd,
				      "[read-only -- use %s %s ? for help]\r\n",
				      FmtCtl(pCLServing->ic[0], &acA1),
				      FmtCtl(pCLServing->ic[1], &acA2));
			}
			continue;

		    case S_HALT1:	/* halt sequence? */
			pCLServing->iState = S_NORMAL;
			if (acIn[i] != '?' &&
			    (acIn[i] < '0' || acIn[i] > '9')) {
			    fileWrite(pCLServing->fd, "aborted]\r\n", -1);
			    continue;
			}

			if (acIn[i] == '?') {
			    int i;
			    fileWrite(pCLServing->fd, "list]\r\n", -1);
			    i = pCEServing->breakType;
			    if (i == 0 || breakList[i - 1].used == 0)
				(void)fileWrite(pCLServing->fd,
						" 0  <undefined>\r\n", -1);
			    else {
				filePrint(pCLServing->fd, " 0  `%s'\r\n",
					  breakList[i - 1].string);
			    }
			    for (i = 0; i < 9; i++) {
				if (breakList[i].used) {
				    filePrint(pCLServing->fd,
					      " %d  `%s'\r\n", i + 1,
					      breakList[i].string);
				}
			    }
			} else {
			    int bt = acIn[i] - '0';
			    (void)sendBreak(pCLServing, pCEServing, bt);
			}
			continue;

		    case S_CATTN:	/* redef escape sequence? */
			pCLServing->ic[0] = acInOrig[i];
			FmtCtl(acInOrig[i], &acA1);
			filePrint(pCLServing->fd, "%s ", acA1.string);
			pCLServing->iState = S_CESC;
			continue;

		    case S_CESC:	/* escape sequent 2 */
			pCLServing->ic[1] = acInOrig[i];
			pCLServing->iState = S_NORMAL;
			FmtCtl(acInOrig[i], &acA1);
			filePrint(pCLServing->fd, "%s  ok]\r\n",
				  acA1.string);
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
				putConsole(pCEServing, acIn[i]);
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
			    putConsole(pCEServing, c);
			    putConsole(pCEServing, acIn[i]);
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
				if (pGE->pCEctl != pCLServing->pCEto) {
				    goto unknown;
				}
				fileWrite(pCLServing->fd, "login:\r\n",
					  -1);
				buildMyString((char *)0,
					      &pCLServing->acid);
				pCLServing->iState = S_IDENT;
				break;

			    case 'b':	/* broadcast message */
			    case 'B':
				fileWrite(pCLServing->fd,
					  "Enter message: ", -1);
				pCLServing->iState = S_BCAST;
				break;

			    case 'a':	/* attach */
			    case 'A':
				if (pGE->pCEctl == pCEServing) {
				    fileWrite(pCLServing->fd,
					      "no -- on ctl]\r\n", -1);
				} else if (!pCEServing->fup) {
				    fileWrite(pCLServing->fd,
					      "line to host is down]\r\n",
					      -1);
				} else if (pCEServing->fronly) {
				    fileWrite(pCLServing->fd,
					      "host is read-only]\r\n",
					      -1);
				} else if ((CONSCLIENT *) 0 ==
					   (pCL = pCEServing->pCLwr)) {
				    pCEServing->pCLwr = pCLServing;
				    pCLServing->fwr = 1;
				    if (pCEServing->nolog) {
					fileWrite(pCLServing->fd,
						  "attached (nologging)]\r\n",
						  -1);
				    } else {
					fileWrite(pCLServing->fd,
						  "attached]\r\n", -1);
				    }
				    tagLogfile(pCEServing, "%s attached",
					       pCLServing->acid.string);
				} else if (pCL == pCLServing) {
				    if (pCEServing->nolog) {
					fileWrite(pCLServing->fd,
						  "ok (nologging)]\r\n",
						  -1);
				    } else {
					fileWrite(pCLServing->fd,
						  "ok]\r\n", -1);
				    }
				} else {
				    pCLServing->fwantwr = 1;
				    filePrint(pCLServing->fd,
					      "no, %s is attached]\r\n",
					      pCL->acid.string);
				}
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
				if (pGE->pCEctl == pCEServing) {
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
					   pCLServing->acid.string);
				ConsDown(pCEServing, &pGE->rinit);
				fileWrite(pCLServing->fd, "line down]\r\n",
					  -1);

				/* tell all who closed it */
				for (pCL = pCEServing->pCLon;
				     (CONSCLIENT *) 0 != pCL;
				     pCL = pCL->pCLnext) {
				    if (pCL == pCLServing)
					continue;
				    if (pCL->fcon) {
					filePrint(pCL->fd,
						  "[line down by %s]\r\n",
						  pCLServing->acid.string);
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
				if (pGE->pCEctl == pCEServing) {
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
					filePrint(pCLServing->fd,
						  "bumped %s (nologging)]\r\n",
						  pCL->acid.string);
				    } else {
					filePrint(pCLServing->fd,
						  "bumped %s]\r\n",
						  pCL->acid.string);
				    }
				    (void)fileWrite(pCL->fd,
						    "\r\n[forced to `spy\' mode by ",
						    -1);
				    (void)fileWrite(pCL->fd,
						    pCLServing->acid.
						    string, -1);
				    (void)fileWrite(pCL->fd, "]\r\n", -1);
				    tagLogfile(pCEServing, "%s bumped %s",
					       pCLServing->acid.string,
					       pCL->acid.string);
				} else {
				    if (pCEServing->nolog) {
					fileWrite(pCLServing->fd,
						  "attached (nologging)]\r\n",
						  -1);
				    } else {
					fileWrite(pCLServing->fd,
						  "attached]\r\n", -1);
				    }
				    tagLogfile(pCEServing, "%s attached",
					       pCLServing->acid.string);
				}
				pCEServing->pCLwr = pCLServing;
				pCLServing->fwr = 1;
				break;

			    case 'g':	/* group info */
			    case 'G':
				/* we do not show the ctl console
				 * else we'd get the client always
				 */
				filePrint(pCLServing->fd, "group %s]\r\n",
					  pGE->pCEctl->server.string);
				for (pCL = pGE->pCLall;
				     (CONSCLIENT *) 0 != pCL;
				     pCL = pCL->pCLscan) {
				    if (pGE->pCEctl == pCL->pCEto)
					continue;
				    sprintf((char *)acOut,
					    " %-32.32s %c %-7.7s %6s ",
					    pCL->acid.string,
					    pCL == pCLServing ? '*' : ' ',
					    pCL->fcon ? (pCL->
							 fwr ? "attach" :
							 "spy") :
					    "stopped",
					    IdleTyme(tyme - pCL->typetym));
				    fileWrite(pCLServing->fd,
					      (char *)acOut, -1);
				    filePrint(pCLServing->fd, "%s\r\n",
					      pCL->pCEto->server.string);
				}
				break;

			    case 'P':	/* DEC vt100 pf1 */
			    case 'h':	/* help                 */
			    case 'H':
			    case '?':
				HelpUser(pCLServing);
				break;

			    case 'i':
			    case 'I':
				fileWrite(pCLServing->fd, "info]\r\n", -1);
				for (pCE = pGE->pCElist;
				     pCE != (CONSENT *) 0;
				     pCE = pCE->pCEnext) {
				    int comma = 0;
				    filePrint(pCLServing->fd,
					      "%s:%s,%d,%d:",
					      pCE->server.string, acMyHost,
					      thepid, pGE->port);
				    if (pCE->fvirtual) {
					filePrint(pCLServing->fd,
						  "|:%s,%d,%s",
						  ((pCE->pccmd.used ==
						    0) ? "/bin/sh" : pCE->
						   pccmd.string),
						  pCE->ipid,
						  pCE->acslave.string);
				    } else if (pCE->isNetworkConsole) {
					filePrint(pCLServing->fd,
						  "!:%s,%d",
						  pCE->networkConsoleHost.
						  string,
						  pCE->networkConsolePort);
				    } else {
					filePrint(pCLServing->fd,
						  "/:%s,%s%c",
						  pCE->dfile.string,
						  (pCE->pbaud ? pCE->
						   pbaud->acrate : ""),
						  (pCE->pparity ? pCE->
						   pparity->ckey : ' '));
				    }
				    filePrint(pCLServing->fd, ",%d:",
					      pCE->fdtty);
				    if (pCE->pCLwr) {
					filePrint(pCLServing->fd,
						  "w@%s@%ld",
						  pCE->pCLwr->acid.string,
						  tyme -
						  pCE->pCLwr->typetym);
					comma = 1;
				    }

				    for (pCL = pCE->pCLon;
					 (CONSCLIENT *) 0 != pCL;
					 pCL = pCL->pCLnext) {
					if (pCL == pCE->pCLwr)
					    continue;
					if (comma)
					    filePrint(pCLServing->fd, ",");
					if (pCL->fcon)
					    filePrint(pCLServing->fd,
						      "r@%s@%ld@%s",
						      pCL->acid.string,
						      tyme - pCL->typetym,
						      pCL->
						      fwantwr ? "rw" :
						      "ro");
					else
					    filePrint(pCLServing->fd,
						      "s@%s@%ld@%s",
						      pCL->acid.string,
						      tyme - pCL->typetym,
						      pCL->
						      fwantwr ? "rw" :
						      "ro");
					comma = 1;
				    }

				    filePrint(pCLServing->fd,
					      ":%s:%s:%s,%s,%s,%s,%d,%d:%d:%s\r\n",
					      (pCE->fup ? "up" : "down"),
					      (pCE->fronly ? "ro" : "rw"),
					      pCE->lfile.string,
					      (pCE->
					       nolog ? "nolog" : "log"),
					      (pCE->
					       activitylog ? "act" :
					       "noact"),
					      (pCE->
					       breaklog ? "brk" : "nobrk"),
					      pCE->mark,
					      (pCE->fdlog ? pCE->fdlog->
					       fd : -1), pCE->breakType,
					      (pCE->
					       autoReUp ? "autoup" :
					       "noautoup"));
				}
				break;
			    case 'L':
				if (pCLServing->fwr) {
				    pCEServing->nolog = !pCEServing->nolog;
				    if (pCEServing->nolog) {
					fileWrite(pCLServing->fd,
						  "logging off]\r\n", -1);
					filePrint(pCEServing->fdlog,
						  "[-- Console logging disabled by %s -- %s]\r\n",
						  pCLServing->acid.string,
						  strtime(NULL));
				    } else {
					fileWrite(pCLServing->fd,
						  "logging on]\r\n", -1);
					filePrint(pCEServing->fdlog,
						  "[-- Console logging restored by %s -- %s]\r\n",
						  pCLServing->acid.string,
						  strtime(NULL));
				    }
				} else {
				    filePrint(pCLServing->fd,
					      "read-only -- use %s %s ? for help]\r\n",
					      FmtCtl(pCLServing->ic[0],
						     &acA1),
					      FmtCtl(pCLServing->ic[1],
						     &acA2));
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
				if (pGE->pCEctl == pCEServing) {
				    fileWrite(pCLServing->fd,
					      "no -- on ctl]\r\n", -1);
				    continue;
				}
				/* with a close/re-open we might
				 * change fd's
				 */
				ConsInit(pCEServing, &pGE->rinit, 0);
				if (!pCEServing->fup) {
				    fileWrite(pCLServing->fd,
					      "line to host is down]\r\n",
					      -1);
				} else if (pCEServing->fronly) {
				    fileWrite(pCLServing->fd,
					      "up read-only]\r\n", -1);
				} else if ((CONSCLIENT *) 0 ==
					   (pCL = pCEServing->pCLwr)) {
				    pCEServing->pCLwr = pCLServing;
				    pCLServing->fwr = 1;
				    fileWrite(pCLServing->fd,
					      "up -- attached]\r\n", -1);
				    tagLogfile(pCEServing, "%s attached",
					       pCLServing->acid.string);
				} else if (pCL == pCLServing) {
				    fileWrite(pCLServing->fd, "up]\r\n",
					      -1);
				    tagLogfile(pCEServing, "%s attached",
					       pCLServing->acid.string);
				} else {
				    filePrint(pCLServing->fd,
					      "up, %s is attached]\r\n",
					      pCL->acid.string);
				}
				break;

			    case '\022':	/* ^R */
				fileWrite(pCLServing->fd, "^R]\r\n", -1);
				Replay(pCEServing->fdlog, pCLServing->fd,
				       1);
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
					   pCLServing->acid.string);
				pCEServing->pCLwr =
				    FindWrite(pCEServing->pCLon);
				fileWrite(pCLServing->fd, "spying]\r\n",
					  -1);
				break;

			    case 'u':	/* hosts on server this */
			    case 'U':
				fileWrite(pCLServing->fd, "hosts]\r\n",
					  -1);
				for (pCE = pGE->pCElist;
				     pCE != (CONSENT *) 0;
				     pCE = pCE->pCEnext) {
				    sprintf((char *)acOut,
					    " %-24.24s %c %-4.4s %-.40s\r\n",
					    pCE->server.string,
					    pCE == pCEServing ? '*' : ' ',
					    pCE->fup ? "up" : "down",
					    pCE->pCLwr ? pCE->pCLwr->acid.
					    string : pCE->
					    pCLon ? "<spies>" : "<none>");
				    (void)fileWrite(pCLServing->fd,
						    (char *)acOut, -1);
				}
				break;

			    case 'v':	/* version */
			    case 'V':
				filePrint(pCLServing->fd,
					  "version `%s\']\r\n",
					  THIS_VERSION);
				break;

			    case 'w':	/* who */
			    case 'W':
				filePrint(pCLServing->fd, "who %s]\r\n",
					  pCEServing->server.string);
				for (pCL = pCEServing->pCLon;
				     (CONSCLIENT *) 0 != pCL;
				     pCL = pCL->pCLnext) {
				    sprintf((char *)acOut,
					    " %-32.32s %c %-7.7s %6s %s\r\n",
					    pCL->acid.string,
					    pCL == pCLServing ? '*' : ' ',
					    pCL->fcon ? (pCL->
							 fwr ? "attach" :
							 "spy") :
					    "stopped",
					    IdleTyme(tyme - pCL->typetym),
					    pCL->actym);
				    (void)fileWrite(pCLServing->fd,
						    (char *)acOut, -1);
				}
				break;

			    case 'x':
			    case 'X':
				fileWrite(pCLServing->fd, "examine]\r\n",
					  -1);
				for (pCE = pGE->pCElist;
				     pCE != (CONSENT *) 0;
				     pCE = pCE->pCEnext) {
				    sprintf((char *)acOut,
					    " %-24.24s on %-32.32s at %5.5s%c\r\n",
					    pCE->server.string,
					    pCE->fvirtual ? pCE->acslave.
					    string : pCE->dfile.string,
					    pCE->pbaud->acrate,
					    pCE->pparity->ckey);
				    (void)fileWrite(pCLServing->fd,
						    (char *)acOut, -1);
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
					       pCLServing->acid.string);
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
				buildMyString((char *)0,
					      &pCLServing->accmd);
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
	fd = accept(fileFDNum(sfd),
		    (struct sockaddr *)&pGE->pCLfree->cnct_port, &so);
	if (fd < 0) {
	    Error("accept: %s", strerror(errno));
	    continue;
	}

	pGE->pCLfree->fd = fileOpenFD(fd, simpleSocket);
	if ((CONSFILE *) 0 == pGE->pCLfree->fd) {
	    Error("fileOpenFD: %s", strerror(errno));
	    close(fd);
	    continue;
	}
#if defined(USE_LIBWRAP)
	{
	    struct request_info request;
	    request_init(&request, RQ_DAEMON, progname, RQ_FILE, fd, 0);
	    fromhost(&request);
	    if (!hosts_access(&request)) {
		fileWrite(pGE->pCLfree->fd,
			  "access from your host refused\r\n", -1);
		fileClose(&pGE->pCLfree->fd);
		resetMark();
		continue;
	    }
	    resetMark();
	}
#endif

	/* We use this information to verify                    (ksb)
	 * the source machine as being local.
	 */
	so = sizeof(in_port);
	if (-1 == getpeername(fd, (struct sockaddr *)&in_port, &so)) {
	    fileWrite(pGE->pCLfree->fd, "getpeername failed\r\n", -1);
	    fileClose(&pGE->pCLfree->fd);
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
	    fileWrite(pGE->pCLfree->fd,
		      "access from your host refused\r\n", -1);
	    fileClose(&pGE->pCLfree->fd);
	    continue;
	}

	/* save pCL so we can advance to the next free one
	 */
	pCL = pGE->pCLfree;
	pGE->pCLfree = pCL->pCLnext;

	/* init the identification stuff
	 */
	buildMyString((char *)0, &pCL->peername);
	if (hpPeer == (struct hostent *)0) {
	    buildMyString(inet_ntoa(in_port.sin_addr), &pCL->peername);
	} else {
	    buildMyString(hpPeer->h_name, &pCL->peername);
	}
	buildMyString((char *)0, &pCL->acid);
	buildMyString("<unknown>@", &pCL->acid);
	buildMyString(pCL->peername.string, &pCL->acid);
	Debug(1, "Client acid initialized to `%s'", pCL->acid.string);
	(void)strcpy(pCL->actym, strtime(&(pCL->tym)));
	pCL->typetym = pCL->tym;

	/* link into the control list for the dummy console
	 */
	pCL->pCEto = pGE->pCEctl;
	pCL->pCLnext = pGE->pCEctl->pCLon;
	pCL->ppCLbnext = &pGE->pCEctl->pCLon;
	if ((CONSCLIENT *) 0 != pCL->pCLnext) {
	    pCL->pCLnext->ppCLbnext = &pCL->pCLnext;
	}
	pGE->pCEctl->pCLon = pCL;

	/* link into all clients list
	 */
	pCL->pCLscan = pGE->pCLall;
	pCL->ppCLbscan = &pGE->pCLall;
	if ((CONSCLIENT *) 0 != pCL->pCLscan) {
	    pCL->pCLscan->ppCLbscan = &pCL->pCLscan;
	}
	pGE->pCLall = pCL;

	FD_SET(fileFDNum(pCL->fd), &pGE->rinit);

	/* init the fsm
	 */
	pCL->fecho = 0;
	pCL->iState = S_NORMAL;
	pCL->ic[0] = DEFATTN;
	pCL->ic[1] = DEFESC;
	pCL->caccess = cType;

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
	if ((CONSCLIENT *) 0 == pGE->pCLfree) {
	    pGE->pCLfree = (CONSCLIENT *) calloc(2, sizeof(CONSCLIENT));
	    if ((CONSCLIENT *) 0 == pGE->pCLfree) {
		OutOfMem();
	    } else {
		pGE->pCLfree->pCLnext = &pGE->pCLfree[1];
	    }
	}
    }
}

/* create a child process:						(fine)
 * fork off a process for each group with an open socket for connections
 */
void
#if USE_ANSI_PROTO
Spawn(GRPENT * pGE)
#else
Spawn(pGE)
    GRPENT *pGE;
#endif
{
    int pid, sfd;
    socklen_t so;
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
				(errno == EACCES))) {
	    lstn_port.sin_port = htons(bindBasePort + portInc);
	} else {
	    Error("bind: %s", strerror(errno));
	    exit(EX_UNAVAILABLE);
	}
    }
    so = sizeof(lstn_port);

    if (-1 == getsockname(sfd, (struct sockaddr *)&lstn_port, &so)) {
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
	    pGE->pid = thepid = getpid();
	    isMaster = 0;
	    break;
    }
    if (listen(sfd, SOMAXCONN) < 0) {
	Error("listen: %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    ssocket = fileOpenFD(sfd, simpleSocket);
    if ((CONSFILE *) 0 == ssocket) {
	Error("fileOpenFD: %s", strerror(errno));
	close(sfd);
	exit(EX_UNAVAILABLE);
    }
    Kiddie(pGE, ssocket);

    /* should never get here...
     */
    fileClose(&ssocket);
    Error("internal flow error");
    exit(EX_UNAVAILABLE);
}
