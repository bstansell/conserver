/*
 *  $Id: group.c,v 5.209 2003-03-10 17:30:58-08 bryan Exp $
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
#if PROTOTYPES
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
#include <util.h>

#include <consent.h>
#include <client.h>
#include <access.h>
#include <group.h>
#include <version.h>
#include <readcfg.h>
#include <main.h>


/* flags that a signal has occurred */
static sig_atomic_t fSawChldHUP = 0, fSawReUp = 0, fSawMark =
    0, fSawGoAway = 0, fSawReapVirt = 0, fSawChldUSR2 = 0;

void
#if PROTOTYPES
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
	    FileWrite(pCL->fd, message, -1);
	}
    }
}

void
#if PROTOTYPES
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
	    FileWrite(pCL->fd, message, -1);
	}
    }
}

void
#if PROTOTYPES
DisconnectClient(GRPENT * pGE, CONSCLIENT * pCL, char *message)
#else
DisconnectClient(pGE, pCL, message)
    GRPENT *pGE;
    CONSCLIENT *pCL;
    char *message;
#endif
{
    CONSENT *pCEServing;

    if (pGE == (GRPENT *) 0 || pCL == (CONSCLIENT *) 0) {
	return;
    }

    if (pCL->fcon) {
	FileWrite(pCL->fd, message, -1);
    }

    /* log it, drop from select list,
     * close gap in table, etc, etc...
     */
    pCEServing = pCL->pCEto;

    if (pGE->pCEctl != pCEServing) {
	Msg("[%s] logout %s", pCEServing->server.string, pCL->acid.string);
    }

    if (fNoinit && pCEServing->pCLon->pCLnext == (CONSCLIENT *) 0)
	ConsDown(pCEServing, &pGE->rinit);

    FD_CLR(FileFDNum(pCL->fd), &pGE->rinit);
    FileClose(&pCL->fd);

    /* mark as not writer, if he is
     * and turn logging back on...
     */
    if (pCL->fwr) {
	pCL->fwr = 0;
	pCL->fwantwr = 0;
	TagLogfile(pCEServing, "%s detached", pCL->acid.string);
	if (pCEServing->nolog) {
	    pCEServing->nolog = 0;
	    FilePrint(pCEServing->fdlog,
		      "[-- Console logging restored (logout) -- %s]\r\n",
		      StrTime(NULL));
	}
	pCEServing->pCLwr = FindWrite(pCEServing->pCLon);
    }

    /* mark as unconnected and remove from both
     * lists (all clients, and this console)
     */
    pCL->fcon = 0;
    if ((CONSCLIENT *) 0 != pCL->pCLnext) {
	pCL->pCLnext->ppCLbnext = pCL->ppCLbnext;
    }
    *(pCL->ppCLbnext) = pCL->pCLnext;
    if ((CONSCLIENT *) 0 != pCL->pCLscan) {
	pCL->pCLscan->ppCLbscan = pCL->ppCLbscan;
    }
    *(pCL->ppCLbscan) = pCL->pCLscan;

    /* the continue below will advance to a (ksb)
     * legal client, even though we are now closed
     * and in the fre list becasue pCLscan is used
     * for the free list
     */
    pCL->pCLnext = pGE->pCLfree;
    pGE->pCLfree = pCL;
}

void
#if PROTOTYPES
DisconnectAllClients(GRPENT * pGE, char *message)
#else
DisconnectAllClients(pGE, message)
    GRPENT *pGE;
    char *message;
#endif
{
    CONSCLIENT *pCL;

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    for (pCL = pGE->pCLall; (CONSCLIENT *) 0 != pCL; pCL = pCL->pCLscan) {
	DisconnectClient(pGE, pCL, message);
    }
}

void
#if PROTOTYPES
DestroyClient(CONSCLIENT * pCL)
#else
DestroyClient(pCL)
    CONSCLIENT *pCL;
#endif
{
    DestroyString(&pCL->acid);
    DestroyString(&pCL->peername);
    DestroyString(&pCL->accmd);
    DestroyString(&pCL->msg);
    FileClose(&pCL->fd);
    free(pCL);
}

void
#if PROTOTYPES
DestroyConsent(GRPENT * pGE, CONSENT * pCE)
#else
DestroyConsent(pGE, pCE)
    GRPENT *pGE;
    CONSENT *pCE;
#endif
{
    CONSCLIENT *pCL;
    CONSENT **ppCE;

    if (pCE == (CONSENT *) 0)
	return;

    Debug(1, "DestroyConsent(): destroying `%s'", pCE->server.string);

    /* must loop using pCLall and pCLscan for the same reason as the
     * drop: code.  this is basically the same set of code, but modified
     * since we know we're going to nuke the console itself.
     */
    for (pCL = pGE->pCLall; pCL != (CONSCLIENT *) 0; pCL = pCL->pCLscan) {
	if (pCL->pCEto != pCE)
	    continue;
	if (pCL->fcon) {
	    FileWrite(pCL->fd,
		      "[-- Conserver reconfigured - console has been (re)moved --]\r\n",
		      -1);
	}
	Msg("[%s] logout %s", pCE->server.string, pCL->acid.string);
	FD_CLR(FileFDNum(pCL->fd), &pGE->rinit);
	FileClose(&pCL->fd);
	if (pCL->fwr) {
	    TagLogfile(pCE, "%s detached", pCL->acid.string);
	    if (pCE->nolog) {
		pCE->nolog = 0;
		FilePrint(pCE->fdlog,
			  "[-- Console logging restored (logout) -- %s]\r\n",
			  StrTime(NULL));
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

    DestroyString(&pCE->server);
    DestroyString(&pCE->dfile);
    DestroyString(&pCE->lfile);
    DestroyString(&pCE->networkConsoleHost);
    DestroyString(&pCE->acslave);
    DestroyString(&pCE->pccmd);
    FileClose(&pCE->fdlog);
    free(pCE);

    pGE->imembers--;
}

void
#if PROTOTYPES
DestroyGroup(GRPENT * pGE)
#else
DestroyGroup(pGE)
    GRPENT *pGE;
#endif
{
    CONSENT *pCEtmp, *pCE;
    CONSCLIENT *pCLtmp, *pCL;

    if (pGE == (GRPENT *) 0)
	return;

    Debug(1, "DestroyGroup(): destroying group #%d (%d members)", pGE->id,
	  pGE->imembers);

    /* nuke each console (which kicks off clients) */
    DestroyConsent(pGE, pGE->pCEctl);
    pCE = pGE->pCElist;
    while (pCE != (CONSENT *) 0) {
	pCEtmp = pCE->pCEnext;
	DestroyConsent(pGE, pCE);
	pCE = pCEtmp;
    }

    /* now we can nuke the client structures */
    pCL = pGE->pCLall;
    while (pCL != (CONSCLIENT *) 0) {
	pCLtmp = pCL->pCLscan;
	DestroyClient(pCL);
	pCL = pCLtmp;
    }
    pCL = pGE->pCLfree;
    while (pCL != (CONSCLIENT *) 0) {
	pCLtmp = pCL->pCLnext;
	DestroyClient(pCL);
	pCL = pCLtmp;
    }

    free(pGE);
}

#if HAVE_PAM
int
#if PROTOTYPES
QuietConv(int num_msg, struct pam_message **msg,
	  struct pam_response **resp, void *appdata_ptr)
#else
QuietConv(num_msg, msg, resp, appdata_ptr)
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
#if PROTOTYPES
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
    conv.conv = &QuietConv;
    conv.appdata_ptr = (void *)&appdata;

    Debug(1, "CheckPass(): pam_start(conserver,%s,...)", pcUser);
    pam_error = pam_start("conserver", pcUser, &conv, &pamh);

    if (pam_error == PAM_SUCCESS) {
	pam_set_item(pamh, PAM_RHOST, "IHaveNoIdeaHowIGotHere");
	Debug(1, "CheckPass(): pam_authenticate(%s)", pcUser);
	pam_error = pam_authenticate(pamh, PAM_SILENT);
	if (pam_error == PAM_SUCCESS) {
	    Debug(1, "CheckPass(): pam_acct_mgmt(%s)", pcUser);
	    pam_error = pam_acct_mgmt(pamh, PAM_SILENT);
	    if (pam_error != PAM_SUCCESS) {
		Error("CheckPass(): PAM failure(%s): %s", pcUser,
		      pam_strerror(pamh, pam_error));
	    }
	} else if (pam_error != PAM_AUTH_ERR) {
	    Error("CheckPass(): PAM failure(%s): %s", pcUser,
		  pam_strerror(pamh, pam_error));
	}
	Debug(1, "CheckPass(): pam_end(%s)", pcUser);
	pam_end(pamh, pam_error);
	if (pam_error == PAM_ABORT)	/* things just got real bad */
	    fSawGoAway = 1;
    } else {
	Error("CheckPass(): PAM failure(%s): %s", pcUser,
	      pam_strerror(pamh, pam_error));
    }
    if (pam_error == PAM_SUCCESS)
	return AUTH_SUCCESS;
    if (pam_error == PAM_USER_UNKNOWN)
	return AUTH_NOUSER;
    return AUTH_INVALID;
#else /* getpw*() */
    struct passwd *pwd;
    int retval = AUTH_SUCCESS;
#if HAVE_GETSPNAM
    struct spwd *spwd;
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

/* on an HUP close and re-open log files so lop can trim them		(ksb)
 * and reread the configuration file
 * lucky for us: log file fd's can change async from the group driver!
 */
static RETSIGTYPE
#if PROTOTYPES
FlagSawChldHUP(int sig)
#else
FlagSawChldHUP(sig)
    int sig;
#endif
{
    fSawChldHUP = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGHUP, FlagSawChldHUP);
#endif
}

/* on an USR2 close and re-open log files so lop can trim them		(ksb)
 * lucky for us: log file fd's can change async from the group driver!
 */
static RETSIGTYPE
#if PROTOTYPES
FlagSawChldUSR2(int sig)
#else
FlagSawChldUSR2(sig)
    int sig;
#endif
{
    fSawChldUSR2 = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGUSR2, FlagSawChldUSR2);
#endif
}

static void
#if PROTOTYPES
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
	FileClose(&pCE->fdlog);
	if ((CONSFILE *) 0 ==
	    (pCE->fdlog =
	     FileOpen(pCE->lfile.string, O_RDWR | O_CREAT | O_APPEND,
		      0666))) {
	    Error("ReOpen(): cannot reopen log file `%s': %s",
		  pCE->lfile.string, strerror(errno));
	    continue;
	}
    }
}

static RETSIGTYPE
#if PROTOTYPES
FlagReUp(int sig)
#else
FlagReUp(sig)
    int sig;
#endif
{
    fSawReUp = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGUSR1, FlagReUp);
#endif
}

static void
#if PROTOTYPES
ReUp(GRPENT * pGE, short automatic)
#else
ReUp(pGE, automatic)
    GRPENT *pGE;
    short automatic;
#endif
{
    CONSENT *pCE;
    int autoReUp;
    static time_t lastup = (time_t) 0;	/* last time we tried to up all downed  */
    static time_t lastautoup = (time_t) 0;	/* last time we tried to autoup */

    if ((GRPENT *) 0 == pGE) {
	return;
    }

    if ((automatic == 1) && ((time(NULL) - lastautoup) < 60))
	return;
    if ((automatic == 2) &&
	(!fReopenall || ((time(NULL) - lastup) < (fReopenall * 60))))
	return;

    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	if (pCE->fup || fNoinit || (automatic == 1 && !pCE->autoReUp))
	    continue;
	autoReUp = pCE->autoReUp;
	if (automatic)
	    Msg("[%s] automatic reinitialization", pCE->server.string);
	ConsInit(pCE, &pGE->rinit, 1);
	if (pCE->fup)
	    pCE->pCLwr = FindWrite(pCE->pCLon);
	else if (automatic)
	    pCE->autoReUp = autoReUp;
    }

    /* update all the timers */
    if (automatic == 0)
	lastup = lastautoup = time(NULL);
    else if (automatic == 1)
	lastautoup = time(NULL);
    else if (automatic == 2)
	lastup = lastautoup = time(NULL);
}

static RETSIGTYPE
#if PROTOTYPES
FlagMark(int sig)
#else
FlagMark(sig)
    int sig;
#endif
{
    fSawMark = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGALRM, FlagMark);
#endif
}

/* various areas of the code (sometimes not even our own) mess with
 * the alarm signal, so this function is here to reset it to what
 * we need.  We do not actually set an alarm here, but set the flag
 * that will call Mark() which will set the next alarm.
 */
void
#if PROTOTYPES
ResetMark(void)
#else
ResetMark()
#endif
{
    SimpleSignal(SIGALRM, FlagMark);
    fSawMark = 1;
}

void
#if PROTOTYPES
TagLogfile(const CONSENT * pCE, const char *fmt, ...)
#else
TagLogfile(pCE, fmt, va_alist)
    const CONSENT *pCE;
    const char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if PROTOTYPES
    va_start(ap, fmt);
#else
    va_start(ap);
#endif

    if ((pCE == (CONSENT *) 0) || (pCE->fdlog == (CONSFILE *) 0) ||
	(pCE->activitylog == 0))
	return;

    FileWrite(pCE->fdlog, "[-- ", -1);
    FileVWrite(pCE->fdlog, fmt, ap);
    FilePrint(pCE->fdlog, " -- %s]\r\n", StrTime(NULL));
    va_end(ap);
}

static void
#if PROTOTYPES
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
    sprintf(acOut, "[-- MARK -- %s]\r\n", StrTime(&tyme));

    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	if ((CONSFILE *) 0 == pCE->fdlog) {
	    continue;
	}
	if ((pCE->nextMark > 0) && (tyme >= pCE->nextMark)) {
	    Debug(1, "Mark(): [-- MARK --] stamp added to %s",
		  pCE->lfile.string);
	    FileWrite(pCE->fdlog, acOut, -1);
	    /* Add as many pCE->mark values as necessary so that we move
	     * beyond the current time.
	     */
	    pCE->nextMark +=
		(((tyme - pCE->nextMark) / pCE->mark) + 1) * pCE->mark;
	}
    }
    if ((i = (60 - (tyme % 60))) <= 0) {
	i = 1;
    }
    alarm(i);
}

void
#if PROTOTYPES
WriteLog(CONSENT * pCE, char *s, int len)
#else
WriteLog(pCE, s, len)
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
	FileWrite(pCE->fdlog, s, len);
	return;
    }
    acOut[0] = '\000';
    for (j = 0; j < len; j++) {
	if (pCE->nextMark == 0) {
	    FileWrite(pCE->fdlog, s + i, j - i);
	    i = j;
	    if (acOut[0] == '\000') {
		sprintf(acOut, "[%s]", StrTime(NULL));
	    }
	    FileWrite(pCE->fdlog, acOut, -1);
	    pCE->nextMark = pCE->mark;
	}
	if (s[j] == '\n') {
	    Debug(1,
		  "WriteLog(): [%s] found newline (nextMark=%d, mark=%d)",
		  pCE->server.string, pCE->nextMark, pCE->mark);
	    pCE->nextMark++;
	}
    }
    if (i < j) {
	FileWrite(pCE->fdlog, s + i, j - i);
    }
}

static RETSIGTYPE
#if PROTOTYPES
FlagGoAway(int sig)
#else
FlagGoAway(sig)
    int sig;
#endif
{
    fSawGoAway = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGTERM, FlagGoAway);
#endif
}

/* yep, basically the same...ah well, maybe someday */
static RETSIGTYPE
#if PROTOTYPES
FlagGoAwayAlso(int sig)
#else
FlagGoAwayAlso(sig)
    int sig;
#endif
{
    fSawGoAway = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGINT, FlagGoAwayAlso);
#endif
}

#if HAVE_SIGACTION
static
#endif
  RETSIGTYPE
#if PROTOTYPES
FlagReapVirt(int sig)
#else
FlagReapVirt(sig)
    int sig;
#endif
{
    fSawReapVirt = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGCHLD, FlagReapVirt);
#endif
}

/* on a TERM we have to cleanup utmp entries (ask ptyd to do it)	(ksb)
 */
static void
#if PROTOTYPES
DeUtmp(GRPENT * pGE, CONSFILE * sfd)
#else
DeUtmp(pGE, sfd)
    GRPENT *pGE;
    CONSFILE *sfd;
#endif
{
    CONSENT *pCE;

    /* shut down the socket */
    FileClose(&sfd);

    /* say Bye to all connections */
    if ((GRPENT *) 0 != pGE) {
	DisconnectAllClients(pGE,
			     "[-- Console server shutting down --]\r\n");

	for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	    ConsDown(pCE, &pGE->rinit);
	}
    }

    DumpDataStructures();

    endpwent();
    Bye(EX_OK);
}

/* virtual console procs are our kids, when they die we get a CHLD	(ksb)
 * which will send us here to clean up the exit code.  The lack of a
 * reader on the pseudo will cause us to notice the death in Kiddie...
 */
static void
#if PROTOTYPES
ReapVirt(GRPENT * pGE)
#else
ReapVirt(pGE)
    GRPENT *pGE;
#endif
{
    pid_t pid;
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
		Msg("[%s] exit(%d)", pCE->server.string,
		    WEXITSTATUS(UWbuf));
	    if (WIFSIGNALED(UWbuf))
		Msg("[%s] signal(%d)", pCE->server.string,
		    WTERMSIG(UWbuf));

	    /* If someone was writing, they fall back to read-only */
	    if (pCE->pCLwr != (CONSCLIENT *) 0) {
		pCE->pCLwr->fwr = 0;
		pCE->pCLwr->fwantwr = 1;
		TagLogfile(pCE, "%s detached", pCE->pCLwr->acid.string);
		pCE->pCLwr = (CONSCLIENT *) 0;
	    }

	    if (fNoautoreup &&
		!(WIFEXITED(UWbuf) && WEXITSTATUS(UWbuf) == 0)) {
		ConsDown(pCE, &pGE->rinit);
	    } else {
		/* Try an initial reconnect */
		Msg("[%s] automatic reinitialization", pCE->server.string);
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

static char acStop[] = {	/* buffer for OOB stop command          */
    OB_SUSP
};

int
#if PROTOTYPES
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
    static STRING *username = (STRING *) 0;

    if (username == (STRING *) 0)
	username = AllocString();

    BuildString((char *)0, username);
    BuildString(pCLServing->acid.string, username);
    if ((user = strchr(username->string, '@')))
	*user = '\000';

    if ((fp = fopen(pcPasswd, "r")) == (FILE *) 0) {
	Msg("CheckPasswd(): cannot open passwd file %s: %s", pcPasswd,
	    strerror(errno));

	if (CheckPass("root", pw_string) == AUTH_SUCCESS) {
	    Msg("[%s] user %s authenticated via root passwd",
		pCLServing->pCEwant->server.string,
		pCLServing->acid.string);
	    return AUTH_SUCCESS;
	}
    } else {
	char *wholeLine;
	static STRING *saveLine = (STRING *) 0;

	if (saveLine == (STRING *) 0)
	    saveLine = AllocString();
	BuildString((char *)0, saveLine);

	while ((wholeLine = ReadLine(fp, saveLine, &iLine)) != (char *)0) {
	    PruneSpace(wholeLine);
	    /*printf("whole=<%s>\n", wholeLine); */
	    if (wholeLine[0] == '\000')
		continue;

	    if ((char *)0 == (this_pw = strchr(wholeLine, ':')) ||
		(char *)0 == (servers = strchr(this_pw + 1, ':'))) {
		Error("CheckPasswd(): %s(%d) bad password line `%s'",
		      pcPasswd, iLine, wholeLine);
		continue;
	    }
	    *this_pw++ = '\000';
	    *servers++ = '\000';
	    user = PruneSpace(wholeLine);
	    this_pw = PruneSpace(this_pw);
	    servers = PruneSpace(servers);

	    /*
	       printf
	       ("Got servers <%s> passwd <%s> user <%s>, want <%s>\n",
	       servers, this_pw, user, pCLServing->pCEwant->server.string);
	     */

	    if (strcmp(user, "*any*") != 0 &&
		strcmp(user, username->string) != 0)
		continue;

	    /* If one is empty and the other isn't, instant failure */
	    if ((*this_pw == '\000' && *pw_string != '\000') ||
		(*this_pw != '\000' && *pw_string == '\000')) {
		break;
	    }

	    if ((*this_pw == '\000' && *pw_string == '\000') ||
		((strcmp(this_pw, "*passwd*") ==
		  0) ? (CheckPass(username->string,
				  pw_string) ==
			AUTH_SUCCESS) : (strcmp(this_pw,
						crypt(pw_string,
						      this_pw)) == 0))) {
		server = strtok(servers, ", \t\n");
		while (server) {	/* For each server */
		    if (strcmp(server, "any") == 0) {
			Verbose("[%s] user %s authenticated",
				pCLServing->pCEwant->server.string,
				pCLServing->acid.string);
			fclose(fp);
			return AUTH_SUCCESS;
		    } else {
			char *p;
			int status;
			static STRING *tomatch = (STRING *) 0;
			if (tomatch == (STRING *) 0)
			    tomatch = AllocString();
#if HAVE_POSIX_REGCOMP
			regex_t re;
#endif
			BuildString((char *)0, tomatch);
#if HAVE_POSIX_REGCOMP
			BuildStringChar('^', tomatch);
			BuildString(server, tomatch);
			BuildStringChar('$', tomatch);
#else
			BuildString(server, tomatch);
#endif
			p = pCLServing->pCEwant->server.string;
			while (p != (char *)0) {
#if HAVE_POSIX_REGCOMP
			    if (regcomp(&re, tomatch->string, REG_NOSUB)
				!= 0) {
				Error
				    ("CheckPasswd(): %s(%d) server name `%s' not a valid regular expression",
				     pcPasswd, iLine, server);
				break;
			    }
			    status = regexec(&re, p, 0, NULL, 0);
			    regfree(&re);
#else
			    status = strcmp(tomatch->string, p);
#endif
			    if (status == 0) {
				Verbose("[%s] user %s authenticated",
					pCLServing->pCEwant->server.string,
					pCLServing->acid.string);
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
#if PROTOTYPES
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
#if PROTOTYPES
PutConsole(CONSENT * pCEServing, unsigned char c)
#else
PutConsole(pCEServing, c)
    CONSENT *pCEServing;
    unsigned char c;
#endif
{
    if (pCEServing->isNetworkConsole && (c == IAC))
	write(pCEServing->fdtty, &c, 1);
    write(pCEServing->fdtty, &c, 1);
}

void
#if PROTOTYPES
SendRealBreak(CONSCLIENT * pCLServing, CONSENT * pCEServing)
#else
SendRealBreak(pCLServing, pCEServing)
    CONSCLIENT *pCLServing;
    CONSENT *pCEServing;
#endif
{
    Debug(1, "SendRealBreak(): [%s] sending a break",
	  pCEServing->server.string);
    if (pCEServing->isNetworkConsole) {
	unsigned char haltseq[2];

	haltseq[0] = IAC;
	haltseq[1] = BREAK;
	write(pCEServing->fdtty, haltseq, 2);
    } else {
#if HAVE_TERMIO_H
	if (-1 == ioctl(pCEServing->fdtty, TCSBRK, (char *)0)) {
	    FileWrite(pCLServing->fd, "failed]\r\n", -1);
	    return;
	}
#else
# if HAVE_TCSENDBREAK
	if (-1 == tcsendbreak(pCEServing->fdtty, 0)) {
	    FileWrite(pCLServing->fd, "failed]\r\n", -1);
	    return;
	}
# else
#  if HAVE_TERMIOS_H
	if (-1 == ioctl(pCEServing->fdtty, TIOCSBRK, (char *)0)) {
	    FileWrite(pCLServing->fd, "failed]\r\n", -1);
	    return;
	}
	FileWrite(pCLServing->fd, "- ", -1);
	usleep(999999);
	ResetMark();
	if (-1 == ioctl(pCEServing->fdtty, TIOCCBRK, (char *)0)) {
	    FileWrite(pCLServing->fd, "failed]\r\n", -1);
	    return;
	}
#  endif
# endif
#endif
    }
}

void
#if PROTOTYPES
DoBreakWork(CONSCLIENT * pCLServing, CONSENT * pCEServing, short bt,
	    short cleanup)
#else
DoBreakWork(pCLServing, pCEServing, bt, cleanup)
    CONSCLIENT *pCLServing;
    CONSENT *pCEServing;
    short bt;
    short cleanup;
#endif
{
    char *p, s;
    short backslash = 0, waszero = 0;
    short cntrl;
    char oct[3];
    short octs = -1;
    static STRING *cleaned = (STRING *) 0;

    if (cleaned == (STRING *) 0)
	cleaned = AllocString();

    BuildString((char *)0, cleaned);

    if (cleanup && (bt < 1 || bt > 9))
	return;
    if (bt < 0 || bt > 9) {
	if (!cleanup)
	    FileWrite(pCLServing->fd, "aborted]\r\n", -1);
	return;
    }
    if (bt == 0) {
	bt = pCEServing->breakType;
	waszero = 1;
    }
    if (bt == 0 || breakList[bt - 1].used <= 1) {
	if (!cleanup)
	    FileWrite(pCLServing->fd, "undefined]\r\n", -1);
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
			BuildStringChar('\\', cleaned);
			for (i = 0; i <= 1 - octs; i++)
			    BuildStringChar('0', cleaned);
			for (i = 0; i <= octs; i++)
			    BuildStringChar(oct[i], cleaned);
		    } else {
			char c = '\000';
			c = oct[0] - '0';
			for (i = 1; i <= octs; i++)
			    c = c * 8 + (oct[i] - '0');
			PutConsole(pCEServing, c);
		    }
		}
		octs = -1;
	    }
	}
	if (s == '\\' && !cntrl) {
	    if (backslash) {
		if (cleanup)
		    BuildString("\\\\", cleaned);
		else
		    PutConsole(pCEServing, s);
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
		    BuildString("\\z", cleaned);
		else
		    SendRealBreak(pCLServing, pCEServing);
		s = '\000';
	    } else if (s >= '0' && s <= '7') {
		if (++octs < 3) {
		    oct[octs] = s;
		}
		s = '\000';
	    } else {
		if (octs < 0) {
		    if (cleanup)
			BuildStringChar(o, cleaned);
		    else
			PutConsole(pCEServing, s);
		    s = '\000';
		} else if (octs > 2) {
		    Error("octal number too large in BREAK%d sequence",
			  bt);
		    octs = -1;
		} else {
		    int i;
		    if (cleanup) {
			BuildStringChar('\\', cleaned);
			for (i = 0; i <= octs; i++)
			    BuildStringChar(oct[i], cleaned);
		    } else {
			char c = '\000';
			c = oct[0] - '0';
			for (i = 1; i <= octs; i++)
			    c = c * 8 + (oct[i] - '0');
			PutConsole(pCEServing, c);
		    }
		    octs = -1;
		}
	    }
	    if (s != '\000') {
		if (cleanup) {
		    BuildStringChar('\\', cleaned);
		    BuildStringChar(o, cleaned);
		} else
		    PutConsole(pCEServing, s);
	    }
	    backslash = 0;
	    continue;
	}
	if (s == '^') {
	    if (cntrl) {
		if (cleanup)
		    BuildString("^^", cleaned);
		else {
		    s = s & 0x1f;
		    PutConsole(pCEServing, s);
		}
		cntrl = 0;
	    } else
		cntrl = 1;
	    continue;
	}
	if (cntrl) {
	    if (s == '?') {
		if (cleanup)
		    BuildString("^?", cleaned);
		else {
		    s = 0x7f;	/* delete */
		    PutConsole(pCEServing, s);
		}
		continue;
	    }
	    if (cleanup) {
		BuildStringChar('^', cleaned);
		BuildStringChar(s, cleaned);
	    } else {
		s = s & 0x1f;
		PutConsole(pCEServing, s);
	    }
	    cntrl = 0;
	    continue;
	}
	if (cleanup)
	    BuildStringChar(s, cleaned);
	else
	    PutConsole(pCEServing, s);
    }

    if (octs > 2) {
	Error("octal number too large in BREAK%d sequence", bt);
    } else if (octs != -1) {
	int i;
	if (cleanup) {
	    BuildStringChar('\\', cleaned);
	    for (i = 0; i <= 1 - octs; i++)
		BuildStringChar('0', cleaned);
	    for (i = 0; i <= octs; i++)
		BuildStringChar(oct[i], cleaned);
	} else {
	    char c = '\000';
	    c = oct[0] - '0';
	    for (i = 1; i <= octs; i++)
		c = c * 8 + (oct[i] - '0');
	    PutConsole(pCEServing, c);
	}
    }

    if (backslash)
	Error("trailing backslash ignored in BREAK%d sequence", bt);
    if (cntrl)
	Error("trailing circumflex ignored in BREAK%d sequence", bt);

    if (cleanup) {
	BuildString((char *)0, &breakList[bt - 1]);
	BuildString(cleaned->string, &breakList[bt - 1]);
    } else {
	FileWrite(pCLServing->fd, "sent]\r\n", -1);
	if (pCEServing->breaklog) {
	    if (waszero) {
		FilePrint(pCEServing->fdlog,
			  "[-- break #0(%d) sent -- `%s' -- %s]\r\n", bt,
			  breakList[bt - 1].string, StrTime(NULL));
	    } else {
		FilePrint(pCEServing->fdlog,
			  "[-- break #%d sent -- `%s' -- %s]\r\n", bt,
			  breakList[bt - 1].string, StrTime(NULL));
	    }
	}
    }
}

void
#if PROTOTYPES
SendBreak(CONSCLIENT * pCLServing, CONSENT * pCEServing, short bt)
#else
SendBreak(pCLServing, pCEServing, bt)
    CONSCLIENT *pCLServing;
    CONSENT *pCEServing;
    short bt;
#endif
{
    DoBreakWork(pCLServing, pCEServing, bt, 0);
}

void
#if PROTOTYPES
CleanupBreak(short bt)
#else
CleanupBreak(bt)
    short bt;
#endif
{
    DoBreakWork((CONSCLIENT *) 0, (CONSENT *) 0, bt, 1);
}

#if HAVE_OPENSSL
int
#if PROTOTYPES
AttemptSSL(CONSCLIENT * pCL)
#else
AttemptSSL(pCL)
    CONSCLIENT *pCL;
#endif
{
    int sflags, fdnum;
    SSL *ssl;

    fdnum = FileFDNum(pCL->fd);
    if (ctx == (SSL_CTX *) 0) {
	Error("AttemptSSL(): WTF?  The SSL context disappeared?!?!?");
	exit(EX_UNAVAILABLE);
    }
    if (!(ssl = SSL_new(ctx))) {
	Error("AttemptSSL(): SSL_new() failed for client `%s' (fd %d)",
	      pCL->peername.string, fdnum);
	return 0;
    }
    FileSetSSL(pCL->fd, ssl);
    SSL_set_accept_state(ssl);
    SSL_set_fd(ssl, fdnum);
    Debug(1,
	  "AttemptSSL(): setting socket to blocking for client `%s' (fd %d)",
	  pCL->peername.string, fdnum);
    sflags = fcntl(fdnum, F_GETFL, 0);
    if (sflags != -1)
	fcntl(fdnum, F_SETFL, sflags & ~O_NONBLOCK);
    Debug(1, "AttemptSSL(): about to SSL_accept() for client `%s' (fd %d)",
	  pCL->peername.string, fdnum);
    if (SSL_accept(ssl) <= 0) {
	Error("SSL negotiation failed for client `%s'",
	      pCL->peername.string);
	ERR_print_errors_fp(stderr);
	SSL_free(ssl);
	if (sflags != -1)
	    fcntl(fdnum, F_SETFL, sflags);
	return 0;
    }
    Debug(1,
	  "AttemptSSL(): returning socket to non-blocking for client `%s' (fd %d)",
	  pCL->peername.string, fdnum);
    if (sflags != -1)
	fcntl(fdnum, F_SETFL, sflags);
    FileSetType(pCL->fd, SSLSocket);
    if (fDebug)
	Debug(1, "AttemptSSL(): SSL Connection: %s :: %s",
	      SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl));
    return 1;
}
#endif


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
#if PROTOTYPES
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
    int fd;
    char cType;
    int maxfd;
    socklen_t so;
    fd_set rmask;
    unsigned char acOut[BUFSIZ], acIn[BUFSIZ], acInOrig[BUFSIZ];
    static STRING *bcast = (STRING *) 0;
    static STRING *acA1 = (STRING *) 0;
    static STRING *acA2 = (STRING *) 0;
#if HAVE_TERMIOS_H
    struct termios sbuf;
#else
# if HAVE_SGTTY_H
    struct sgttyb sty;
# endif
#endif
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
    unsigned long dmallocMarkClientConnection = 0;
#endif


    if (bcast == (STRING *) 0)
	bcast = AllocString();
    if (acA1 == (STRING *) 0)
	acA1 = AllocString();
    if (acA2 == (STRING *) 0)
	acA2 = AllocString();

    /* nuke the other group lists - of no use in the child */
    while (pGroups != (GRPENT *) 0) {
	pGEtmp = pGroups->pGEnext;
	if (pGroups != pGE)
	    DestroyGroup(pGroups);
	pGroups = pGEtmp;
    }
    pGroups = pGE;
    pGE->pGEnext = (GRPENT *) 0;

    /* nuke the remote consoles - of no use in the child */
    while (pRCList != (REMOTE *) 0) {
	pRCtmp = pRCList->pRCnext;
	DestroyString(&pRCList->rserver);
	DestroyString(&pRCList->rhost);
	free(pRCList);
	pRCList = pRCtmp;
    }

    pGE->pCEctl = (CONSENT *) calloc(1, sizeof(CONSENT));
    if (pGE->pCEctl == (CONSENT *) 0)
	OutOfMem();
    InitString(&pGE->pCEctl->server);
    InitString(&pGE->pCEctl->dfile);
    InitString(&pGE->pCEctl->lfile);
    InitString(&pGE->pCEctl->networkConsoleHost);
    InitString(&pGE->pCEctl->acslave);

    /* turn off signals that master() might have turned on
     * (only matters if respawned)
     */
    SimpleSignal(SIGQUIT, SIG_IGN);
    SimpleSignal(SIGPIPE, SIG_IGN);
#if defined(SIGTTOU)
    SimpleSignal(SIGTTOU, SIG_IGN);
#endif
#if defined(SIGTTIN)
    SimpleSignal(SIGTTIN, SIG_IGN);
#endif
#if defined(SIGPOLL)
    SimpleSignal(SIGPOLL, SIG_IGN);
#endif
    SimpleSignal(SIGTERM, FlagGoAway);
    SimpleSignal(SIGCHLD, FlagReapVirt);
    SimpleSignal(SIGINT, FlagGoAwayAlso);

    sprintf((char *)acOut, "ctl_%hu", pGE->port);
    BuildString((char *)acOut, &pGE->pCEctl->server);
    pGE->pCEctl->iend = 0;
    BuildString((char *)0, &pGE->pCEctl->lfile);
    BuildString("/dev/null", &pGE->pCEctl->lfile);
    BuildString((char *)0, &pGE->pCEctl->dfile);
    BuildString("/dev/null", &pGE->pCEctl->dfile);
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
    maxfd = GetMaxFiles();
    FD_ZERO(&pGE->rinit);
    FD_SET(FileFDNum(sfd), &pGE->rinit);
    /* open all the files we need for the consoles in our group
     * if we can't get one (bitch and) flag as down
     */
    if (!fNoinit)
	ReUp(pGE, 0);

    /* prime the list of free connection slots
     */
    pGE->pCLfree = (CONSCLIENT *) calloc(1, sizeof(CONSCLIENT));
    if ((CONSCLIENT *) 0 == pGE->pCLfree)
	OutOfMem();

    /* on a SIGHUP we should close and reopen our log files and
     * reread the config file
     */
    SimpleSignal(SIGHUP, FlagSawChldHUP);

    /* on a SIGUSR2 we should close and reopen our log files
     */
    SimpleSignal(SIGUSR2, FlagSawChldUSR2);

    /* on a SIGUSR1 we try to bring up all downed consoles */
    SimpleSignal(SIGUSR1, FlagReUp);

    /* on a SIGALRM we should mark log files */
    ResetMark();

    /* the MAIN loop a group server
     */
    pGE->pCLall = (CONSCLIENT *) 0;
    while (1) {
	/* check signal flags */
	if (fSawGoAway) {
	    fSawGoAway = 0;
	    DeUtmp(pGE, sfd);
	}
	if (fSawReapVirt) {
	    fSawReapVirt = 0;
	    ReapVirt(pGE);
	}
	if (fSawChldHUP) {
	    fSawChldHUP = 0;
	    ReopenLogfile();
	    ReReadCfg();
	    pGE = pGroups;
	    FD_SET(FileFDNum(sfd), &pGE->rinit);
	    ReOpen(pGE);
	    ReUp(pGE, 0);
	}
	if (fSawChldUSR2) {
	    fSawChldUSR2 = 0;
	    ReopenLogfile();
	    ReOpen(pGE);
	    ReUp(pGE, 0);
	}
	if (fSawChldHUP) {
	    fSawChldHUP = 0;
	    ReopenLogfile();
	    ReReadCfg();
	    pGE = pGroups;
	    FD_SET(FileFDNum(sfd), &pGE->rinit);
	    ReOpen(pGE);
	    ReUp(pGE, 0);
	}
	if (fSawReUp) {
	    fSawReUp = 0;
	    ReUp(pGE, 0);
	}
	/* see if we need to bring things back up - this has to happen
	 * *before* ReUp(,1) otherwise we get double-reups */
	ReUp(pGE, 2);
	if (fSawMark) {
	    fSawMark = 0;
	    Mark(pGE);
	    ReUp(pGE, 1);
	}

	rmask = pGE->rinit;

	if (-1 ==
	    select(maxfd, &rmask, (fd_set *) 0, (fd_set *) 0,
		   (struct timeval *)0)) {
	    if (errno != EINTR) {
		Error("Kiddie(): select(): %s", strerror(errno));
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
		Error("[%s] lost carrier (%s)", pCEServing->server.string,
		      pCEServing->fvirtual ? pCEServing->acslave.
		      string : pCEServing->dfile.string);

		/* If someone was writing, they fall back to read-only */
		if (pCEServing->pCLwr != (CONSCLIENT *) 0) {
		    pCEServing->pCLwr->fwr = 0;
		    pCEServing->pCLwr->fwantwr = 1;
		    TagLogfile(pCEServing, "%s detached",
			       pCEServing->pCLwr->acid.string);
		    pCEServing->pCLwr = (CONSCLIENT *) 0;
		}

		if (fNoautoreup) {
		    ConsDown(pCEServing, &pGE->rinit);
		} else {
		    /* Try an initial reconnect */
		    Msg("[%s] automatic reinitialization",
			pCEServing->server.string);
		    ConsInit(pCEServing, &pGE->rinit, 0);

		    /* If we didn't succeed, try again later */
		    if (!pCEServing->fup)
			pCEServing->autoReUp = 1;
		    else
			pCEServing->pCLwr = FindWrite(pCEServing->pCLon);
		}

		continue;
	    }
	    Debug(1, "Kiddie(): read %d bytes from fd %d", nr,
		  pCEServing->fdtty);

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
			Debug(1, "Kiddie(): [%s] got telnet `IAC'",
			      pCEServing->server.string);
			state = 1;
		    } else if (state == 1 && acInOrig[i] != IAC) {
			Debug(1, "Kiddie(): [%s] got telnet cmd `%u'",
			      pCEServing->server.string, acInOrig[i]);
			if (acInOrig[i] == DONT || acInOrig[i] == DO ||
			    acInOrig[i] == WILL || acInOrig[i] == WONT)
			    state = 2;
			else
			    state = 0;
		    } else if (state == 2) {
			Debug(1, "Kiddie(): [%s] got telnet option `%u'",
			      pCEServing->server.string, acInOrig[i]);
			state = 0;
		    } else {
			if (state == 5) {
			    state = 0;
			    if (acInOrig[i] == '\000')
				continue;
			}
			if (acInOrig[i] == IAC)
			    Debug(1, "Kiddie(): [%s] quoted `IAC'",
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
		WriteLog(pCEServing, (char *)acIn, nr);
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
		    if (pCEServing->server.used > 1)
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
		    FileWrite(pCL->fd, (char *)acIn, nr);
		}
	    }
	}


	/* anything from a connection?
	 */
	for (pCLServing = pGE->pCLall; (CONSCLIENT *) 0 != pCLServing;
	     pCLServing = pCLServing->pCLscan) {
	    if (!FD_ISSET(FileFDNum(pCLServing->fd), &rmask)) {
		continue;
	    }
	    pCEServing = pCLServing->pCEto;

	    /* read connection */
	    if ((nr = FileRead(pCLServing->fd, acIn, sizeof(acIn))) == 0) {
		/* reached EOF - close connection */
	      drop:
		/* re-entry point to drop a connection
		 * (for any other reason)
		 */
		DisconnectClient(pGE, pCLServing, (char *)0);
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
		Debug(1, "Kiddie(): dmalloc / MarkClientConnection");
		dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
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
			if ('\r' != acIn[i]) {
			    if (acIn[i] == '\a' ||
				(acIn[i] >= ' ' && acIn[i] <= '~')) {
				BuildStringChar(acIn[i], &pCLServing->msg);
				if (pGE->pCEctl != pCEServing)
				    FileWrite(pCLServing->fd,
					      (char *)&acIn[i], 1);
			    } else if ((acIn[i] == '\b' || acIn[i] == 0x7f)
				       && pCLServing->msg.used > 1) {
				if (pCLServing->msg.
				    string[pCLServing->msg.used - 2] !=
				    '\a' && pGE->pCEctl != pCEServing) {
				    FileWrite(pCLServing->fd, "\b \b", 3);
				}
				pCLServing->msg.string[pCLServing->msg.
						       used - 2] = '\000';
				pCLServing->msg.used--;
			    }
			    continue;
			}
			FileWrite(pCLServing->fd, "]\r\n", 3);
			BuildString((char *)0, bcast);
			BuildString("[", bcast);
			if (pGE->pCEctl != pCEServing) {
			    BuildString(pCLServing->acid.string, bcast);
			    BuildString(": ", bcast);
			    BuildString(pCLServing->msg.string, bcast);
			} else {
			    char *msg;
			    if ((msg =
				 strchr(pCLServing->msg.string,
					':')) == (char *)0) {
				BuildString(pCLServing->acid.string,
					    bcast);
				msg = pCLServing->msg.string;
			    } else {
				*msg++ = '\000';
				BuildString(pCLServing->msg.string, bcast);
				BuildStringChar('@', bcast);
				BuildString(pCLServing->peername.string,
					    bcast);
			    }
			    BuildString("?: ", bcast);
			    BuildString(msg, bcast);
			}
			BuildString("]\r\n", bcast);
			if (pGE->pCEctl != pCEServing)
			    SendClientsMsg(pCEServing, bcast->string);
			else
			    SendAllClientsMsg(pGE, bcast->string);

			BuildString((char *)0, &pCLServing->msg);
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_IDENT:
			/* append chars to acid until [\r]\n
			 */
			if ('\n' != acIn[i]) {
			    BuildStringChar(acIn[i], &pCLServing->acid);
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
			BuildStringChar('@', &pCLServing->acid);
			BuildString(pCLServing->peername.string,
				    &pCLServing->acid);
			Debug(1,
			      "Kiddie(): client acid reinitialized to `%s'",
			      pCLServing->acid.string);
			BuildString((char *)0, &pCLServing->accmd);
			FileWrite(pCLServing->fd, "host:\r\n", -1);
			pCLServing->iState = S_HOST;
			continue;

		    case S_HOST:
			/* append char to buffer, check for \n
			 * continue if incomplete
			 * else switch to new host
			 */
			if ('\n' != acIn[i]) {
			    BuildStringChar(acIn[i], &pCLServing->accmd);
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
				BuildString((char *)0, &pCLServing->accmd);
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
				    BuildString((char *)0,
						&pCLServing->accmd);
				    break;
				}
			    }
			}
			if ((CONSENT *) 0 == pCLServing->pCEwant) {
			    FilePrint(pCLServing->fd,
				      "%s: no such console\r\n",
				      pCLServing->accmd.string);
			    BuildString((char *)0, &pCLServing->accmd);
			    goto drop;
			}
			BuildString((char *)0, &pCLServing->accmd);

			if (('t' == pCLServing->caccess) ||
			    (CheckPasswd(pCLServing, "") ==
			     AUTH_SUCCESS)) {
			    goto shift_console;
			}
			FileWrite(pCLServing->fd, "passwd:\r\n", -1);
			pCLServing->iState = S_PASSWD;
			continue;

		    case S_PASSWD:
			/* gather passwd, check and drop or
			 * set new state
			 */
			if ('\n' != acIn[i]) {
			    BuildStringChar(acIn[i], &pCLServing->accmd);
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
			    FileWrite(pCLServing->fd, "Sorry.\r\n", -1);
			    Msg("[%s] user %s bad passwd",
				pCLServing->pCEwant->server.string,
				pCLServing->acid.string);
			    BuildString((char *)0, &pCLServing->accmd);
			    goto drop;
			}
#if HAVE_MEMSET
			memset((void *)pCLServing->accmd.string, 0,
			       pCLServing->accmd.used);
#else
			bzero((char *)pCLServing->accmd.string,
			      pCLServing->accmd.used);
#endif
			BuildString((char *)0, &pCLServing->accmd);
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
			    TagLogfile(pCEServing, "%s detached",
				       pCLServing->acid.string);
			    pCEServing->pCLwr =
				FindWrite(pCEServing->pCLon);
			}

			/* inform operators of the change
			 */
			if (pGE->pCEctl == pCEServing) {
			    Msg("[%s] login %s",
				pCLServing->pCEwant->server.string,
				pCLServing->acid.string);
			} else {
			    Msg("[%s] %s moves to %s",
				pCEServing->server.string,
				pCLServing->acid.string,
				pCLServing->pCEwant->server.string);
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
			    FileWrite(pCLServing->fd,
				      "line to host is down]\r\n", -1);
			} else if (pCEServing->fronly) {
			    FileWrite(pCLServing->fd,
				      "host is read-only]\r\n", -1);
			} else if ((CONSCLIENT *) 0 == pCEServing->pCLwr) {
			    pCEServing->pCLwr = pCLServing;
			    pCLServing->fwr = 1;
			    FileWrite(pCLServing->fd, "attached]\r\n", -1);
			    /* this keeps the ops console neat */
			    pCEServing->iend = 0;
			    TagLogfile(pCEServing, "%s attached",
				       pCLServing->acid.string);
			} else {
			    FileWrite(pCLServing->fd, "spy]\r\n", -1);
			}
			pCLServing->fcon = 1;
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_QUOTE:	/* send octal code              */
			/* must type in 3 octal digits */
			if (acIn[i] >= '0' && acIn[i] <= '7') {
			    BuildStringChar(acIn[i], &pCLServing->accmd);
			    if (pCLServing->accmd.used < 4) {
				FileWrite(pCLServing->fd, (char *)&acIn[i],
					  1);
				continue;
			    }
			    FileWrite(pCLServing->fd, (char *)&acIn[i], 1);
			    FileWrite(pCLServing->fd, "]", 1);

			    pCLServing->accmd.string[0] =
				(((pCLServing->accmd.string[0] - '0') * 8 +
				  (pCLServing->accmd.string[1] -
				   '0')) * 8) +
				(pCLServing->accmd.string[2] - '0');
			    PutConsole(pCEServing,
				       pCLServing->accmd.string[0]);
			    BuildString((char *)0, &pCLServing->accmd);
			} else {
			    FileWrite(pCLServing->fd, " aborted]\r\n", -1);
			}
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_SUSP:
			if (!pCEServing->fup) {
			    FileWrite(pCLServing->fd, " -- line down]\r\n",
				      -1);
			} else if (pCEServing->fronly) {
			    FileWrite(pCLServing->fd, " -- read-only]\r\n",
				      -1);
			} else if ((CONSCLIENT *) 0 == pCEServing->pCLwr) {
			    pCEServing->pCLwr = pCLServing;
			    pCLServing->fwr = 1;
			    if (pCEServing->nolog) {
				FileWrite(pCLServing->fd,
					  " -- attached (nologging)]\r\n",
					  -1);
			    } else {
				FileWrite(pCLServing->fd,
					  " -- attached]\r\n", -1);
			    }
			    TagLogfile(pCEServing, "%s attached",
				       pCLServing->acid.string);
			} else {
			    FileWrite(pCLServing->fd, " -- spy mode]\r\n",
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
			    PutConsole(pCEServing, acIn[i]);
			    continue;
			}
			/* if the client is stuck in spy mode
			 * give them a clue as to how to get out
			 * (LLL nice to put chars out as ^Ec, rather
			 * than octal escapes, but....)
			 */
			if ('\r' == acIn[i] || '\n' == acIn[i]) {
			    FilePrint(pCLServing->fd,
				      "[read-only -- use %s %s ? for help]\r\n",
				      FmtCtl(pCLServing->ic[0], acA1),
				      FmtCtl(pCLServing->ic[1], acA2));
			}
			continue;

		    case S_HALT1:	/* halt sequence? */
			pCLServing->iState = S_NORMAL;
			if (acIn[i] != '?' &&
			    (acIn[i] < '0' || acIn[i] > '9')) {
			    FileWrite(pCLServing->fd, "aborted]\r\n", -1);
			    continue;
			}

			if (acIn[i] == '?') {
			    int i;
			    FileWrite(pCLServing->fd, "list]\r\n", -1);
			    i = pCEServing->breakType;
			    if (i == 0 || breakList[i - 1].used <= 1)
				FileWrite(pCLServing->fd,
					  " 0  <undefined>\r\n", -1);
			    else {
				FilePrint(pCLServing->fd, " 0  `%s'\r\n",
					  breakList[i - 1].string);
			    }
			    for (i = 0; i < 9; i++) {
				if (breakList[i].used > 1) {
				    FilePrint(pCLServing->fd,
					      " %d  `%s'\r\n", i + 1,
					      breakList[i].string);
				}
			    }
			} else {
			    int bt = acIn[i] - '0';
			    SendBreak(pCLServing, pCEServing, bt);
			}
			continue;

		    case S_CATTN:	/* redef escape sequence? */
			pCLServing->ic[0] = acInOrig[i];
			FmtCtl(acInOrig[i], acA1);
			FilePrint(pCLServing->fd, "%s ", acA1->string);
			pCLServing->iState = S_CESC;
			continue;

		    case S_CESC:	/* escape sequent 2 */
			pCLServing->ic[1] = acInOrig[i];
			pCLServing->iState = S_NORMAL;
			FmtCtl(acInOrig[i], acA1);
			FilePrint(pCLServing->fd, "%s  ok]\r\n",
				  acA1->string);
			continue;

		    case S_ESC1:	/* first char in escape sequence */
			if (acInOrig[i] == pCLServing->ic[1]) {
			    if (pCLServing->fecho)
				FileWrite(pCLServing->fd, "\r\n[", -1);
			    else
				FileWrite(pCLServing->fd, "[", -1);
			    pCLServing->iState = S_CMD;
			    continue;
			}
			/* ^E^Ec or ^_^_^[
			 * pass (possibly stripped) first ^E (^_) and
			 * stay in same state
			 */
			if (acInOrig[i] == pCLServing->ic[0]) {
			    if (pCLServing->fwr) {
				PutConsole(pCEServing, acIn[i]);
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
			    PutConsole(pCEServing, c);
			    PutConsole(pCEServing, acIn[i]);
			}
			continue;

		    case S_CMD:	/* have 1/2 of the escape sequence */
			pCLServing->iState = S_NORMAL;
			switch (acIn[i]) {
			    case '+':
			    case '-':
				if (0 !=
				    (pCLServing->fecho = '+' == acIn[i]))
				    FileWrite(pCLServing->fd,
					      "drop line]\r\n", -1);
				else
				    FileWrite(pCLServing->fd,
					      "no drop line]\r\n", -1);
				break;

#if HAVE_OPENSSL
			    case '*':	/* SSL encryption */
				if (pGE->pCEctl != pCLServing->pCEto) {
				    goto unknown;
				}
				FileWrite(pCLServing->fd, "ssl:\r\n", -1);
				if (!AttemptSSL(pCLServing))
				    goto drop;
				Debug(1,
				      "Kiddie(): SSL connection a success for client `%s'",
				      pCLServing->peername.string);
				break;
#endif

			    case ';':	/* ;login: */
				if (pGE->pCEctl != pCLServing->pCEto) {
				    goto unknown;
				}
#if HAVE_OPENSSL
				if (fReqEncryption &&
				    FileGetType(pCLServing->fd) !=
				    SSLSocket) {
				    FileWrite(pCLServing->fd,
					      "Encryption required\r\n",
					      -1);
				    goto drop;
				}
#endif
				FileWrite(pCLServing->fd, "login:\r\n",
					  -1);
				BuildString((char *)0, &pCLServing->acid);
				pCLServing->iState = S_IDENT;
				break;

			    case 'b':	/* broadcast message */
			    case 'B':
				FileWrite(pCLServing->fd,
					  "Enter message: ", -1);
				pCLServing->iState = S_BCAST;
				break;

			    case 'a':	/* attach */
			    case 'A':
				if (pGE->pCEctl == pCEServing) {
				    FileWrite(pCLServing->fd,
					      "no -- on ctl]\r\n", -1);
				} else if (!pCEServing->fup) {
				    FileWrite(pCLServing->fd,
					      "line to host is down]\r\n",
					      -1);
				} else if (pCEServing->fronly) {
				    FileWrite(pCLServing->fd,
					      "host is read-only]\r\n",
					      -1);
				} else if ((CONSCLIENT *) 0 ==
					   (pCL = pCEServing->pCLwr)) {
				    pCEServing->pCLwr = pCLServing;
				    pCLServing->fwr = 1;
				    if (pCEServing->nolog) {
					FileWrite(pCLServing->fd,
						  "attached (nologging)]\r\n",
						  -1);
				    } else {
					FileWrite(pCLServing->fd,
						  "attached]\r\n", -1);
				    }
				    TagLogfile(pCEServing, "%s attached",
					       pCLServing->acid.string);
				} else if (pCL == pCLServing) {
				    if (pCEServing->nolog) {
					FileWrite(pCLServing->fd,
						  "ok (nologging)]\r\n",
						  -1);
				    } else {
					FileWrite(pCLServing->fd,
						  "ok]\r\n", -1);
				    }
				} else {
				    pCLServing->fwantwr = 1;
				    FilePrint(pCLServing->fd,
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
				    FileWrite(pCLServing->fd,
					      "failed]\r\n", -1);
				    continue;
				}
				if (0 != (sbuf.c_iflag & IXOFF)) {
				    sbuf.c_iflag &= ~(IXOFF | IXON);
				    FileWrite(pCLServing->fd,
					      "flow OFF]\r\n", -1);
				} else {
				    sbuf.c_iflag |= IXOFF | IXON;
				    FileWrite(pCLServing->fd,
					      "flow ON]\r\n", -1);
				}
				if (-1 ==
				    tcsetattr(pCEServing->fdtty, TCSANOW,
					      &sbuf)) {
				    FileWrite(pCLServing->fd,
					      "failed]\r\n", -1);
				    continue;
				}
#else
				if (-1 ==
				    ioctl(pCEServing->fdtty, TIOCGETP,
					  (char *)&sty)) {
				    FileWrite(pCLServing->fd,
					      "failed]\r\n", -1);
				    break;
				}
				if (0 != (sty.sg_flags & TANDEM)) {
				    sty.sg_flags &= ~TANDEM;
				    FileWrite(pCLServing->fd,
					      "flow OFF]\r\n", -1);
				} else {
				    sty.sg_flags |= TANDEM;
				    FileWrite(pCLServing->fd,
					      "flow ON]\r\n", -1);
				}
				ioctl(pCEServing->fdtty, TIOCSETP,
				      (char *)&sty);
#endif
				break;

			    case 'd':	/* down a console       */
			    case 'D':
				if (pGE->pCEctl == pCEServing) {
				    FileWrite(pCLServing->fd,
					      "no -- on ctl]\r\n", -1);
				    continue;
				}
				if (!pCLServing->fwr &&
				    !pCEServing->fronly) {
				    FileWrite(pCLServing->fd,
					      "attach to down line]\r\n",
					      -1);
				    break;
				}
				if (!pCEServing->fup) {
				    FileWrite(pCLServing->fd, "ok]\r\n",
					      -1);
				    break;
				}

				pCLServing->fwr = 0;
				pCEServing->pCLwr = (CONSCLIENT *) 0;
				TagLogfile(pCEServing, "%s detached",
					   pCLServing->acid.string);
				ConsDown(pCEServing, &pGE->rinit);
				FileWrite(pCLServing->fd, "line down]\r\n",
					  -1);

				/* tell all who closed it */
				for (pCL = pCEServing->pCLon;
				     (CONSCLIENT *) 0 != pCL;
				     pCL = pCL->pCLnext) {
				    if (pCL == pCLServing)
					continue;
				    if (pCL->fcon) {
					FilePrint(pCL->fd,
						  "[line down by %s]\r\n",
						  pCLServing->acid.string);
				    }
				}
				break;

			    case 'e':	/* redefine escape keys */
			    case 'E':
				pCLServing->iState = S_CATTN;
				FileWrite(pCLServing->fd, "redef: ", -1);
				break;

			    case 'f':	/* force attach */
			    case 'F':
				if (pGE->pCEctl == pCEServing) {
				    FileWrite(pCLServing->fd,
					      "no -- on ctl]\r\n", -1);
				    continue;
				} else if (pCEServing->fronly) {
				    FileWrite(pCLServing->fd,
					      "host is read-only]\r\n",
					      -1);
				    continue;
				} else if (!pCEServing->fup) {
				    FileWrite(pCLServing->fd,
					      "line to host is down]\r\n",
					      -1);
				    continue;
				}
				if ((CONSCLIENT *) 0 !=
				    (pCL = pCEServing->pCLwr)) {
				    if (pCL == pCLServing) {
					if (pCEServing->nolog) {
					    FileWrite(pCLServing->fd,
						      "ok (nologging)]\r\n",
						      -1);
					} else {
					    FileWrite(pCLServing->fd,
						      "ok]\r\n", -1);
					}
					break;
				    }
				    pCL->fwr = 0;
				    pCL->fwantwr = 1;
				    if (pCEServing->nolog) {
					FilePrint(pCLServing->fd,
						  "bumped %s (nologging)]\r\n",
						  pCL->acid.string);
				    } else {
					FilePrint(pCLServing->fd,
						  "bumped %s]\r\n",
						  pCL->acid.string);
				    }
				    FileWrite(pCL->fd,
					      "\r\n[forced to `spy' mode by ",
					      -1);
				    FileWrite(pCL->fd,
					      pCLServing->acid.string, -1);
				    FileWrite(pCL->fd, "]\r\n", -1);
				    TagLogfile(pCEServing, "%s bumped %s",
					       pCLServing->acid.string,
					       pCL->acid.string);
				} else {
				    if (pCEServing->nolog) {
					FileWrite(pCLServing->fd,
						  "attached (nologging)]\r\n",
						  -1);
				    } else {
					FileWrite(pCLServing->fd,
						  "attached]\r\n", -1);
				    }
				    TagLogfile(pCEServing, "%s attached",
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
				FilePrint(pCLServing->fd, "group %s]\r\n",
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
				    FileWrite(pCLServing->fd,
					      (char *)acOut, -1);
				    FilePrint(pCLServing->fd, "%s\r\n",
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
				FileWrite(pCLServing->fd, "info]\r\n", -1);
				for (pCE = pGE->pCElist;
				     pCE != (CONSENT *) 0;
				     pCE = pCE->pCEnext) {
				    int comma = 0;
				    FilePrint(pCLServing->fd,
					      "%s:%s,%lu,%hu:",
					      pCE->server.string, acMyHost,
					      (unsigned long)thepid,
					      pGE->port);
				    if (pCE->fvirtual) {
					FilePrint(pCLServing->fd,
						  "|:%s,%lu,%s",
						  (pCE->pccmd.used >
						   1 ? pCE->pccmd.
						   string : defaultShell->
						   string),
						  (unsigned long)pCE->ipid,
						  pCE->acslave.string);
				    } else if (pCE->isNetworkConsole) {
					FilePrint(pCLServing->fd,
						  "!:%s,%hu",
						  pCE->networkConsoleHost.
						  string,
						  pCE->networkConsolePort);
				    } else {
					FilePrint(pCLServing->fd,
						  "/:%s,%s%c",
						  pCE->dfile.string,
						  (pCE->pbaud ? pCE->
						   pbaud->acrate : ""),
						  (pCE->pparity ? pCE->
						   pparity->ckey : ' '));
				    }
				    FilePrint(pCLServing->fd, ",%d:",
					      pCE->fdtty);
				    if (pCE->pCLwr) {
					FilePrint(pCLServing->fd,
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
					    FilePrint(pCLServing->fd, ",");
					if (pCL->fcon)
					    FilePrint(pCLServing->fd,
						      "r@%s@%ld@%s",
						      pCL->acid.string,
						      tyme - pCL->typetym,
						      pCL->
						      fwantwr ? "rw" :
						      "ro");
					else
					    FilePrint(pCLServing->fd,
						      "s@%s@%ld@%s",
						      pCL->acid.string,
						      tyme - pCL->typetym,
						      pCL->
						      fwantwr ? "rw" :
						      "ro");
					comma = 1;
				    }

				    FilePrint(pCLServing->fd,
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
					FileWrite(pCLServing->fd,
						  "logging off]\r\n", -1);
					FilePrint(pCEServing->fdlog,
						  "[-- Console logging disabled by %s -- %s]\r\n",
						  pCLServing->acid.string,
						  StrTime(NULL));
				    } else {
					FileWrite(pCLServing->fd,
						  "logging on]\r\n", -1);
					FilePrint(pCEServing->fdlog,
						  "[-- Console logging restored by %s -- %s]\r\n",
						  pCLServing->acid.string,
						  StrTime(NULL));
				    }
				} else {
				    FilePrint(pCLServing->fd,
					      "read-only -- use %s %s ? for help]\r\n",
					      FmtCtl(pCLServing->ic[0],
						     acA1),
					      FmtCtl(pCLServing->ic[1],
						     acA2));
				}
				break;

			    case 'l':	/* halt character 1     */
				if (pCEServing->fronly) {
				    FileWrite(pCLServing->fd,
					      "can't halt read-only host]\r\n",
					      -1);
				    continue;
				}
				if (!pCLServing->fwr) {
				    FileWrite(pCLServing->fd,
					      "attach to halt]\r\n", -1);
				    continue;
				}
				pCLServing->iState = S_HALT1;
				FileWrite(pCLServing->fd, "halt ", -1);
				break;

			    case 'o':	/* close and re-open line */
			    case 'O':
				if (pGE->pCEctl == pCEServing) {
				    FileWrite(pCLServing->fd,
					      "no -- on ctl]\r\n", -1);
				    continue;
				}
				/* with a close/re-open we might
				 * change fd's
				 */
				ConsInit(pCEServing, &pGE->rinit, 0);
				if (!pCEServing->fup) {
				    FileWrite(pCLServing->fd,
					      "line to host is down]\r\n",
					      -1);
				} else if (pCEServing->fronly) {
				    FileWrite(pCLServing->fd,
					      "up read-only]\r\n", -1);
				} else if ((CONSCLIENT *) 0 ==
					   (pCL = pCEServing->pCLwr)) {
				    pCEServing->pCLwr = pCLServing;
				    pCLServing->fwr = 1;
				    FileWrite(pCLServing->fd,
					      "up -- attached]\r\n", -1);
				    TagLogfile(pCEServing, "%s attached",
					       pCLServing->acid.string);
				} else if (pCL == pCLServing) {
				    FileWrite(pCLServing->fd, "up]\r\n",
					      -1);
				    TagLogfile(pCEServing, "%s attached",
					       pCLServing->acid.string);
				} else {
				    FilePrint(pCLServing->fd,
					      "up, %s is attached]\r\n",
					      pCL->acid.string);
				}
				break;

			    case '\022':	/* ^R */
				FileWrite(pCLServing->fd, "^R]\r\n", -1);
				Replay(pCEServing->fdlog, pCLServing->fd,
				       1);
				break;

			    case 'R':	/* DEC vt100 pf3 */
			    case 'r':	/* replay 20 lines */
				FileWrite(pCLServing->fd, "replay]\r\n",
					  -1);
				Replay(pCEServing->fdlog, pCLServing->fd,
				       20);
				break;

			    case 'p':	/* replay 60 lines */
				FileWrite(pCLServing->fd,
					  "long replay]\r\n", -1);
				Replay(pCEServing->fdlog, pCLServing->fd,
				       60);
				break;

			    case 'S':	/* DEC vt100 pf4 */
			    case 's':	/* spy mode */
				pCLServing->fwantwr = 0;
				if (!pCLServing->fwr) {
				    FileWrite(pCLServing->fd, "ok]\r\n",
					      -1);
				    break;
				}
				pCLServing->fwr = 0;
				TagLogfile(pCEServing, "%s detached",
					   pCLServing->acid.string);
				pCEServing->pCLwr =
				    FindWrite(pCEServing->pCLon);
				FileWrite(pCLServing->fd, "spying]\r\n",
					  -1);
				break;

			    case 'u':	/* hosts on server this */
			    case 'U':
				FileWrite(pCLServing->fd, "hosts]\r\n",
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
				    FileWrite(pCLServing->fd,
					      (char *)acOut, -1);
				}
				break;

			    case 'v':	/* version */
			    case 'V':
				FilePrint(pCLServing->fd,
					  "version `%s']\r\n",
					  THIS_VERSION);
				break;

			    case 'w':	/* who */
			    case 'W':
				FilePrint(pCLServing->fd, "who %s]\r\n",
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
				    FileWrite(pCLServing->fd,
					      (char *)acOut, -1);
				}
				break;

			    case 'x':
			    case 'X':
				FileWrite(pCLServing->fd, "examine]\r\n",
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
				    FileWrite(pCLServing->fd,
					      (char *)acOut, -1);
				}
				break;

			    case 'z':	/* suspend the client */
			    case 'Z':
			    case '\032':
				if (1 !=
				    FileSend(pCLServing->fd, acStop, 1,
					     MSG_OOB)) {
				    break;
				}
				pCLServing->fcon = 0;
				pCLServing->iState = S_SUSP;
				if (pCEServing->pCLwr == pCLServing) {
				    pCLServing->fwr = 0;
				    pCLServing->fwantwr = 0;
				    pCEServing->pCLwr = (CONSCLIENT *) 0;
				    TagLogfile(pCEServing, "%s detached",
					       pCLServing->acid.string);
				}
				break;

			    case '\t':	/* toggle tab expand    */
				FileWrite(pCLServing->fd, "tabs]\r\n", -1);
#if HAVE_TERMIO_H
				/* ZZZ */
#else
# if HAVE_TERMIOS_H
				if (-1 ==
				    tcgetattr(pCEServing->fdtty, &sbuf)) {
				    FileWrite(pCLServing->fd,
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
				    FileWrite(pCLServing->fd,
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
				FileWrite(pCLServing->fd,
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
				    FileWrite(pCLServing->fd,
					      "[failed]\r\n", -1);
				    continue;
				}
				if (0 == (sbuf.c_iflag & IXOFF)) {
				    sbuf.c_iflag |= IXOFF | IXON;
				    tcsetattr(pCEServing->fdtty, TCSANOW,
					      &sbuf);
				}
#else
				if (-1 !=
				    ioctl(pCEServing->fdtty, TIOCGETP,
					  (char *)&sty) &&
				    0 == (sty.sg_flags & TANDEM)) {
				    sty.sg_flags |= TANDEM;
				    ioctl(pCEServing->fdtty, TIOCSETP,
					  (char *)&sty);
				}
#endif
				goto drop;

			    case ' ':	/* abort escape sequence */
			    case '\n':
			    case '\r':
				FileWrite(pCLServing->fd, "ignored]\r\n",
					  -1);
				break;

			    case '\\':	/* quote mode (send ^Q,^S) */
				if (pCEServing->fronly) {
				    FileWrite(pCLServing->fd,
					      "can't write to read-only host]\r\n",
					      -1);
				    continue;
				}
				if (!pCLServing->fwr) {
				    FileWrite(pCLServing->fd,
					      "attach to send character]\r\n",
					      -1);
				    continue;
				}
				BuildString((char *)0, &pCLServing->accmd);
				pCLServing->iState = S_QUOTE;
				FileWrite(pCLServing->fd, "quote \\", -1);
				break;

			    default:	/* unknown sequence */
			      unknown:
				FileWrite(pCLServing->fd,
					  "unknown -- use `?']\r\n", -1);
				break;
			}
			continue;
		}
	}


	/* if nothing on control line, get more
	 */
	if (!FD_ISSET(FileFDNum(sfd), &rmask)) {
	    continue;
	}

	/* accept new connections and deal with them
	 */
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	dmallocMarkClientConnection = dmalloc_mark();
#endif
	so = sizeof(struct sockaddr_in);
	fd = accept(FileFDNum(sfd),
		    (struct sockaddr *)&pGE->pCLfree->cnct_port, &so);
	if (fd < 0) {
	    Error("Kiddie(): accept(): %s", strerror(errno));
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	    Debug(1, "Kiddie(): dmalloc / MarkClientConnection");
	    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
	    continue;
	}

	pGE->pCLfree->fd = FileOpenFD(fd, simpleSocket);
	if ((CONSFILE *) 0 == pGE->pCLfree->fd) {
	    Error("Kiddie(): FileOpenFD(): %s", strerror(errno));
	    close(fd);
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	    Debug(1, "Kiddie(): dmalloc / MarkClientConnection");
	    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
	    continue;
	}
#if defined(USE_LIBWRAP)
	{
	    struct request_info request;
	    request_init(&request, RQ_DAEMON, progname, RQ_FILE, fd, 0);
	    fromhost(&request);
	    if (!hosts_access(&request)) {
		FileWrite(pGE->pCLfree->fd,
			  "access from your host refused\r\n", -1);
		FileClose(&pGE->pCLfree->fd);
		ResetMark();
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
		Debug(1, "Kiddie(): dmalloc / MarkClientConnection");
		dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
		continue;
	    }
	    ResetMark();
	}
#endif

	/* We use this information to verify                    (ksb)
	 * the source machine as being local.
	 */
	so = sizeof(in_port);
	if (-1 == getpeername(fd, (struct sockaddr *)&in_port, &so)) {
	    FileWrite(pGE->pCLfree->fd, "getpeername failed\r\n", -1);
	    FileClose(&pGE->pCLfree->fd);
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	    Debug(1, "Kiddie(): dmalloc / MarkClientConnection");
	    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
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
	    FileWrite(pGE->pCLfree->fd,
		      "access from your host refused\r\n", -1);
	    FileClose(&pGE->pCLfree->fd);
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	    Debug(1, "Kiddie(): dmalloc / MarkClientConnection");
	    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
	    continue;
	}

	/* save pCL so we can advance to the next free one
	 */
	pCL = pGE->pCLfree;
	pGE->pCLfree = pCL->pCLnext;

	/* init the identification stuff
	 */
	BuildString((char *)0, &pCL->peername);
	if (hpPeer == (struct hostent *)0) {
	    BuildString(inet_ntoa(in_port.sin_addr), &pCL->peername);
	} else {
	    BuildString(hpPeer->h_name, &pCL->peername);
	}
	BuildString((char *)0, &pCL->acid);
	BuildString("<unknown>@", &pCL->acid);
	BuildString(pCL->peername.string, &pCL->acid);
	Debug(1, "Kiddie(): client acid initialized to `%s'",
	      pCL->acid.string);
	strcpy(pCL->actym, StrTime(&(pCL->tym)));
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

	FD_SET(FileFDNum(pCL->fd), &pGE->rinit);

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
	FileWrite(pCL->fd, "ok\r\n", -1);

	/* remove from the free list
	 * if we ran out of free slots, calloc one...
	 */
	if ((CONSCLIENT *) 0 == pGE->pCLfree) {
	    pGE->pCLfree = (CONSCLIENT *) calloc(1, sizeof(CONSCLIENT));
	    if ((CONSCLIENT *) 0 == pGE->pCLfree)
		OutOfMem();
	}
    }
}

/* create a child process:						(fine)
 * fork off a process for each group with an open socket for connections
 */
void
#if PROTOTYPES
Spawn(GRPENT * pGE)
#else
Spawn(pGE)
    GRPENT *pGE;
#endif
{
    pid_t pid;
    int sfd;
    socklen_t so;
    struct sockaddr_in lstn_port;
    int true = 1;
    unsigned short portInc = 0;
    CONSFILE *ssocket;

    /* get a socket for listening
     */
#if HAVE_MEMSET
    memset((void *)&lstn_port, 0, sizeof(lstn_port));
#else
    bzero((char *)&lstn_port, sizeof(lstn_port));
#endif
    lstn_port.sin_family = AF_INET;
    lstn_port.sin_addr.s_addr = bindAddr;
    lstn_port.sin_port = htons(bindBasePort);

    /* create a socket to listen on
     * (prepared by master so he can see the port number of the kid)
     */
    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	Error("Spawn(): socket(): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }
#if HAVE_SETSOCKOPT
    if (setsockopt
	(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&true, sizeof(true)) < 0) {
	Error("Spawn(): setsockopt(%u,SO_REUSEADDR): %s", sfd,
	      strerror(errno));
	exit(EX_UNAVAILABLE);
    }
#endif

    while (bind(sfd, (struct sockaddr *)&lstn_port, sizeof(lstn_port)) < 0) {
	if (bindBasePort && (
#if defined(EADDRINUSE)
				(errno == EADDRINUSE) ||
#endif
				(errno == EACCES)) && portInc++) {
	    lstn_port.sin_port = htons(bindBasePort + portInc);
	} else {
	    Error("Spawn(): bind(%u): %s", sfd, strerror(errno));
	    exit(EX_UNAVAILABLE);
	}
    }
    so = sizeof(lstn_port);

    if (-1 == getsockname(sfd, (struct sockaddr *)&lstn_port, &so)) {
	Error("Spawn(): getsockname(%u): %s", sfd, strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    pGE->port = lstn_port.sin_port;

    fflush(stderr);
    fflush(stdout);
    switch (pid = fork()) {
	case -1:
	    Error("Spawn(): fork(): %s", strerror(errno));
	    exit(EX_UNAVAILABLE);
	default:
	    close(sfd);
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
	Error("Spawn(): listen(%u): %s", sfd, strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    ssocket = FileOpenFD(sfd, simpleSocket);
    if ((CONSFILE *) 0 == ssocket) {
	Error("Spawn(): FileOpenFD(%u): %s", sfd, strerror(errno));
	close(sfd);
	exit(EX_UNAVAILABLE);
    }
    Kiddie(pGE, ssocket);

    /* should never get here...
     */
    FileClose(&ssocket);
    Error("Spawn(): internal flow error");
    exit(EX_UNAVAILABLE);
}
