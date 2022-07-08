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

#include <compat.h>

#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#include <arpa/telnet.h>

#include <cutil.h>
#include <consent.h>
#include <client.h>
#include <access.h>
#include <group.h>
#include <readcfg.h>
#include <master.h>
#include <main.h>
#include <version.h>
#include <stdio.h>

#if HAVE_PAM
# include <security/pam_appl.h>
#endif


/* flags that a signal has occurred */
static sig_atomic_t fSawChldHUP = 0, fSawReUp = 0, fSawGoAway =
    0, fSawReapVirt = 0, fSawChldUSR2 = 0;

/* timers */
time_t timers[T_MAX];

#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
static unsigned long dmallocMarkClientConnection = 0;
#endif

void
SendIWaitClientsMsg(CONSENT *pCE, char *message)
{
    CONSCLIENT *pCL;

    if ((CONSENT *)0 == pCE) {
	return;
    }

    for (pCL = pCE->pCLon; (CONSCLIENT *)0 != pCL; pCL = pCL->pCLnext) {
	if (pCL->fcon && pCL->fiwait) {
	    pCL->fiwait = 0;
	    FileWrite(pCL->fd, FLAGFALSE, message, -1);
	}
    }
}

void
SendClientsMsg(CONSENT *pCE, char *message)
{
    CONSCLIENT *pCL;

    if ((CONSENT *)0 == pCE) {
	return;
    }

    for (pCL = pCE->pCLon; (CONSCLIENT *)0 != pCL; pCL = pCL->pCLnext) {
	if (pCL->fcon) {
	    FileWrite(pCL->fd, FLAGFALSE, message, -1);
	}
    }
}

void
SendCertainClientsMsg(GRPENT *pGE, char *who, char *message)
{
    CONSCLIENT *pCL;
    char *console = (char *)0;

    if ((GRPENT *)0 == pGE || who == (char *)0 || message == (char *)0) {
	return;
    }

    if ((console = strrchr(who, '@')) != (char *)0) {
	*console++ = '\000';
	if (*console == '\000')
	    console = (char *)0;
    }

    for (pCL = pGE->pCLall; (CONSCLIENT *)0 != pCL; pCL = pCL->pCLscan) {
	if (pCL->fcon) {
	    if (*who != '\000' && strcmp(pCL->username->string, who) != 0)
		continue;
	    if (console != (char *)0 &&
		strcmp(pCL->pCEto->server, console) != 0)
		continue;
	    FileWrite(pCL->fd, FLAGFALSE, message, -1);
	}
    }
}

void
SendAllClientsMsg(GRPENT *pGE, char *message)
{
    CONSCLIENT *pCL;

    if ((GRPENT *)0 == pGE) {
	return;
    }

    for (pCL = pGE->pCLall; (CONSCLIENT *)0 != pCL; pCL = pCL->pCLscan) {
	if (pCL->fcon) {
	    FileWrite(pCL->fd, FLAGFALSE, message, -1);
	}
    }
}

void
AbortAnyClientExec(CONSCLIENT *pCL)
{
    if (pCL->iState == S_CEXEC) {
	FileSetQuoteIAC(pCL->fd, FLAGFALSE);
	FilePrint(pCL->fd, FLAGTRUE, "%c%c", OB_IAC, OB_ABRT);
	FileSetQuoteIAC(pCL->fd, FLAGTRUE);
	pCL->fcon = 1;
	pCL->iState = S_NORMAL;
    }
}

void
StopTask(CONSENT *pCE)
{
    if (pCE->taskpid != 0) {
	kill(pCE->taskpid, SIGHUP);
	CONDDEBUG((1, "StopTask(): sending task pid %lu signal %d",
		   (unsigned long)pCE->taskpid, SIGHUP));
    }

    if (pCE->taskfile != (CONSFILE *)0) {
	int taskfile = FileFDNum(pCE->taskfile);
	FD_CLR(taskfile, &rinit);
	FileClose(&pCE->taskfile);
	pCE->taskfile = (CONSFILE *)0;
    }
}

void
ClientWantsWrite(CONSCLIENT *pCL)
{
    CONSENT *pCE;

    if ((CONSCLIENT *)0 == pCL)
	return;
    if (pCL->fwr)
	return;

    pCL->fwr = 0;
    pCL->fwantwr = 1;
    pCE = pCL->pCEto;
    if ((CONSENT *)0 == pCE)
	return;

    /* promote the client to the top of the list
     * (which allows them to be picked first for
     * aquiring read-write access)
     *   first by extracting...
     */
    if ((CONSCLIENT *)0 != pCL->pCLnext) {
	pCL->pCLnext->ppCLbnext = pCL->ppCLbnext;
    }
    *(pCL->ppCLbnext) = pCL->pCLnext;

    /*   now by inserting...
     */
    pCL->pCLnext = pCE->pCLon;
    pCL->ppCLbnext = &pCE->pCLon;
    if ((CONSCLIENT *)0 != pCL->pCLnext) {
	pCL->pCLnext->ppCLbnext = &pCL->pCLnext;
    }
    pCE->pCLon = pCL;
}

void
DisconnectClient(GRPENT *pGE, CONSCLIENT *pCL, char *message, FLAG force)
{
    CONSENT *pCEServing;

    if (pGE == (GRPENT *)0 || pCL == (CONSCLIENT *)0) {
	return;
    }

    AbortAnyClientExec(pCL);

    if (pCL->fcon) {
	FileWrite(pCL->fd, FLAGFALSE, message, -1);
    }

    if (force != FLAGTRUE && !FileBufEmpty(pCL->fd)) {
	pCL->ioState = ISFLUSHING;
	return;
    }

    /* log it, drop from select list,
     * close gap in table, etc, etc...
     */
    pCEServing = pCL->pCEto;

    if (pGE->pCEctl != pCEServing) {
	Msg("[%s] logout %s", pCEServing->server, pCL->acid->string);
    } else if (pCL->iState == S_NORMAL)
	Verbose("<group> logout %s", pCL->acid->string);

    if (pCEServing->ondemand == FLAGTRUE &&
	pCEServing->pCLon->pCLnext == (CONSCLIENT *)0)
	ConsDown(pCEServing, FLAGFALSE, FLAGFALSE);

    FD_CLR(FileFDNum(pCL->fd), &rinit);
    FD_CLR(FileFDNum(pCL->fd), &winit);
    FileClose(&pCL->fd);

    /* mark as not writer, if he is
     * and turn logging back on...
     */
    if (pCL->fwr) {
	BumpClient(pCEServing, (char *)0);
	TagLogfileAct(pCEServing, "%s detached", pCL->acid->string);
	if (pCEServing->nolog) {
	    pCEServing->nolog = 0;
	    TagLogfile(pCEServing, "Console logging restored (logout)");
	}
	FindWrite(pCEServing);
    }

    /* mark as unconnected and remove from both
     * lists (all clients, and this console)
     */
    pCL->fcon = 0;
    if ((CONSCLIENT *)0 != pCL->pCLnext) {
	pCL->pCLnext->ppCLbnext = pCL->ppCLbnext;
    }
    *(pCL->ppCLbnext) = pCL->pCLnext;
    if ((CONSCLIENT *)0 != pCL->pCLscan) {
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
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
    CONDDEBUG((1, "DisconnectClient(): dmalloc / MarkClientConnection"));
    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
}

int
DisconnectCertainClients(GRPENT *pGE, char *admin, char *who)
{
    CONSCLIENT *pCL;
    char *console = (char *)0;
    int count = 0;
    char *msg = (char *)0;

    if ((GRPENT *)0 == pGE || who == (char *)0) {
	return 0;
    }

    if ((console = strrchr(who, '@')) != (char *)0) {
	*console++ = '\000';
	if (*console == '\000')
	    console = (char *)0;
    }

    for (pCL = pGE->pCLall; (CONSCLIENT *)0 != pCL; pCL = pCL->pCLscan) {
	/* skip folks not connected to a console 
	 * we check for 'fcon' in other code, but that skips users
	 * that are suspended as well, we don't want that here
	 */
	if (pGE->pCEctl == pCL->pCEto)
	    continue;
	if (*who != '\000' && strcmp(pCL->username->string, who) != 0)
	    continue;
	if (console != (char *)0 &&
	    strcmp(pCL->pCEto->server, console) != 0)
	    continue;
	if (msg == (char *)0) {
	    BuildTmpString((char *)0);
	    BuildTmpString("[-- Disconnected by admin `");
	    BuildTmpString(admin);
	    msg = BuildTmpString("' --]\r\n");
	}
	DisconnectClient(pGE, pCL, msg, FLAGFALSE);
	count++;
    }

    return count;
}

void
DisconnectAllClients(GRPENT *pGE, char *message)
{
    CONSCLIENT *pCL;

    if ((GRPENT *)0 == pGE) {
	return;
    }

    for (pCL = pGE->pCLall; (CONSCLIENT *)0 != pCL; pCL = pCL->pCLscan) {
	DisconnectClient(pGE, pCL, message, FLAGTRUE);
    }
}

void
DestroyClient(CONSCLIENT *pCL)
{
    if (pCL == (CONSCLIENT *)0)
	return;
    if (pCL->acid != (STRING *)0)
	DestroyString(pCL->acid);
    if (pCL->peername != (STRING *)0)
	DestroyString(pCL->peername);
    if (pCL->accmd != (STRING *)0)
	DestroyString(pCL->accmd);
    if (pCL->username != (STRING *)0)
	DestroyString(pCL->username);
    FileClose(&pCL->fd);
    free(pCL);
}

void
DestroyConsentUsers(CONSENTUSERS **cu)
{
    CONSENTUSERS *n = (CONSENTUSERS *)0;

    if (cu == (CONSENTUSERS **)0)
	return;

    while ((*cu) != (CONSENTUSERS *)0) {
	n = (*cu)->next;
	free(*cu);
	(*cu) = n;
    }
}

CONSENTUSERS *
ConsentFindUser(CONSENTUSERS *pCU, char *id)
{
    short close = 0;
    struct group *g = (struct group *)0;
    struct passwd *pwd = (struct passwd *)0;

    for (; pCU != (CONSENTUSERS *)0; pCU = pCU->next) {
	if (pCU->user->name[0] == '@' && pCU->user->name[1] != '\000') {
	    if (close == 0) {
		close = 1;
		/* try to grab the primary group */
		pwd = getpwnam(id);
	    }

	    /* grab the group info */
	    if ((g = getgrnam(pCU->user->name + 1)) == (struct group *)0) {
		Error("ConsentFindUser(): unknown group name `%s'",
		      pCU->user->name + 1);
	    } else if (pwd != (struct passwd *)0 &&
		       pwd->pw_gid == g->gr_gid) {
		goto donehunting;
	    } else if (g->gr_mem != (char **)0) {
		char **m;
		for (m = g->gr_mem; *m != (char *)0; m++)
		    if (strcmp(*m, id) == 0)
			goto donehunting;
	    }
	} else if (strcmp(pCU->user->name, id) == 0) {
	    goto donehunting;
	}
    }
  donehunting:
    if (close) {
	endgrent();
	endpwent();
    }
    return pCU;
}

int
ConsentUserOk(CONSENTUSERS *pCU, char *id)
{
    CONSENTUSERS *c;

    if ((c = ConsentFindUser(pCU, id)) != (CONSENTUSERS *)0)
	return !c->not;
    if ((c = ConsentFindUser(pCU, "*")) != (CONSENTUSERS *)0)
	return !c->not;
    return -1;
}

/* check user permissions.  return 0 for r/w, 1 for r/o, -1 for none */
int
ClientAccess(CONSENT *pCE, char *user)
{
    CONDDEBUG((1, "ClientAccess(): Authenticating user %s", user));

    if (ConsentUserOk(pCE->rw, user) == 1)
	return 0;
    if (ConsentUserOk(pCE->ro, user) == 1)
	return 1;
#if STRIP_REALM
    {
	/* try the username without @REALM against the ACL
	 * this allows for falling back to PAM from kerberos5/gssapi
	 * as the latter uses 'user@REALM' and the former only 'user'
	 */
	char *at;
	char *shortname;
	int ret = -1;

	if ((at = strrchr(user, '@')) != (char *)0) {
	    shortname = StrDup(user);
	    *(shortname + (at - user)) = '\000';

	    CONDDEBUG((1,
		       "ClientAccess(): Shortname computed from %s is %s",
		       user, shortname));
	    if (ConsentUserOk(pCE->rw, shortname) == 1) {
		ret = 0;
	    } else if (ConsentUserOk(pCE->ro, shortname) == 1) {
		ret = 1;
	    }
	    free(shortname);
	    return ret;
	}
    }
#endif
    return -1;
}

void
DestroyConsent(GRPENT *pGE, CONSENT *pCE)
{
    CONSCLIENT *pCL;
    CONSENT **ppCE;
    NAMES *name;

    if (pCE == (CONSENT *)0 || pGE == (GRPENT *)0)
	return;

    CONDDEBUG((1, "DestroyConsent(): destroying `%s'", pCE->server));

    /* must loop using pCLall and pCLscan for the same reason as the
     * drop: code.  this is basically the same set of code, but modified
     * since we know we're going to nuke the console itself.
     */
    for (pCL = pGE->pCLall; pCL != (CONSCLIENT *)0; pCL = pCL->pCLscan) {
	if (pCL->pCEto != pCE)
	    continue;
	AbortAnyClientExec(pCL);
	if (pCL->fcon) {
	    FileWrite(pCL->fd, FLAGFALSE,
		      "[-- Conserver reconfigured - console has been (re)moved --]\r\n",
		      -1);
	}
	Msg("[%s] logout %s", pCE->server, pCL->acid->string);
	FD_CLR(FileFDNum(pCL->fd), &rinit);
	FD_CLR(FileFDNum(pCL->fd), &winit);
	FileClose(&pCL->fd);
	if (pCL->fwr) {
	    BumpClient(pCE, (char *)0);
	    TagLogfileAct(pCE, "%s detached", pCL->acid->string);
	    if (pCE->nolog) {
		pCE->nolog = 0;
		TagLogfile(pCE, "Console logging restored (logout)");
	    }
	}
	/* mark as unconnected and remove from both
	 * lists (all clients, and this console)
	 */
	if ((CONSCLIENT *)0 != pCL->pCLnext) {
	    pCL->pCLnext->ppCLbnext = pCL->ppCLbnext;
	}
	*(pCL->ppCLbnext) = pCL->pCLnext;
	if ((CONSCLIENT *)0 != pCL->pCLscan) {
	    pCL->pCLscan->ppCLbscan = pCL->ppCLbscan;
	}
	*(pCL->ppCLbscan) = pCL->pCLscan;

	pCL->pCLnext = pGE->pCLfree;
	pGE->pCLfree = pCL;
    }

    StopTask(pCE);
    ConsDown(pCE, FLAGFALSE, FLAGTRUE);

    for (ppCE = &(pGE->pCElist); *ppCE != (CONSENT *)0;
	 ppCE = &((*ppCE)->pCEnext)) {
	if (*ppCE == pCE) {
	    *ppCE = pCE->pCEnext;
	    break;
	}
    }

    DestroyConsentUsers(&(pCE->ro));
    DestroyConsentUsers(&(pCE->rw));

    if (pCE->server != (char *)0)
	free(pCE->server);
    if (pCE->host != (char *)0)
	free(pCE->host);
    if (pCE->master != (char *)0)
	free(pCE->master);
    if (pCE->exec != (char *)0)
	free(pCE->exec);
    if (pCE->device != (char *)0)
	free(pCE->device);
    if (pCE->devicesubst != (char *)0)
	free(pCE->devicesubst);
    if (pCE->execsubst != (char *)0)
	free(pCE->execsubst);
    if (pCE->initsubst != (char *)0)
	free(pCE->initsubst);
    if (pCE->logfile != (char *)0)
	free(pCE->logfile);
    if (pCE->initcmd != (char *)0)
	free(pCE->initcmd);
    if (pCE->motd != (char *)0)
	free(pCE->motd);
    if (pCE->idlestring != (char *)0)
	free(pCE->idlestring);
    if (pCE->replstring != (char *)0)
	free(pCE->replstring);
    if (pCE->tasklist != (char *)0)
	free(pCE->tasklist);
    if (pCE->breaklist != (char *)0)
	free(pCE->breaklist);
    if (pCE->execSlave != (char *)0)
	free(pCE->execSlave);
    while (pCE->aliases != (NAMES *)0) {
	name = pCE->aliases->next;
	if (pCE->aliases->name != (char *)0)
	    free(pCE->aliases->name);
	free(pCE->aliases);
	pCE->aliases = name;
    }
    FileClose(&pCE->fdlog);
    if (pCE->wbuf != (STRING *)0)
	DestroyString(pCE->wbuf);
    free(pCE);

    pGE->imembers--;
}

void
DestroyGroup(GRPENT *pGE)
{
    CONSENT *pCEtmp, *pCE;
    CONSCLIENT *pCLtmp, *pCL;

    if (pGE == (GRPENT *)0)
	return;

    CONDDEBUG((1, "DestroyGroup(): destroying group #%d (%d members)",
	       pGE->id, pGE->imembers));

    /* nuke each console (which kicks off clients) */
    DestroyConsent(pGE, pGE->pCEctl);
    pCE = pGE->pCElist;
    while (pCE != (CONSENT *)0) {
	pCEtmp = pCE->pCEnext;
	DestroyConsent(pGE, pCE);
	pCE = pCEtmp;
    }

    /* now we can nuke the client structures */
    pCL = pGE->pCLall;
    while (pCL != (CONSCLIENT *)0) {
	pCLtmp = pCL->pCLscan;
	DestroyClient(pCL);
	pCL = pCLtmp;
    }
    pCL = pGE->pCLfree;
    while (pCL != (CONSCLIENT *)0) {
	pCLtmp = pCL->pCLnext;
	DestroyClient(pCL);
	pCL = pCLtmp;
    }

    free(pGE);
}

#if HAVE_PAM
int
QuietConv(int num_msg, const struct pam_message **msg,
	  struct pam_response **resp, void *appdata_ptr)
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
		    (pcUser != (char *)0 ? StrDup(pcUser) : (char *)0);
		break;

	    case PAM_PROMPT_ECHO_OFF:
		response[i].resp =
		    (pcWord != (char *)0 ? StrDup(pcWord) : (char *)0);
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
CheckPass(char *pcUser, char *pcWord, FLAG empty_check)
{
    if (pcWord == (char *)0) {
	pcWord = "";
    }
#if HAVE_PAM
    if (empty_check == FLAGTRUE)
	return AUTH_INVALID;
    int pam_error;
    char *appdata[2];
    static pam_handle_t *pamh = (pam_handle_t *)0;
    struct pam_conv conv;
    appdata[0] = pcUser;
    appdata[1] = pcWord;
    conv.conv = &QuietConv;
    conv.appdata_ptr = (void *)&appdata;

    CONDDEBUG((1, "CheckPass(): pam_start(conserver,%s,...)", pcUser));
    pam_error = pam_start("conserver", pcUser, &conv, &pamh);

    if (pam_error == PAM_SUCCESS) {
	pam_set_item(pamh, PAM_RHOST, "IHaveNoIdeaHowIGotHere");
	CONDDEBUG((1, "CheckPass(): pam_authenticate(%s)", pcUser));
	pam_error = pam_authenticate(pamh, PAM_SILENT);
	if (pam_error == PAM_SUCCESS) {
	    CONDDEBUG((1, "CheckPass(): pam_acct_mgmt(%s)", pcUser));
	    pam_error = pam_acct_mgmt(pamh, PAM_SILENT);
	    if (pam_error != PAM_SUCCESS) {
		Error("CheckPass(): PAM failure(%s): %s", pcUser,
		      pam_strerror(pamh, pam_error));
	    }
	} else if (pam_error != PAM_AUTH_ERR) {
	    Error("CheckPass(): PAM failure(%s): %s", pcUser,
		  pam_strerror(pamh, pam_error));
	}
	CONDDEBUG((1, "CheckPass(): pam_end(%s)", pcUser));
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
    char *pass;
# if HAVE_ISCOMSEC && HAVE_GETPRPWNAM
    struct pr_passwd *prpwd;
# endif
# if HAVE_GETSPNAM
    struct spwd *spwd;
# endif

    if ((pwd = getpwnam(pcUser)) == (struct passwd *)0) {
	CONDDEBUG((1, "CheckPass(): getpwnam(%s): %s", pcUser,
		   strerror(errno)));
	retval = AUTH_NOUSER;
	goto finished_pass;
    }
    pass = pwd->pw_passwd;

# if HAVE_ISCOMSEC && HAVE_GETPRPWNAM
    if (iscomsec()) {
	CONDDEBUG((1, "CheckPass(): trusted password check"));
	if ((prpwd = getprpwnam(pcUser)) == (struct pr_passwd *)0) {
	    CONDDEBUG((1, "CheckPass(): getprpwnam(%s): %s", pcUser,
		       strerror(errno)));
	    retval = AUTH_NOUSER;
	    goto finished_pass;
	}
	pass = prpwd->ufld.fd_encrypt;
    }
# endif

# if HAVE_GETSPNAM
    if ('x' == pass[0] && '\000' == pass[1]) {
	CONDDEBUG((1, "CheckPass(): shadow password check"));
	if ((spwd = getspnam(pcUser)) == (struct spwd *)0) {
	    CONDDEBUG((1, "CheckPass(): getspnam(%s): %s", pcUser,
		       strerror(errno)));
	    retval = AUTH_NOUSER;
	    goto finished_pass;
	}
	pass = spwd->sp_pwdp;
    }
# endif

    if (pass[0] == '\000' && pcWord[0] == '\000') {
	retval = AUTH_SUCCESS;	/* let empty password match */
    } else {
	char *encrypted;
	char *salt;

	if (pass[0] == '\000')
	    salt = "XX";
	else
	    salt = pass;

# if HAVE_ISCOMSEC && HAVE_BIGCRYPT
	if (iscomsec())
	    encrypted = bigcrypt(pcWord, salt);
	else
# endif
	    encrypted = crypt(pcWord, salt);
	if ((strcmp(pass, encrypted) != 0)) {
	    CONDDEBUG((1, "CheckPass(): password check failed (%s)",
		       pass));
	    retval = AUTH_INVALID;
	}
    }

  finished_pass:
    endpwent();
# if HAVE_ISCOMSEC && HAVE_GETPRPWNAM
    if (iscomsec())
	endprpwent();
# endif
# if HAVE_GETSPNAM
    endspent();
# endif
    return retval;
#endif /* getpw*() */
}

/* on an HUP close and re-open log files so lop can trim them		(ksb)
 * and reread the configuration file
 * lucky for us: log file fd's can change async from the group driver!
 */
static RETSIGTYPE
FlagSawChldHUP(int sig)
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
FlagSawChldUSR2(int sig)
{
    fSawChldUSR2 = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGUSR2, FlagSawChldUSR2);
#endif
}

void
ConsoleError(CONSENT *pCE)
{
    if (pCE->autoreinit != FLAGTRUE) {
	ConsDown(pCE, FLAGTRUE, FLAGTRUE);
    } else {
	/* Try an initial reconnect */
	Msg("[%s] automatic reinitialization", pCE->server);
	ConsInit(pCE);

	/* If we didn't succeed, try again later */
	if (!pCE->fup)
	    pCE->autoReUp = 1;
    }
}

static void
ReOpen(GRPENT *pGE)
{
    CONSENT *pCE;

    if ((GRPENT *)0 == pGE) {
	return;
    }

    for (pCE = pGE->pCElist; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	if ((CONSFILE *)0 == pCE->fdlog) {
	    continue;
	}
	FileClose(&pCE->fdlog);
	if ((CONSFILE *)0 ==
	    (pCE->fdlog =
	     FileOpen(pCE->logfile, O_RDWR | O_CREAT | O_APPEND, 0644))) {
	    Error("[%s] FileOpen(%s): %s: forcing down", pCE->server,
		  pCE->logfile, strerror(errno));
	    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
	    continue;
	}
    }
}

static RETSIGTYPE
FlagReUp(int sig)
{
    fSawReUp = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGUSR1, FlagReUp);
#endif
}

static struct delay {
    char *host;
    time_t last;
    struct delay *next;
} *delays = (struct delay *)0;

/* returns zero if the delay has been reached, otherwise returns
 * the time when the next init should happen
 */
static time_t
InitDelay(CONSENT *pCE)
{
    char *l;
    struct delay *d;

    if (pCE->host != (char *)0)
	l = pCE->host;
    else
	l = "";

    for (d = delays; d != (struct delay *)0; d = d->next) {
	if (strcmp(l, d->host) == 0) {
	    if ((time((time_t *)0) - d->last) >= config->initdelay) {
		return (time_t)0;
	    } else
		return d->last + config->initdelay;
	}
    }
    return (time_t)0;
}

static void
UpdateDelay(CONSENT *pCE)
{
    char *l;
    struct delay *d;

    if (pCE->host != (char *)0)
	l = pCE->host;
    else
	l = "";

    for (d = delays; d != (struct delay *)0; d = d->next) {
	if (strcmp(l, d->host) == 0) {
	    d->last = time((time_t *)0);
	    return;
	}
    }
    if ((d =
	 (struct delay *)malloc(sizeof(struct delay))) ==
	(struct delay *)0)
	OutOfMem();
    if ((d->host = StrDup(l)) == (char *)0)
	OutOfMem();
    d->last = time((time_t *)0);
    d->next = delays;
    delays = d;
}

static void
ReUp(GRPENT *pGE, short automatic)
{
    CONSENT *pCE;
    int autoReUp;
    time_t tyme;
    short retry;
    static short autoup = 0;
    short wasAuto = 0;

    if ((GRPENT *)0 == pGE)
	return;

    tyme = time((time_t *)0);
    if ((automatic == 1) && (tyme < timers[T_AUTOUP]))
	return;
    if ((automatic == 2) &&
	(!config->reinitcheck || (tyme < timers[T_REINIT])))
	return;

    if (automatic == -1)
	wasAuto = autoup;
    autoup = 0;

    /* we loop here 'cause the init process could take a bit of time
     * (depending on how many things we init in the run through the
     * consoles) and we might be able to then initialize more stuff.
     * we'll eventually run through too fast, run out of consoles, or
     * have a big enough delay to go back to the main loop.
     */
    do {
	retry = 0;
	for (pCE = pGE->pCElist; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	    short updateDelay = 0;

	    if (pCE->fup || pCE->ondemand == FLAGTRUE ||
		(automatic == 1 && !pCE->autoReUp))
		continue;
	    if (config->initdelay > 0) {
		time_t t;
		if ((t = InitDelay(pCE)) > 0) {
		    if (timers[T_INITDELAY] == (time_t)0 ||
			timers[T_INITDELAY] > t)
			timers[T_INITDELAY] = t;
		    continue;
		} else {
		    updateDelay = retry = 1;
		}
	    }
	    autoReUp = pCE->autoReUp;
	    if (automatic > 0 || wasAuto) {
		Msg("[%s] automatic reinitialization", pCE->server);
		autoup = 1;
	    }
	    ConsInit(pCE);
	    if (updateDelay)
		UpdateDelay(pCE);
	    if (!pCE->fup && automatic > 0)
		pCE->autoReUp = autoReUp;
	}
    } while (retry);

    /* update all the timers */
    if (automatic == 0 || automatic == 2) {
	if (config->reinitcheck)
	    timers[T_REINIT] = tyme + (config->reinitcheck * 60);
    }
    if (!fNoautoreup)
	timers[T_AUTOUP] = tyme + 60;
}

void
TagLogfile(const CONSENT *pCE, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    if ((pCE == (CONSENT *)0) || (pCE->fdlog == (CONSFILE *)0))
	return;

    FileWrite(pCE->fdlog, FLAGTRUE, "[-- ", -1);
    FileVWrite(pCE->fdlog, FLAGTRUE, fmt, ap);
    FilePrint(pCE->fdlog, FLAGFALSE, " -- %s]\r\n", StrTime((time_t *)0));
    va_end(ap);
}

void
TagLogfileAct(const CONSENT *pCE, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    if ((pCE == (CONSENT *)0) || (pCE->fdlog == (CONSFILE *)0) ||
	(pCE->activitylog != FLAGTRUE))
	return;

    FileWrite(pCE->fdlog, FLAGTRUE, "[-- ", -1);
    FileVWrite(pCE->fdlog, FLAGTRUE, fmt, ap);
    FilePrint(pCE->fdlog, FLAGFALSE, " -- %s]\r\n", StrTime((time_t *)0));
    va_end(ap);
}

static void
RollLogs(GRPENT *pGE)
{
    CONSENT *pCE;
    struct stat stLog;
    char *t = (char *)0;
    char timestr[40];
    time_t tyme = (time_t)0;
    short maxset = 0;
    char buf[4096];
    int roll = 0;
    int r = 0;
    CONSFILE *old;

    if ((GRPENT *)0 == pGE)
	return;

    for (pCE = pGE->pCElist; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	if (pCE->logfilemax == 0)
	    continue;
	maxset = 1;
	if (pCE->fdlog == (CONSFILE *)0)
	    continue;
	if (FileStat(pCE->fdlog, &stLog) != 0) {
	    CONDDEBUG((1, "RollLogs(): FileStat(%d) failed",
		       FileFDNum(pCE->fdlog)));
	    continue;
	}
	if (stLog.st_size < pCE->logfilemax)
	    continue;
	if (pCE->logfilemax > 1024) {
	    if (pCE->logfilemax > 0x100000)
		Msg("[%s] logfile exceeds %dMB: rolling", pCE->server,
		    pCE->logfilemax / 0x100000);
	    else
		Msg("[%s] logfile exceeds %dKB: rolling", pCE->server,
		    pCE->logfilemax / 1024);
	}

	if (pCE->logfilemax < 4000)
	    roll = 100;
	else if (pCE->logfilemax > 160000)
	    roll = 4000;
	else
	    roll = pCE->logfilemax * 0.025;

	r = 0;

	if (FileSeek(pCE->fdlog, stLog.st_size - roll, SEEK_SET) > 0) {
	    if ((r = FileRead(pCE->fdlog, buf, 4096)) > 0) {
		if (r == roll) {
		    for (; r != 0 && buf[roll - r] != '\n'; r--);
		    r--;	/* go beyond \n */
		} else
		    r = 0;
	    }
	}

	if (tyme == (time_t)0) {
	    tyme = time((time_t *)0);
	    strftime(timestr, sizeof(timestr), "-%Y%m%d-%H%M%S",
		     gmtime(&tyme));
	}
	BuildTmpString((char *)0);
	t = BuildTmpStringPrint("%s%s", pCE->logfile, timestr);

	if (rename(pCE->logfile, t) != 0) {
	    Error("[%s] RollLogs(): rename(%s,%s) failed: %s", pCE->server,
		  pCE->logfile, t, strerror(errno));
	    continue;
	}

	old = pCE->fdlog;

	if ((pCE->fdlog =
	     FileOpen(pCE->logfile, O_RDWR | O_CREAT | O_APPEND,
		      0644)) == (CONSFILE *)0) {
	    FileClose(&old);
	    Error("[%s] RollLogs(): open(%s): %s: forcing down",
		  pCE->server, pCE->logfile, strerror(errno));
	    ConsDown(pCE, FLAGTRUE, FLAGTRUE);
	    continue;
	}
	if (r > 0) {
	    FileWrite(pCE->fdlog, FLAGFALSE, buf + roll - r, r);
	    ftruncate(FileFDNum(old), stLog.st_size - r);
	}

	FileClose(&old);
    }

    if (tyme != (time_t)0)
	BuildTmpString((char *)0);

    if (maxset == 0)
	timers[T_ROLL] = (time_t)0;
    else {
	if (timers[T_ROLL] == (time_t)0)
	    /* try and spread processes out a bit */
	    timers[T_ROLL] = time((time_t *)0) + 300 + (pGE->id * 7) % 60;
	else
	    timers[T_ROLL] = time((time_t *)0) + 300;
    }
}

static void
Mark(GRPENT *pGE)
{
    time_t tyme;
    CONSENT *pCE;
    static STRING *out = (STRING *)0;

    if ((GRPENT *)0 == pGE)
	return;

    if (out == (STRING *)0)
	out = AllocString();

    BuildString((char *)0, out);

    /* [-- MARK -- `date`] */
    BuildStringPrint(out, "[-- MARK -- %s]\r\n", StrTime(&tyme));

    timers[T_MARK] = (time_t)0;

    for (pCE = pGE->pCElist; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	if (pCE->nextMark > 0) {
	    if (tyme >= pCE->nextMark) {
		if ((CONSFILE *)0 != pCE->fdlog) {
		    CONDDEBUG((1, "Mark(): [-- MARK --] stamp added to %s",
			       pCE->logfile));
		    FileWrite(pCE->fdlog, FLAGFALSE, out->string,
			      out->used - 1);
		}
		/* Add as many pCE->mark values as necessary so that we move
		 * beyond the current time.
		 */
		pCE->nextMark +=
		    (((tyme - pCE->nextMark) / pCE->mark) + 1) * pCE->mark;
	    }
	    if (timers[T_MARK] == (time_t)0 ||
		timers[T_MARK] > pCE->nextMark)
		timers[T_MARK] = pCE->nextMark;
	}
    }
}

void
WriteLog(CONSENT *pCE, char *s, int len)
{
    int i = 0;
    int j;
    static STRING *buf = (STRING *)0;

    if ((CONSFILE *)0 == pCE->fdlog) {
	return;
    }
    if (pCE->mark >= 0) {	/* no line marking */
	FileWrite(pCE->fdlog, FLAGFALSE, s, len);
	return;
    }

    if (buf == (STRING *)0)
	buf = AllocString();
    BuildString((char *)0, buf);

    for (j = 0; j < len; j++) {
	if (pCE->nextMark == 0) {
	    FileWrite(pCE->fdlog, FLAGTRUE, s + i, j - i);
	    i = j;

	    if (buf->used <= 1)
		BuildStringPrint(buf, "[%s]", StrTime((time_t *)0));

	    FileWrite(pCE->fdlog, FLAGTRUE, buf->string, buf->used - 1);
	    pCE->nextMark = pCE->mark;
	}
	if (s[j] == '\n') {
	    CONDDEBUG((1,
		       "WriteLog(): [%s] found newline (nextMark=%d, mark=%d)",
		       pCE->server, pCE->nextMark, pCE->mark));
	    pCE->nextMark++;
	}
    }
    if (i < j) {
	FileWrite(pCE->fdlog, FLAGTRUE, s + i, j - i);
    }
    FileWrite(pCE->fdlog, FLAGFALSE, (char *)0, 0);
}

static RETSIGTYPE
FlagGoAway(int sig)
{
    fSawGoAway = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGTERM, FlagGoAway);
#endif
}

/* yep, basically the same...ah well, maybe someday */
static RETSIGTYPE
FlagGoAwayAlso(int sig)
{
    fSawGoAway = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGINT, FlagGoAwayAlso);
#endif
}

static RETSIGTYPE
FlagReapVirt(int sig)
{
    fSawReapVirt = 1;
#if !HAVE_SIGACTION
    SimpleSignal(SIGCHLD, FlagReapVirt);
#endif
}

/* on a TERM we have to cleanup utmp entries (ask ptyd to do it)	(ksb)
 */
void
DeUtmp(GRPENT *pGE, int sfd)
{
    CONSENT *pCE;
#if USE_UNIX_DOMAIN_SOCKETS
    struct sockaddr_un lstn_port;
    socklen_t so;

    so = sizeof(lstn_port);
    if (getsockname(sfd, (struct sockaddr *)&lstn_port, &so) != -1)
	unlink(lstn_port.sun_path);
#endif
    /* shut down the socket */
    close(sfd);

    /* say Bye to all connections */
    if ((GRPENT *)0 != pGE) {
	DisconnectAllClients(pGE,
			     "[-- Console server shutting down --]\r\n");

	for (pCE = pGE->pCElist; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	    ConsDown(pCE, FLAGFALSE, FLAGTRUE);
	}
    }

    if (unifiedlog != (CONSFILE *)0)
	FileClose(&unifiedlog);

    DumpDataStructures();

    endpwent();
    Bye(EX_OK);
}

/* virtual console procs are our kids, when they die we get a CHLD	(ksb)
 * which will send us here to clean up the exit code.  The lack of a
 * reader on the pseudo will cause us to notice the death in Kiddie...
 */
static void
ReapVirt(GRPENT *pGE)
{
    pid_t pid;
    int UWbuf;
    CONSENT *pCE;

    while (-1 != (pid = waitpid(-1, &UWbuf, WNOHANG | WUNTRACED))) {
	if (0 == pid) {
	    break;
	}
	/* stopped child is just continued
	 */
	if (WIFSTOPPED(UWbuf) && 0 == kill(pid, SIGCONT)) {
	    Msg("child pid %lu: stopped, sending SIGCONT",
		(unsigned long)pid);
	    continue;
	}

	if ((GRPENT *)0 == pGE) {
	    continue;
	}

	for (pCE = pGE->pCElist; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	    if (pid == pCE->initpid) {
		if (WIFEXITED(UWbuf))
		    Msg("[%s] initcmd terminated: pid %lu: exit(%d)",
			pCE->server, pid, WEXITSTATUS(UWbuf));
		if (WIFSIGNALED(UWbuf))
		    Msg("[%s] initcmd terminated: pid %lu: signal(%d)",
			pCE->server, pid, WTERMSIG(UWbuf));
		TagLogfileAct(pCE, "initcmd terminated");
		pCE->initpid = 0;
		StopInit(pCE);
		break;
	    }
	    if (pid == pCE->taskpid) {
		CONSCLIENT *pCL;
		if (WIFEXITED(UWbuf)) {
		    Msg("[%s] task terminated: pid %lu: exit(%d)",
			pCE->server, pid, WEXITSTATUS(UWbuf));
		    if (pCE->tasklog == FLAGTRUE)
			TagLogfile(pCE,
				   "task terminated: pid %lu: exit(%d)",
				   pid, WEXITSTATUS(UWbuf));
		    /* tell all how it ended */
		    for (pCL = pCE->pCLon; (CONSCLIENT *)0 != pCL;
			 pCL = pCL->pCLnext) {
			if (pCL->fcon) {
			    FilePrint(pCL->fd, FLAGFALSE,
				      "[task terminated: exit(%d)]\r\n",
				      WEXITSTATUS(UWbuf));
			}
		    }
		}
		if (WIFSIGNALED(UWbuf)) {
		    Msg("[%s] task terminated: pid %lu: signal(%d)",
			pCE->server, pid, WTERMSIG(UWbuf));
		    if (pCE->tasklog == FLAGTRUE)
			TagLogfile(pCE,
				   "task terminated: pid %lu: signal(%d)",
				   pid, WTERMSIG(UWbuf));
		    /* tell all how it ended */
		    for (pCL = pCE->pCLon; (CONSCLIENT *)0 != pCL;
			 pCL = pCL->pCLnext) {
			if (pCL->fcon) {
			    FilePrint(pCL->fd, FLAGFALSE,
				      "[task terminated: signal(%d)]\r\n",
				      WTERMSIG(UWbuf));
			}
		    }
		}
		pCE->taskpid = 0;
		StopTask(pCE);
		break;
	    }

	    if (pid != pCE->ipid)
		continue;

	    if (WIFEXITED(UWbuf))
		Msg("[%s] exit(%d)", pCE->server, WEXITSTATUS(UWbuf));
	    if (WIFSIGNALED(UWbuf))
		Msg("[%s] signal(%d)", pCE->server, WTERMSIG(UWbuf));

	    if (pCE->autoreinit != FLAGTRUE &&
		!(WIFEXITED(UWbuf) && WEXITSTATUS(UWbuf) == 0)) {
		ConsDown(pCE, FLAGTRUE, FLAGFALSE);
	    } else {
		/* Try an initial reconnect */
		Msg("[%s] automatic reinitialization", pCE->server);
		ConsInit(pCE);

		/* If we didn't succeed, try again later */
		if (!pCE->fup)
		    pCE->autoReUp = 1;
	    }
	    break;
	}
    }
}

int
CheckPasswd(CONSCLIENT *pCL, char *pw_string, FLAG empty_check)
{
    FILE *fp;
    int iLine = 0;
    char *this_pw, *user;

#if USE_UNIX_DOMAIN_SOCKETS
# if TRUST_UDS_CRED
    struct UDS_CRED_STYPE client_cred;
    socklen_t client_cred_len = sizeof(client_cred);
    memset(&client_cred, 0, sizeof(client_cred));
    int err;

    if ((err =
	 getsockopt(pCL->fd->fd, SOL_SOCKET, UDS_CRED_SO, &client_cred,
		    &client_cred_len)) == -1) {
	Error("CheckPasswd(): getsockopt(CREDENTIALS) failed: %s",
	      strerror(err));
    } else if (client_cred.pid != 0) {
	/* Does pCL->username->string and client_cred.uid match ? */
	struct passwd *pwd = (struct passwd *)0;

	/* we allow root to impersonate anyone */
	if (client_cred.UDS_CRED_UID == 0)
	    return AUTH_SUCCESS;

	if ((pwd = getpwnam(pCL->username->string)) != NULL) {
	    if (pwd->pw_uid == client_cred.UDS_CRED_UID) {
		Verbose("user %s authenticated", pCL->username->string);
		return AUTH_SUCCESS;
	    }
	}
    }
# endif
#endif

    if ((fp = fopen(config->passwdfile, "r")) == (FILE *)0) {
	if (CheckPass(pCL->username->string, pw_string, empty_check) ==
	    AUTH_SUCCESS) {
	    Verbose("user %s authenticated", pCL->acid->string);
	    return AUTH_SUCCESS;
	}
    } else {
	char *wholeLine;
	static STRING *saveLine = (STRING *)0;

	if (saveLine == (STRING *)0)
	    saveLine = AllocString();
	BuildString((char *)0, saveLine);

	while ((wholeLine = ReadLine(fp, saveLine, &iLine)) != (char *)0) {
	    PruneSpace(wholeLine);
	    /*printf("whole=<%s>\n", wholeLine); */
	    if (wholeLine[0] == '\000')
		continue;

	    if ((char *)0 == (this_pw = strchr(wholeLine, ':'))) {
		Error("CheckPasswd(): %s(%d) bad password line `%s'",
		      config->passwdfile, iLine, wholeLine);
		continue;
	    }
	    *this_pw++ = '\000';
	    user = PruneSpace(wholeLine);
	    this_pw = PruneSpace(this_pw);

	    if (strcmp(user, "*any*") != 0 &&
		strcmp(user, pCL->username->string) != 0)
		continue;

	    /* If one is empty and the other isn't, instant failure */
	    if ((*this_pw == '\000' && *pw_string != '\000') ||
		(*this_pw != '\000' && *pw_string == '\000')) {
		break;
	    }

	    if ((*this_pw == '\000' && *pw_string == '\000') ||
		((strcmp(this_pw, "*passwd*") ==
		  0) ? (CheckPass(pCL->username->string, pw_string,
				  empty_check) ==
			AUTH_SUCCESS) : (strcmp(this_pw,
						crypt(pw_string,
						      this_pw)) == 0))) {
		Verbose("user %s authenticated", pCL->acid->string);
		fclose(fp);
		return AUTH_SUCCESS;
	    }
	    break;
	}
	fclose(fp);
    }

    return AUTH_INVALID;
}

static char *
IdleTyme(long tyme)
{
    long hours, minutes;
    static STRING *timestr = (STRING *)0;

    if (timestr == (STRING *)0)
	timestr = AllocString();

    minutes = tyme / 60;
    hours = minutes / 60;
    minutes = minutes % 60;

    BuildString((char *)0, timestr);
    if (hours < 24)
	BuildStringPrint(timestr, " %2ld:%02ld", hours, minutes);
    else if (hours < 24 * 2)
	BuildStringPrint(timestr, " 1 day");
    else if (hours < 24 * 10)
	BuildStringPrint(timestr, "%1ld days", hours / 24);
    else
	BuildStringPrint(timestr, "%2lddays", hours / 24);

    return timestr->string;
}

void
PutConsole(CONSENT *pCEServing, unsigned char c, int quote)
{
    /* if we need to send an IAC char to a telnet-based port, quote
     * the thing (which means send two to the port).  but, since we're
     * using IAC as a trigger for breaks and pauses, we have to load
     * two into the buffer here and two below (so two get sent).
     *
     * if we're just sending a IAC character in the raw, the 'quote'
     * flag will not be set and we'll put only two IAC chars into
     * the buffer (below)...which will result in one to the port.
     *
     * we're also tracking the first IAC character in the buffer with
     * the wbufIAC variable...that way we don't have to do a string
     * search every time we flush this thing ('cause it should be
     * rather infrequent to have an IAC char).
     *
     * quote == 0, raw - processed by conserver
     * quote == 1, console - processed by console
     * quote == 2, telnet - processed by telnet protocol
     * if console != telnet, 1 == 2
     */
    if (quote == 1 && pCEServing->type == HOST &&
	pCEServing->raw != FLAGTRUE && c == IAC) {
	BuildStringChar((char)c, pCEServing->wbuf);
	if (pCEServing->wbufIAC == 0)
	    pCEServing->wbufIAC = pCEServing->wbuf->used;
	BuildStringChar((char)c, pCEServing->wbuf);
    }
    /* if we're trying to send an IAC char, quote it in the buffer */
    if (quote && c == IAC) {
	BuildStringChar((char)c, pCEServing->wbuf);
	if (pCEServing->wbufIAC == 0)
	    pCEServing->wbufIAC = pCEServing->wbuf->used;
    }
    BuildStringChar((char)c, pCEServing->wbuf);
    if (c == IAC && pCEServing->wbufIAC == 0)
	pCEServing->wbufIAC = pCEServing->wbuf->used;

    CONDDEBUG((1, "PutConsole(): queued byte to console %s",
	       pCEServing->server));
}

void
ExpandString(char *str, CONSENT *pCE, short breaknum)
{
    char s;
    short backslash = 0;
    short cntrl = 0;
    char oct = '\000';
    short octs = 0;

    if (str == (char *)0 || pCE == (CONSENT *)0)
	return;

    backslash = 0;
    cntrl = 0;
    while ((s = (*str++)) != '\000') {
	if (octs > 0 && octs < 3 && s >= '0' && s <= '7') {
	    ++octs;
	    oct = oct * 8 + (s - '0');
	    continue;
	}
	if (octs != 0) {
	    PutConsole(pCE, oct, 1);
	    octs = 0;
	    oct = '\000';
	}
	if (backslash) {
	    backslash = 0;
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
	    else if (s >= '0' && s <= '7') {
		++octs;
		oct = oct * 8 + (s - '0');
		continue;
	    } else if (s == 'd') {
		PutConsole(pCE, IAC, 0);
		PutConsole(pCE,
			   '0' + breaknum + (breaknum >
					     9 ? BREAKALPHAOFFSET : 0), 0);
		continue;
	    } else if (s == 'z') {
		PutConsole(pCE, IAC, 0);
		PutConsole(pCE, BREAK, 0);
		continue;
	    }
	    PutConsole(pCE, s, 1);
	    continue;
	}
	if (cntrl) {
	    cntrl = 0;
	    if (s == '?')
		s = 0x7f;	/* delete */
	    else
		s = s & 0x1f;
	    PutConsole(pCE, s, 1);
	    continue;
	}
	if (s == '\\') {
	    backslash = 1;
	    continue;
	}
	if (s == '^') {
	    cntrl = 1;
	    continue;
	}
	PutConsole(pCE, s, 1);
    }

    if (octs != 0)
	PutConsole(pCE, oct, 1);

    if (backslash)
	PutConsole(pCE, '\\', 1);

    if (cntrl)
	PutConsole(pCE, '^', 1);
}

void
SendBreak(CONSCLIENT *pCLServing, CONSENT *pCEServing, short bt)
{
    CONSCLIENT *pCL;

    short waszero = 0;
    if (bt < 0 || bt > BREAKLISTSIZE) {
	FileWrite(pCLServing->fd, FLAGFALSE, "aborted]\r\n", -1);
	return;
    }
    if (bt == 0) {
	bt = pCEServing->breakNum;
	waszero = 1;
    }
    if (bt == 0 || breakList[bt - 1].seq->used <= 1) {
	FileWrite(pCLServing->fd, FLAGFALSE, "undefined]\r\n", -1);
	return;
    }

    if (breakList[bt - 1].confirm == FLAGTRUE) {
	switch (pCLServing->confirmed) {
	    case FLAGUNKNOWN:
		FileWrite(pCLServing->fd, FLAGFALSE, "confirm? [y/N] ",
			  -1);
		pCLServing->confirmed = FLAGFALSE;
		pCLServing->cState = S_HALT1;
		pCLServing->iState = S_CONFIRM;
		pCLServing->cOption = '0' + bt;
		return;
	    case FLAGFALSE:
		FileWrite(pCLServing->fd, FLAGFALSE, "aborted]\r\n", -1);
		pCLServing->confirmed = FLAGUNKNOWN;
		return;
	    case FLAGTRUE:
		pCLServing->confirmed = FLAGUNKNOWN;
	}
    }


    ExpandString(breakList[bt - 1].seq->string, pCEServing, bt);

    FileWrite(pCLServing->fd, FLAGFALSE, "sent]\r\n", -1);

    /* tell all who sent it */
    for (pCL = pCEServing->pCLon; (CONSCLIENT *)0 != pCL;
	 pCL = pCL->pCLnext) {
	if (pCL == pCLServing)
	    continue;
	if (pCL->fcon) {
	    FilePrint(pCL->fd, FLAGFALSE, "[break sent by %s]\r\n",
		      pCLServing->acid->string);
	}
    }

    if (pCEServing->breaklog == FLAGTRUE) {
	if (waszero) {
	    TagLogfile(pCEServing, "break #0(%c) sent -- `%s'",
		       '0' + bt + (bt > 9 ? BREAKALPHAOFFSET : 0),
		       breakList[bt - 1].seq->string);
	} else {
	    TagLogfile(pCEServing, "break #%c sent -- `%s'",
		       '0' + bt + (bt > 9 ? BREAKALPHAOFFSET : 0),
		       breakList[bt - 1].seq->string);
	}
    }
}

static int
StartTask(CONSENT *pCE, char *cmd, uid_t uid, gid_t gid)
{
    int i;
    extern char **environ;
    char *pcShell, **ppcArgv;
    extern int FallBack(char **, int *);
    char *execSlave = (char *)0;	/* pseudo-device slave side             */
    int execSlaveFD;		/* fd of slave side                     */
    int cofile;

    if ((cofile = FallBack(&execSlave, &execSlaveFD)) == -1) {
	Error("[%s] StartTask(): failed to allocate pseudo-tty: %s",
	      pCE->server, strerror(errno));
	return -1;
    }
    if (execSlave != (char *)0)
	free(execSlave);

    fflush(stdout);
    fflush(stderr);

    switch (pCE->taskpid = fork()) {
	case -1:
	    pCE->taskpid = 0;
	    return -1;
	case 0:
	    break;
	default:		/* server */
	    close(execSlaveFD);
	    if ((pCE->taskfile =
		 FileOpenFD(cofile, simpleFile)) == (CONSFILE *)0) {
		close(cofile);
		Error("[%s] FileOpenFD(%d,simpleFile) failed", pCE->server,
		      cofile);
		return -1;
	    }
	    Msg("[%s] task started: pid %lu", pCE->server,
		(unsigned long)pCE->taskpid);
	    FD_SET(cofile, &rinit);
	    if (maxfd < cofile + 1)
		maxfd = cofile + 1;
	    fflush(stderr);
	    return 0;
    }

    close(cofile);

#if HAVE_SETSID
    setsid();
#else
    tcsetpgrp(0, getpid());
#endif

    close(1);
    if (dup(execSlaveFD) != 1) {
	Error("[%s] StartTask(): fd 1 sync error", pCE->server);
	exit(EX_OSERR);
    }
    close(2);
    if (dup(execSlaveFD) != 2) {
	exit(EX_OSERR);
    }
    /* no stdin */
    close(0);
    close(execSlaveFD);

    /* setup new process with clean file descriptors
     */
#if HAVE_CLOSEFROM
    closefrom(3);
#else
    i = GetMaxFiles();
    for ( /* i above */ ; --i > 2;) {
	close(i);
    }
#endif

    if (geteuid() == 0) {
	if (gid != 0)
	    setgid(gid);
	if (uid != 0)
	    setuid(uid);
    }

    SetupTty(pCE, 1);

    pcShell = "/bin/sh";
    static char *apcArgv[] = {
	"/bin/sh", "-ce", (char *)0, (char *)0
    };

    apcArgv[2] = cmd;
    ppcArgv = apcArgv;

    execve(pcShell, ppcArgv, environ);
    Error("[%s] execve(): %s", pCE->server, strerror(errno));
    exit(EX_OSERR);
    return -1;
}

void
InvokeTask(CONSCLIENT *pCLServing, CONSENT *pCEServing, char id)
{
    TASKS *t = (TASKS *)0;
    char *cmd;

    if ((id < '0' || id > '9') && (id < 'a' || id > 'z')) {
	FileWrite(pCLServing->fd, FLAGFALSE, "aborted]\r\n", -1);
	return;
    }

    if (pCEServing->taskpid != 0) {
	FileWrite(pCLServing->fd, FLAGFALSE, "aborted - task running]\r\n",
		  -1);
	return;
    }

    if ((char *)0 != strchr(pCEServing->tasklist, id) ||
	(char *)0 != strchr(pCEServing->tasklist, '*')) {
	for (t = taskList; t != (TASKS *)0; t = t->next) {
	    if (t->id == id)
		break;
	}
    }

    if (t == (TASKS *)0) {
	FileWrite(pCLServing->fd, FLAGFALSE, "undefined]\r\n", -1);
	return;
    }

    if (t->confirm == FLAGTRUE) {
	switch (pCLServing->confirmed) {
	    case FLAGUNKNOWN:
		FileWrite(pCLServing->fd, FLAGFALSE, "confirm? [y/N] ",
			  -1);
		pCLServing->confirmed = FLAGFALSE;
		pCLServing->cState = S_TASK;
		pCLServing->iState = S_CONFIRM;
		pCLServing->cOption = id;
		return;
	    case FLAGFALSE:
		FileWrite(pCLServing->fd, FLAGFALSE, "aborted]\r\n", -1);
		pCLServing->confirmed = FLAGUNKNOWN;
		return;
	    case FLAGTRUE:
		pCLServing->confirmed = FLAGUNKNOWN;
	}
    }

    if ((cmd = StrDup(t->cmd->string)) == (char *)0)
	OutOfMem();

    if (t->subst != (char *)0) {
	substData->data = (void *)pCEServing;
	ProcessSubst(substData, &cmd, (char **)0, (char *)0, t->subst);
    }

    if (StartTask(pCEServing, cmd, t->uid, t->gid) == 0) {
	CONSCLIENT *pCL;
	char *detail;

	FilePrint(pCLServing->fd, FLAGFALSE, "`%c' started]\r\n", id);
	detail = t->descr->used > 1 ? t->descr->string : cmd;

	/* tell all who started it */
	for (pCL = pCEServing->pCLon; (CONSCLIENT *)0 != pCL;
	     pCL = pCL->pCLnext) {
	    if (pCL == pCLServing)
		continue;
	    if (pCL->fcon) {
		FilePrint(pCL->fd, FLAGFALSE,
			  "[task `%s' started by %s]\r\n", detail,
			  pCLServing->acid->string);
	    }
	}

	if (pCEServing->tasklog == FLAGTRUE) {
	    TagLogfile(pCEServing, "task started: pid %lu -- `%s'",
		       pCEServing->taskpid, cmd);
	}
    } else {
	FileWrite(pCLServing->fd, FLAGFALSE, "failure]\r\n", -1);
    }
    free(cmd);
}

#if HAVE_OPENSSL
int
AttemptSSL(CONSCLIENT *pCL)
{
    int fdnum;
    SSL *ssl;
    int retval;

    fdnum = FileFDNum(pCL->fd);
    if (ctx == (SSL_CTX *)0) {
	Error("AttemptSSL(): WTF?  The SSL context disappeared?!?!?");
	Bye(EX_SOFTWARE);
    }
    if (!(ssl = SSL_new(ctx))) {
	Error("AttemptSSL(): SSL_new() failed for fd %d", fdnum);
	return 0;
    }
    FileSetSSL(pCL->fd, ssl);
    SSL_set_accept_state(ssl);
    SSL_set_fd(ssl, fdnum);

    if ((retval = FileSSLAccept(pCL->fd)) < 0) {
	Error("AttemptSSL(): FileSSLAccept() failed for fd %d", fdnum);
	return 0;
    } else if (retval == 0)
	pCL->ioState = INSSLACCEPT;
    return 1;
}
#endif

#if HAVE_GSSAPI
int
AttemptGSSAPI(CONSCLIENT *pCL)
{
    int nr, ret = 0;
    char buf[1024];
    gss_buffer_desc sendtok, recvtok, dbuf;
    gss_ctx_id_t gssctx = GSS_C_NO_CONTEXT;
    OM_uint32 stmaj, stmin, mctx, dmin;
    gss_name_t user = 0;

    if ((nr = FileRead(pCL->fd, buf, sizeof(buf))) <= 0) {
	return nr;
    }
    recvtok.value = buf;
    recvtok.length = nr;

    stmaj =
	gss_accept_sec_context(&stmin, &gssctx, gss_mycreds, &recvtok,
			       NULL, &user, NULL, &sendtok, NULL, NULL,
			       NULL);
    switch (stmaj) {
	case GSS_S_COMPLETE:
	    FileSetQuoteIAC(pCL->fd, FLAGFALSE);
	    FileWrite(pCL->fd, FLAGFALSE, sendtok.value, sendtok.length);
	    FileSetQuoteIAC(pCL->fd, FLAGTRUE);
	    pCL->iState = S_NORMAL;
	    gss_release_buffer(&stmin, &sendtok);
	    BuildString((char *)0, pCL->username);
	    BuildString((char *)0, pCL->acid);
	    stmaj = gss_display_name(&stmin, user, &dbuf, NULL);

	    BuildStringN(dbuf.value, dbuf.length, pCL->username);
	    BuildStringN(dbuf.value, dbuf.length, pCL->acid);
	    BuildStringChar('@', pCL->acid);
	    BuildString(pCL->peername->string, pCL->acid);
	    gss_release_name(&stmin, &user);
	    gss_release_buffer(&stmin, &dbuf);
	    ret = 1;
	    break;
	case GSS_S_CREDENTIALS_EXPIRED:
	    /* reacquire creds and try again */
	    Error("Credentials expired");
	    break;
	default:
	    gss_display_status(&dmin, stmaj, GSS_C_GSS_CODE,
			       GSS_C_NULL_OID, &mctx, &dbuf);
	    Error("GSSAPI didn't work, %*s", dbuf.length, dbuf.value);
	    ret = -1;
    }
    return ret;
}
#endif

CONSENT *
HuntForConsole(GRPENT *pGE, char *name)
{
    /* try to find a given console
     * we assume all the right checks for ambiguity
     * were already done by the master process, so
     * the first match should be what the user wants
     */
    CONSENT *pCE = (CONSENT *)0;

    if (name == (char *)0)
	return pCE;

    for (pCE = pGE->pCElist; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	NAMES *n = (NAMES *)0;
	if (strcasecmp(name, pCE->server) == 0)
	    break;
	for (n = pCE->aliases; n != (NAMES *)0; n = n->next) {
	    if (strcasecmp(name, n->name) == 0)
		break;
	}
	if (n != (NAMES *)0)
	    break;
    }
    if (pCE == (CONSENT *)0 && config->autocomplete == FLAGTRUE) {
	NAMES *n = (NAMES *)0;
	int len = strlen(name);
	for (pCE = pGE->pCElist; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	    if (strncasecmp(name, pCE->server, len) == 0)
		break;
	    for (n = pCE->aliases; n != (NAMES *)0; n = n->next) {
		if (strncasecmp(name, n->name, len) == 0)
		    break;
	    }
	    if (n != (NAMES *)0)
		break;
	}
    }
    return pCE;
}

void
CommandAttach(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	      long tyme)
{
    CONSCLIENT *pCL;

    ClientWantsWrite(pCLServing);

    if (pCEServing->fronly) {
	FileWrite(pCLServing->fd, FLAGFALSE, "console is read-only]\r\n",
		  -1);
    } else if (pCLServing->fro) {
	FileWrite(pCLServing->fd, FLAGFALSE, "read-only]\r\n", -1);
    } else if ((CONSCLIENT *)0 == (pCL = pCEServing->pCLwr)) {
	pCEServing->pCLwr = pCLServing;
	pCLServing->fwr = 1;
	if (pCEServing->nolog) {
	    FileWrite(pCLServing->fd, FLAGFALSE,
		      "attached (nologging)]\r\n", -1);
	} else {
	    FileWrite(pCLServing->fd, FLAGFALSE, "attached]\r\n", -1);
	}
	TagLogfileAct(pCEServing, "%s attached", pCLServing->acid->string);
    } else if (pCL == pCLServing) {
	if (pCEServing->nolog) {
	    FileWrite(pCLServing->fd, FLAGFALSE, "ok (nologging)]\r\n",
		      -1);
	} else {
	    FileWrite(pCLServing->fd, FLAGFALSE, "ok]\r\n", -1);
	}
    } else {
	FilePrint(pCLServing->fd, FLAGFALSE, "no, %s is attached]\r\n",
		  pCL->acid->string);
    }
}

void
CommandChangeFlow(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
		  long tyme)
{
    struct termios sbuf;
    int cofile;

    if (!pCLServing->fwr) {
	FileWrite(pCLServing->fd, FLAGFALSE, "attach to change flow]\r\n",
		  -1);
	return;
    }
    if (pCEServing->type != DEVICE && pCEServing->type != EXEC) {
	FileWrite(pCLServing->fd, FLAGFALSE, "ok]\r\n", -1);
	return;
    }
    cofile = FileFDNum(pCEServing->cofile);
    if (-1 == tcgetattr(cofile, &sbuf)) {
	FileWrite(pCLServing->fd, FLAGFALSE, "failed]\r\n", -1);
	return;
    }
    if (0 != (sbuf.c_iflag & IXON)) {
	sbuf.c_iflag &= ~(IXON);
    } else {
	sbuf.c_iflag |= IXON;
    }
    if (-1 == tcsetattr(cofile, TCSANOW, &sbuf)) {
	FileWrite(pCLServing->fd, FLAGFALSE, "failed]\r\n", -1);
	return;
    }
    if ((sbuf.c_iflag & IXON) == 0) {
	FileWrite(pCLServing->fd, FLAGFALSE, "ixon OFF]\r\n", -1);
    } else {
	FileWrite(pCLServing->fd, FLAGFALSE, "ixon ON]\r\n", -1);
    }
}

void
CommandDown(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	    long tyme)
{
    CONSCLIENT *pCL;

    if (!pCLServing->fwr) {
	FileWrite(pCLServing->fd, FLAGFALSE, "attach to down line]\r\n",
		  -1);
	return;
    }
    if (!pCEServing->fup) {
	FileWrite(pCLServing->fd, FLAGFALSE, "ok]\r\n", -1);
	return;
    }

    ConsDown(pCEServing, FLAGFALSE, FLAGFALSE);
    FileWrite(pCLServing->fd, FLAGFALSE, "line down]\r\n", -1);

    /* tell all who closed it */
    for (pCL = pCEServing->pCLon; (CONSCLIENT *)0 != pCL;
	 pCL = pCL->pCLnext) {
	if (pCL == pCLServing)
	    continue;
	if (pCL->fcon) {
	    FilePrint(pCL->fd, FLAGFALSE, "[line down by %s]\r\n",
		      pCLServing->acid->string);
	}
    }
}

void
CommandExamine(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	       long tyme, char *args)
{
    CONSENT *pCE;

    if (args == (char *)0)
	pCE = pGE->pCElist;
    else
	pCE = HuntForConsole(pGE, args);

    for (; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	char *d = (char *)0;
	char *b = (char *)0;
	char p = '\000';
	switch (pCE->type) {
	    case EXEC:
		d = pCE->execSlave;
		b = "Local";
		p = ' ';
		break;
	    case DEVICE:
		d = BuildTmpStringPrint("%s@%s", pCE->device, pCE->master);
		b = pCE->baud->acrate;
		p = pCE->parity->key[0];
		break;
#if HAVE_FREEIPMI
	    case IPMI:
		d = BuildTmpStringPrint("%s", pCE->host);
		b = "IPMI";
		p = ' ';
		break;
#endif
	    case HOST:
		d = BuildTmpStringPrint("%s/%hu", pCE->host, pCE->netport);
		b = "Netwk";
		p = ' ';
		break;
	    case NOOP:
		d = "NOOP";
		b = "NOOP";
		p = ' ';
		break;
	    case UDS:
		d = pCE->uds;
		b = "UDS";
		p = ' ';
		break;
	    case UNKNOWNTYPE:	/* shut up gcc */
		break;
	}
	FilePrint(pCLServing->fd, FLAGFALSE,
		  " %-24.24s on %-32.32s at %7.7s%c\r\n", pCE->server, d,
		  b, p);
	if (args != (char *)0)
	    break;
    }
}

void
CommandForce(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	     long tyme)
{
    CONSCLIENT *pCL;

    ClientWantsWrite(pCLServing);

    if (pCLServing->fro) {
	FileWrite(pCLServing->fd, FLAGFALSE, "read-only]\r\n", -1);
	return;
    } else if (pCEServing->fronly) {
	FileWrite(pCLServing->fd, FLAGFALSE, "console is read-only]\r\n",
		  -1);
	return;
    }
    if ((CONSCLIENT *)0 != (pCL = pCEServing->pCLwr)) {
	if (pCL == pCLServing) {
	    if (pCEServing->nolog) {
		FileWrite(pCLServing->fd, FLAGFALSE, "ok (nologging)]\r\n",
			  -1);
	    } else {
		FileWrite(pCLServing->fd, FLAGFALSE, "ok]\r\n", -1);
	    }
	    return;
	}
	if (pCEServing->nolog) {
	    FilePrint(pCLServing->fd, FLAGFALSE,
		      "bumped %s (nologging)]\r\n", pCL->acid->string);
	} else {
	    FilePrint(pCLServing->fd, FLAGFALSE, "bumped %s]\r\n",
		      pCL->acid->string);
	}
	AbortAnyClientExec(pCL);
	BumpClient(pCEServing, (char *)0);
	ClientWantsWrite(pCL);
	if (pCL->fcon)
	    FilePrint(pCL->fd, FLAGFALSE,
		      "\r\n[forced to `spy' mode by %s]\r\n",
		      pCLServing->acid->string);
	TagLogfileAct(pCEServing, "%s bumped %s", pCLServing->acid->string,
		      pCL->acid->string);
    } else {
	if (pCEServing->nolog) {
	    FileWrite(pCLServing->fd, FLAGFALSE,
		      "attached (nologging)]\r\n", -1);
	} else {
	    FileWrite(pCLServing->fd, FLAGFALSE, "attached]\r\n", -1);
	}
	TagLogfileAct(pCEServing, "%s attached", pCLServing->acid->string);
    }
    pCEServing->pCLwr = pCLServing;
    pCLServing->fwr = 1;
}

void
CommandGroup(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	     long tyme, char *args)
{
    CONSCLIENT *pCL;
    CONSENT *pCE;

    pCE = HuntForConsole(pGE, args);

    /* we do not show the ctl console
     * else we'd get the client always
     */
    for (pCL = pGE->pCLall; (CONSCLIENT *)0 != pCL; pCL = pCL->pCLscan) {
	if (pGE->pCEctl == pCL->pCEto)
	    continue;
	if (pCE != (CONSENT *)0 && pCL->pCEto != pCE)
	    continue;
	FilePrint(pCLServing->fd, FLAGFALSE,
		  " %-32.32s %c %-7.7s %6s %s\r\n", pCL->acid->string,
		  pCL == pCLServing ? '*' : ' ',
		  pCL->fcon ? (pCL->fwr ? "attach" : "spy") : "stopped",
		  IdleTyme(tyme - pCL->typetym), pCL->pCEto->server);
    }
}

void
CommandHosts(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	     long tyme, char *args)
{
    CONSENT *pCE;

    if (args == (char *)0)
	pCE = pGE->pCElist;
    else
	pCE = HuntForConsole(pGE, args);

    for (; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	FilePrint(pCLServing->fd, FLAGFALSE,
		  " %-24.24s %c %-4.4s %-.40s\r\n", pCE->server,
		  pCE == pCEServing ? '*' : ' ', (pCE->fup &&
						  pCE->ioState == ISNORMAL)
		  ? (pCE->initfile == (CONSFILE *)
		     0 ? "up" : "init") : "down",
		  pCE->pCLwr ? pCE->pCLwr->acid->
		  string : pCE->pCLon ? "<spies>" : "<none>");
	if (args != (char *)0)
	    break;
    }
}

void
CommandInfo(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	    long tyme, char *args)
{
    CONSENT *pCE;
    CONSCLIENT *pCL;

    if (args == (char *)0)
	pCE = pGE->pCElist;
    else
	pCE = HuntForConsole(pGE, args);

    for (; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	int comma = 0;
	char *s = (char *)0;
	FilePrint(pCLServing->fd, FLAGTRUE, "%s:%s,%lu,%hu:", pCE->server,
		  myHostname, (unsigned long)thepid, pGE->port);
	switch (pCE->type) {
	    case EXEC:
		FilePrint(pCLServing->fd, FLAGTRUE, "|:%s,%lu,%s,%d:",
			  (pCE->exec != (char *)0 ? pCE->exec : "/bin/sh"),
			  (unsigned long)pCE->ipid, pCE->execSlave,
			  FileFDNum(pCE->cofile));
		break;
#if HAVE_FREEIPMI
	    case IPMI:
		FilePrint(pCLServing->fd, FLAGTRUE, "@:%s,%d:", pCE->host,
			  FileFDNum(pCE->cofile));
		break;
#endif
	    case HOST:
		FilePrint(pCLServing->fd, FLAGTRUE, "!:%s,%hu,%s,%d:",
			  pCE->host, pCE->netport,
			  (pCE->raw == FLAGTRUE ? "raw" : "telnet"),
			  FileFDNum(pCE->cofile));
		break;
	    case NOOP:
		FileWrite(pCLServing->fd, FLAGTRUE, "#::", 3);
		break;
	    case UDS:
		FilePrint(pCLServing->fd, FLAGTRUE, "%%:%s,%d:", pCE->uds,
			  FileFDNum(pCE->cofile));
		break;
	    case DEVICE:
		FilePrint(pCLServing->fd, FLAGTRUE, "/:%s,%s%c,%d:",
			  pCE->device,
			  (pCE->baud ? pCE->baud->acrate : ""),
			  (pCE->parity ? pCE->parity->key[0] : ' '),
			  FileFDNum(pCE->cofile));
		break;
	    case UNKNOWNTYPE:	/* shut up gcc */
		break;
	}
	if (pCE->pCLwr) {
	    FilePrint(pCLServing->fd, FLAGTRUE, "w@%s@%ld",
		      pCE->pCLwr->acid->string,
		      tyme - pCE->pCLwr->typetym);
	    comma = 1;
	}

	for (pCL = pCE->pCLon; (CONSCLIENT *)0 != pCL; pCL = pCL->pCLnext) {
	    if (pCL == pCE->pCLwr)
		continue;
	    if (comma)
		FilePrint(pCLServing->fd, FLAGTRUE, ",");
	    if (pCL->fcon)
		FilePrint(pCLServing->fd, FLAGTRUE, "r@%s@%ld@%s",
			  pCL->acid->string, tyme - pCL->typetym,
			  (pCL->fwantwr && !pCL->fro) ? "rw" : "ro");
	    else
		FilePrint(pCLServing->fd, FLAGTRUE, "s@%s@%ld@%s",
			  pCL->acid->string, tyme - pCL->typetym,
			  (pCL->fwantwr && !pCL->fro) ? "rw" : "ro");
	    comma = 1;
	}

	FilePrint(pCLServing->fd, FLAGTRUE,
		  ":%s:%s:%s,%s,%s,%s,%s,%d,%d:%d:%s:",
		  ((pCE->fup &&
		    pCE->ioState == ISNORMAL) ? (pCE->initfile ==
						 (CONSFILE *)0 ? "up" :
						 "init")
		   : "down"), (pCE->fronly ? "ro" : "rw"),
		  (pCE->logfile == (char *)0 ? "" : pCE->logfile),
		  (pCE->nolog ? "nolog" : "log"),
		  (pCE->activitylog == FLAGTRUE ? "act" : "noact"),
		  (pCE->breaklog == FLAGTRUE ? "brk" : "nobrk"),
		  (pCE->tasklog == FLAGTRUE ? "task" : "notask"),
		  pCE->mark, (pCE->fdlog ? pCE->fdlog->fd : -1),
		  pCE->breakNum, (pCE->autoReUp ? "autoup" : "noautoup"));
	if (pCE->aliases != (NAMES *)0) {
	    NAMES *n;
	    comma = 0;
	    for (n = pCE->aliases; n != (NAMES *)0; n = n->next) {
		if (comma)
		    FilePrint(pCLServing->fd, FLAGTRUE, ",");
		FilePrint(pCLServing->fd, FLAGTRUE, "%s", n->name);
		comma = 1;
	    }
	}
	BuildTmpString((char *)0);
	s = (char *)0;
	if (pCE->type == DEVICE) {
	    if (pCE->hupcl == FLAGTRUE)
		s = BuildTmpString(",hupcl");
	    if (pCE->cstopb == FLAGTRUE)
		s = BuildTmpString(",cstopb");
#if defined(CRTSCTS)
	    if (pCE->crtscts == FLAGTRUE)
		s = BuildTmpString(",crtscts");
#endif
	}
	if (pCE->type == DEVICE || pCE->type == EXEC) {
	    if (pCE->ixon == FLAGTRUE)
		s = BuildTmpString(",ixon");
	    if (pCE->ixany == FLAGTRUE)
		s = BuildTmpString(",ixany");
	    if (pCE->ixoff == FLAGTRUE)
		s = BuildTmpString(",ixoff");
	}
	if (pCE->ondemand == FLAGTRUE)
	    s = BuildTmpString(",ondemand");
	if (pCE->reinitoncc == FLAGTRUE)
	    s = BuildTmpString(",reinitoncc");
	if (pCE->striphigh == FLAGTRUE)
	    s = BuildTmpString(",striphigh");
	if (pCE->autoreinit == FLAGTRUE)
	    s = BuildTmpString(",autoreinit");
	if (pCE->unloved == FLAGTRUE)
	    s = BuildTmpString(",unloved");
	if (pCE->login == FLAGTRUE)
	    s = BuildTmpString(",login");
	FilePrint(pCLServing->fd, FLAGFALSE, ":%s:%s:%d:%s\r\n",
		  (s == (char *)0 ? "" : s + 1),
		  (pCE->initcmd == (char *)0 ? "" : pCE->initcmd),
		  pCE->idletimeout,
		  (pCE->idlestring == (char *)0 ? "" : pCE->idlestring));
	BuildTmpString((char *)0);
	if (args != (char *)0)
	    break;
    }
}

void
CommandLogging(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	       long tyme)
{
    if (pCLServing->fwr) {
	pCEServing->nolog = !pCEServing->nolog;
	if (pCEServing->nolog) {
	    FileWrite(pCLServing->fd, FLAGFALSE, "logging off]\r\n", -1);
	    TagLogfile(pCEServing, "Console logging disabled by %s",
		       pCLServing->acid->string);
	} else {
	    FileWrite(pCLServing->fd, FLAGFALSE, "logging on]\r\n", -1);
	    TagLogfile(pCEServing, "Console logging restored by %s",
		       pCLServing->acid->string);
	}
    } else {
	FilePrint(pCLServing->fd, FLAGFALSE,
		  "attach to toggle logging]\r\n");
    }
}

void
CommandOpen(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	    long tyme)
{
    CONSCLIENT *pCL;

    if (!pCLServing->fwr) {
	FileWrite(pCLServing->fd, FLAGFALSE, "attach to reopen]\r\n", -1);
	return;
    }
    /* with a close/re-open we might
     * change fd's
     */
    ConsInit(pCEServing);
    if (pCEServing->fup &&
	(pCEServing->initfile != (CONSFILE *)0 ||
	 pCEServing->ioState == INCONNECT)) {
	FileWrite(pCLServing->fd, FLAGFALSE, "connecting...", -1);
	pCLServing->fiwait = 1;
    } else if (pCEServing->fronly) {
	FilePrint(pCLServing->fd, FLAGFALSE, "%s -- read-only]\r\n",
		  pCEServing->fup ? "up" : "down");
    } else if ((CONSCLIENT *)0 == (pCL = pCEServing->pCLwr)) {
	pCEServing->pCLwr = pCLServing;
	pCLServing->fwr = 1;
	FilePrint(pCLServing->fd, FLAGFALSE, "%s -- attached]\r\n",
		  pCEServing->fup ? "up" : "down");
	TagLogfileAct(pCEServing, "%s attached", pCLServing->acid->string);
    } else if (pCL == pCLServing) {
	FilePrint(pCLServing->fd, FLAGFALSE, "%s]\r\n",
		  pCEServing->fup ? "up" : "down");
	TagLogfileAct(pCEServing, "%s attached", pCLServing->acid->string);
    } else {
	FilePrint(pCLServing->fd, FLAGFALSE, "%s, %s is attached]\r\n",
		  pCEServing->fup ? "up" : "down", pCL->acid->string);
    }
}

void
CommandWho(GRPENT *pGE, CONSCLIENT *pCLServing, CONSENT *pCEServing,
	   long tyme)
{
    CONSCLIENT *pCL;

    for (pCL = pCEServing->pCLon; (CONSCLIENT *)0 != pCL;
	 pCL = pCL->pCLnext) {
	FilePrint(pCLServing->fd, FLAGFALSE,
		  " %-32.32s %c %-7.7s %6s %s\r\n", pCL->acid->string,
		  pCL == pCLServing ? '*' : ' ',
		  pCL->fcon ? (pCL->fwr ? "attach" : "spy") : "stopped",
		  IdleTyme(tyme - pCL->typetym), pCL->actym);
    }
}

char *
TelOpt(int o)
{
    static char opt[128];
    char *telopts[] = {
	"BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD", "NAME",
	"STATUS", "TIMING MARK", "RCTE", "NAOL", "NAOP",
	"NAOCRD", "NAOHTS", "NAOHTD", "NAOFFD", "NAOVTS",
	"NAOVTD", "NAOLFD", "EXTEND ASCII", "LOGOUT", "BYTE MACRO",
	"DATA ENTRY TERMINAL", "SUPDUP", "SUPDUP OUTPUT",
	"SEND LOCATION", "TERMINAL TYPE", "END OF RECORD",
	"TACACS UID", "OUTPUT MARKING", "TTYLOC",
	"3270 REGIME", "X.3 PAD", "NAWS", "TSPEED", "LFLOW",
	"LINEMODE", "XDISPLOC", "OLD-ENVIRON", "AUTHENTICATION",
	"ENCRYPT", "NEW-ENVIRON"
    };

    if (o < sizeof(telopts) / sizeof(char *))
	return telopts[o];
    else {
	sprintf(opt, "%d", o);
	return opt;
    }
}

void
DoConsoleRead(CONSENT *pCEServing)
{
    unsigned char acIn[BUFSIZ], acInOrig[BUFSIZ];
    int nr, i;
    CONSCLIENT *pCL;

    int cofile = FileFDNum(pCEServing->cofile);

    if (!pCEServing->fup) {
	FD_CLR(cofile, &rinit);
	FD_CLR(cofile, &winit);
	return;
    }

    /* read terminal line */
    if ((nr =
	 FileRead(pCEServing->cofile, acInOrig, sizeof(acInOrig))) < 0) {
	Error("[%s] read failure: unexpected EOF", pCEServing->server);
	ConsoleError(pCEServing);
	return;
    }
    CONDDEBUG((1, "DoConsoleRead(): read %d bytes from fd %d", nr,
	       cofile));

    if (nr > 0) {
	pCEServing->lastWrite = time((time_t *)0);
	if (pCEServing->idletimeout != (time_t)0 &&
	    (timers[T_CIDLE] == (time_t)0 ||
	     timers[T_CIDLE] >
	     pCEServing->lastWrite + pCEServing->idletimeout))
	    timers[T_CIDLE] =
		pCEServing->lastWrite + pCEServing->idletimeout;
    }

    if (pCEServing->type == HOST && pCEServing->raw != FLAGTRUE) {
	/* Do a little Telnet Protocol interpretation
	 * state = 0: normal
	 *       = 1: Saw a IAC char
	 *       = 2: Saw a DONT/WONT command
	 *       = 3: Saw a WILL command
	 *       = 4: Saw a DO command
	 *       = 5: Saw a \r
	 */
	int new = 0, state;
	state = pCEServing->telnetState;
	for (i = 0; i < nr; ++i) {
	    if (state == 0 && acInOrig[i] == IAC) {
		CONDDEBUG((1, "DoConsoleRead(): [%s] got telnet `IAC'",
			   pCEServing->server));
		state = 1;
	    } else if (state == 1 && acInOrig[i] != IAC) {
		if (acInOrig[i] == WILL) {
		    state = 3;
		    CONDDEBUG((1,
			       "DoConsoleRead(): [%s] got telnet cmd `WILL'",
			       pCEServing->server));
		} else if (acInOrig[i] == DO) {
		    state = 4;
		    CONDDEBUG((1,
			       "DoConsoleRead(): [%s] got telnet cmd `DO'",
			       pCEServing->server));
		} else if (acInOrig[i] == DONT) {
		    state = 2;
		    CONDDEBUG((1,
			       "DoConsoleRead(): [%s] got telnet cmd `DONT'",
			       pCEServing->server));
		} else if (acInOrig[i] == WONT) {
		    state = 2;
		    CONDDEBUG((1,
			       "DoConsoleRead(): [%s] got telnet cmd `WONT'",
			       pCEServing->server));
		} else {
		    CONDDEBUG((1,
			       "DoConsoleRead(): [%s] got telnet cmd `%u'",
			       pCEServing->server, acInOrig[i]));
		    state = 0;
		}
	    } else if (state == 2) {
		CONDDEBUG((1,
			   "DoConsoleRead(): [%s] got telnet option `%s'",
			   pCEServing->server, TelOpt(acInOrig[i])));
		state = 0;
	    } else if (state == 3) {
		CONDDEBUG((1,
			   "DoConsoleRead(): [%s] got telnet option `%s'",
			   pCEServing->server, TelOpt(acInOrig[i])));
		if ((acInOrig[i] == TELOPT_ECHO &&
		     pCEServing->sentDoEcho != FLAGTRUE) ||
		    (acInOrig[i] == TELOPT_SGA &&
		     pCEServing->sentDoSGA != FLAGTRUE)) {
		    PutConsole(pCEServing, IAC, 2);
		    PutConsole(pCEServing, DO, 2);
		    PutConsole(pCEServing, acInOrig[i], 2);
		    CONDDEBUG((1,
			       "DoConsoleRead(): [%s] sent telnet DO `%s'",
			       pCEServing->server, TelOpt(acInOrig[i])));
		    if (acInOrig[i] == TELOPT_ECHO) {
			pCEServing->sentDoEcho = FLAGTRUE;
		    } else {
			pCEServing->sentDoSGA = FLAGTRUE;
		    }
		}
		state = 0;
	    } else if (state == 4) {
		CONDDEBUG((1,
			   "DoConsoleRead(): [%s] got telnet option `%s'",
			   pCEServing->server, TelOpt(acInOrig[i])));
		PutConsole(pCEServing, IAC, 2);
		PutConsole(pCEServing, WONT, 2);
		PutConsole(pCEServing, acInOrig[i], 2);
		CONDDEBUG((1,
			   "DoConsoleRead(): [%s] sent telnet WONT `%s'",
			   pCEServing->server, TelOpt(acInOrig[i])));
		state = 0;
	    } else {
		if (state == 5) {
		    state = 0;
		    if (acInOrig[i] == '\000')
			continue;
		}
		if (acInOrig[i] == IAC)
		    CONDDEBUG((1, "DoConsoleRead(): [%s] quoted `IAC'",
			       pCEServing->server));
		if (pCEServing->striphigh == FLAGTRUE)
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
	    if (pCEServing->striphigh == FLAGTRUE)
		acIn[i] = acInOrig[i] & 127;
	    else
		acIn[i] = acInOrig[i];
	}
    }
    if (nr == 0)
	return;

    /* log it and write to all connections on this server
     */
    if (!pCEServing->nolog) {
	WriteLog(pCEServing, (char *)acIn, nr);
    }

    /* if we have a command running, interface with it and then
     * allow the normal stuff to happen (so folks can watch)
     */
    if (pCEServing->initfile != (CONSFILE *)0)
	FileWrite(pCEServing->initfile, FLAGFALSE, (char *)acIn, nr);

    /* output all console info nobody is attached
     * or output to unifiedlog if it's open
     */
    if (unifiedlog != (CONSFILE *)0 ||
	(pCEServing->pCLwr == (CONSCLIENT *)0 &&
	 pCEServing->unloved == FLAGTRUE)) {
	/* run through the console ouptut,
	 * add each character to the output line
	 * drop and reset if we have too much
	 * or are at the end of a line (ksb)
	 */
	for (i = 0; i < nr; ++i) {
	    pCEServing->acline[pCEServing->iend++] = acIn[i];
	    if (pCEServing->iend < sizeof(pCEServing->acline) &&
		'\n' != acIn[i])
		continue;

	    /* unloved */
	    if (pCEServing->pCLwr == (CONSCLIENT *)0 &&
		pCEServing->unloved == FLAGTRUE) {
		write(1, pCEServing->server, strlen(pCEServing->server));
		write(1, ": ", 2);
		write(1, pCEServing->acline, pCEServing->iend);
	    }

	    /* unified */
	    if (unifiedlog != (CONSFILE *)0) {
		FileWrite(unifiedlog, FLAGTRUE, pCEServing->server, -1);
		if (pCEServing->pCLwr == (CONSCLIENT *)0)
		    FileWrite(unifiedlog, FLAGTRUE, ": ", 2);
		else
		    FileWrite(unifiedlog, FLAGTRUE, "*: ", 3);
		FileWrite(unifiedlog, FLAGFALSE, pCEServing->acline,
			  pCEServing->iend);
	    }

	    pCEServing->iend = 0;
	}
    }

    /* write console info to clients (not suspended)
     */
    for (pCL = pCEServing->pCLon; (CONSCLIENT *)0 != pCL;
	 pCL = pCL->pCLnext) {
	if (pCL->fcon || pCL->iState == S_CEXEC)
	    FileWrite(pCL->fd, FLAGFALSE, (char *)acIn, nr);
    }
}

void
DoTaskRead(CONSENT *pCEServing)
{
    unsigned char acInOrig[BUFSIZ];
    int nr, fd;
    CONSCLIENT *pCL;

    if (pCEServing->taskfile == (CONSFILE *)0)
	return;

    fd = FileFDNum(pCEServing->taskfile);

    /* read from task */
    if ((nr =
	 FileRead(pCEServing->taskfile, acInOrig, sizeof(acInOrig))) < 0) {
	CONDDEBUG((1, "DoTaskRead(): got %d bytes from fd %d", nr, fd));
	StopTask(pCEServing);
	return;
    }
    CONDDEBUG((1, "DoTaskRead(): read %d bytes from fd %d", nr, fd));

    /* write console info to clients (not suspended)
     */
    for (pCL = pCEServing->pCLon; (CONSCLIENT *)0 != pCL;
	 pCL = pCL->pCLnext) {
	if (pCL->fcon)
	    FileWrite(pCL->fd, FLAGFALSE, (char *)acInOrig, nr);
    }
}

void
DoCommandRead(CONSENT *pCEServing)
{
    unsigned char acInOrig[BUFSIZ];
    int nr, i, fd;

    if (pCEServing->initfile == (CONSFILE *)0)
	return;

    fd = FileFDNum(pCEServing->initfile);

    /* read from command */
    if ((nr =
	 FileRead(pCEServing->initfile, acInOrig, sizeof(acInOrig))) < 0) {
	StopInit(pCEServing);
	return;
    }
    CONDDEBUG((1, "DoCommandRead(): read %d bytes from fd %d", nr, fd));

    for (i = 0; i < nr; ++i) {
	if (pCEServing->striphigh == FLAGTRUE)
	    PutConsole(pCEServing, acInOrig[i] & 127, 1);
	else
	    PutConsole(pCEServing, acInOrig[i], 1);
    }
}

unsigned char CM[] = {
    0xdf, 0xd2, 0xd2, 0xdf, 0xab, 0x90, 0x90, 0x93, 0xdf, 0x96,
    0x8c, 0xdf, 0x9e, 0x91, 0xdf, 0xd5, 0x9e, 0x92, 0x9e, 0x85,
    0x96, 0x91, 0x98, 0xd5, 0xdf, 0x9d, 0x9e, 0x91, 0x9b, 0xd1,
    0xff, 0xdf, 0xd2, 0xd2, 0xdf, 0xb7, 0x9e, 0x89, 0x9a, 0xdf,
    0x86, 0x90, 0x8a, 0xdf, 0x8d, 0x9a, 0x9e, 0x9b, 0xdf, 0x8b,
    0x97, 0x9a, 0xdf, 0x92, 0x9e, 0x91, 0x8f, 0x9e, 0x98, 0x9a,
    0xc0, 0xff, 0xdf, 0xd2, 0xd2, 0xdf, 0xbe, 0x93, 0x88, 0x9e,
    0x86, 0x8c, 0xdf, 0x93, 0x9a, 0x8b, 0xdf, 0x8b, 0x97, 0x9a,
    0xdf, 0x88, 0x90, 0x90, 0x94, 0x96, 0x9a, 0xdf, 0x88, 0x96,
    0x91, 0xd1, 0xff, 0xdf, 0xd2, 0xd2, 0xdf, 0x89, 0x96, 0x92,
    0xdf, 0x96, 0x8c, 0xdf, 0xd5, 0x8b, 0x90, 0x90, 0xd5, 0xdf,
    0x9c, 0x90, 0x90, 0x93, 0xde, 0xff, 0xdf, 0xd2, 0xd2, 0xdf,
    0xb3, 0x9e, 0x8b, 0x9a, 0x8d, 0x9e, 0x93, 0x8a, 0x8c, 0xc5,
    0xdf, 0xc9, 0xd3, 0xc8, 0xd3, 0xca, 0xd3, 0xc7, 0xd3, 0xcb,
    0xd3, 0xc6, 0xd3, 0xce, 0xcc, 0xd3, 0xce, 0xd3, 0xce, 0xcd,
    0xd3, 0xcd, 0xd3, 0xce, 0xce, 0xd3, 0xcc, 0xd3, 0xce, 0xcf,
    0xff, 0xdf, 0xd2, 0xd2, 0xdf, 0xb2, 0x90, 0x8a, 0x91, 0x8b,
    0xdf, 0x9e, 0xdf, 0x91, 0x9a, 0x88, 0xdf, 0x8c, 0x9c, 0x8d,
    0x9e, 0x8b, 0x9c, 0x97, 0xdf, 0x92, 0x90, 0x91, 0x94, 0x9a,
    0x86, 0xdf, 0x9e, 0x91, 0x9b, 0xdf, 0x8b, 0x8d, 0x86, 0xdf,
    0x9e, 0x98, 0x9e, 0x96, 0x91, 0xd1, 0xff, 0xdf, 0xd2, 0xd2,
    0xdf, 0x96, 0x99, 0xdf, 0x86, 0x90, 0x8a, 0xdf, 0x9b, 0x9e,
    0x8d, 0x9a, 0xd1, 0xd1, 0xd1, 0xff, 0xff
};

unsigned char *
Challenge(void)
{
    int i;
    static unsigned char **n = (unsigned char **)0;
    static int cnt = 0;
    static int cur = 0;
    static int rnd = 0;

    if (n == (unsigned char **)0) {
	int j;
	for (i = 0; i < sizeof(CM); i++) {
	    if (CM[i] == 0xff)
		cnt++;
	}
	n = (unsigned char **)calloc(cnt, sizeof(unsigned char *));
	j = 0;
	for (i = 0; i < sizeof(CM); i++) {
	    if (n[j] == (unsigned char *)0)
		n[j] = &(CM[i]);
	    if (CM[i] == 0xff) {
		j++;
	    }
	    CM[i] = CM[i] ^ 0xff;
	}
	cnt--;
	cur = time(NULL) % cnt;
	rnd = time(NULL) % 2;
    }

    if (++rnd % 2 == 0) {
	rnd = 0;
	if (cur >= cnt)
	    cur = 0;
	return n[cur++];
    }
    return n[cnt];
}


/* This routine is used to gather input from the
 * client and save it in the accmd string.
 * GatherLine returns 0 until the user signals
 * they're "done" (a \r), then it returns 1.
 */
typedef enum gatherType {
    G_INT,
    G_TEXT
} GATHERTYPE;

int
GatherLine(char c, int limit, GATHERTYPE g, CONSCLIENT *pCL)
{
    if (c == '\r')
	return 1;

    if ((limit <= 0 || pCL->accmd->used - 1 < limit) &&
	((g == G_TEXT && (c == '\a' || (c >= ' ' && c <= '~'))) ||
	 (g == G_INT && isdigit((int)c)))) {
	BuildStringChar(c, pCL->accmd);
	FileWrite(pCL->fd, FLAGFALSE, (char *)&c, 1);
    } else if ((c == '\b' || c == 0x7f)
	       && pCL->accmd->used > 1) {
	if (pCL->accmd->string[pCL->accmd->used - 2] != '\a')
	    FileWrite(pCL->fd, FLAGFALSE, "\b \b", 3);
	pCL->accmd->string[pCL->accmd->used - 2] = '\000';
	pCL->accmd->used--;
    } else if ((c == 0x15) && pCL->accmd->used > 1) {
	while (pCL->accmd->used > 1) {
	    if (pCL->accmd->string[pCL->accmd->used - 2] != '\a')
		FileWrite(pCL->fd, FLAGFALSE, "\b \b", 3);
	    pCL->accmd->string[pCL->accmd->used - 2] = '\000';
	    pCL->accmd->used--;
	}
    }
    return 0;
}

void
DoClientRead(GRPENT *pGE, CONSCLIENT *pCLServing)
{
    CONSENT *pCEServing = pCLServing->pCEto;
    int nr, i, l;
    unsigned char acIn[BUFSIZ], acInOrig[BUFSIZ];
    time_t tyme;
    static STRING *bcast = (STRING *)0;
    static STRING *acA1 = (STRING *)0;
    static STRING *acA2 = (STRING *)0;

    if (bcast == (STRING *)0)
	bcast = AllocString();
    if (acA1 == (STRING *)0)
	acA1 = AllocString();
    if (acA2 == (STRING *)0)
	acA2 = AllocString();

    /* read connection */
    if ((nr = FileRead(pCLServing->fd, acIn, sizeof(acIn))) < 0) {
	DisconnectClient(pGE, pCLServing, (char *)0, FLAGFALSE);
	return;
    }

    if (nr == 0)
	return;

    /* update last keystroke time */
    pCLServing->typetym = tyme = time((time_t *)0);

    while ((l = ParseIACBuf(pCLServing->fd, acIn, &nr)) >= 0) {
	if (l == 0) {
	    if (FileSawQuoteExec(pCLServing->fd) == FLAGTRUE) {
		if (pCLServing->iState == S_CWAIT) {
		    pCLServing->iState = S_CEXEC;
		    if (pCEServing->pCLwr == pCLServing)
			FileWrite(pCLServing->fd, FLAGFALSE, "[rw]\r\n",
				  6);
		    else
			FileWrite(pCLServing->fd, FLAGFALSE, "[ro]\r\n",
				  6);
		}
	    }
	    if (FileSawQuoteAbrt(pCLServing->fd) == FLAGTRUE) {
		if (pCLServing->iState == S_CWAIT ||
		    pCLServing->iState == S_CEXEC) {
		    pCLServing->fcon = 1;
		    pCLServing->iState = S_NORMAL;
		}
	    }
	    /* not used (yet?)
	       if (FileSawQuoteSusp(pCLServing->fd) == FLAGTRUE) {
	       }
	     */
	    continue;
	}

	for (i = 0; i < l; ++i) {
	    acInOrig[i] = acIn[i];
	    if (pCEServing->striphigh == FLAGTRUE) {
		acIn[i] &= 127;
	    }
	}

	for (i = 0; i < l; ++i) {
	    if (pGE->pCEctl == pCEServing) {
		static char *pcArgs;
		static char *pcCmd;

		CONDDEBUG((1, "state = %d", pCLServing->iState));
		if ('\n' != acIn[i]) {
		    BuildStringChar(acIn[i], pCLServing->accmd);
		    continue;
		}
		if ((pCLServing->accmd->used > 1) &&
		    ('\r' ==
		     pCLServing->accmd->string[pCLServing->accmd->used -
					       2])) {
		    pCLServing->accmd->string[pCLServing->accmd->used -
					      2] = '\000';
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
			DisconnectClient(pGE, pCLServing, (char *)0,
					 FLAGFALSE);
			return;
		    }
		    Verbose("<group> login %s", pCLServing->acid->string);
		    FileWrite(pCLServing->fd, FLAGFALSE, "ok\r\n", -1);
		    pCLServing->iState = S_NORMAL;
		    BuildString((char *)0, pCLServing->accmd);
		    continue;
		}

		if ((pcArgs =
		     strchr(pCLServing->accmd->string,
			    ' ')) != (char *)0) {
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
			"broadcast    send broadcast message\r\n",
			"call         connect to given console\r\n",
			"disconnect*  disconnect the given user(s)\r\n",
			"examine      examine port and baud rates\r\n",
			"exit         disconnect\r\n",
			"group        show users in this group\r\n",
			"help         this help message\r\n",
			"hosts        show host status and user\r\n",
			"info         show console information\r\n",
			"textmsg      send a text message\r\n",
			"* = requires admin privileges\r\n",
			(char *)0
		    };
		    char **ppc;
		    for (ppc =
			 (pCLServing->iState ==
			  S_IDENT ? apcHelp1 : apcHelp2);
			 (char *)0 != *ppc; ++ppc) {
			FileWrite(pCLServing->fd, FLAGTRUE, *ppc, -1);
		    }
		    FileWrite(pCLServing->fd, FLAGFALSE, (char *)0, 0);
		} else if (strcmp(pcCmd, "exit") == 0) {
		    FileWrite(pCLServing->fd, FLAGFALSE, "goodbye\r\n",
			      -1);
		    DisconnectClient(pGE, pCLServing, (char *)0,
				     FLAGFALSE);
		    return;
#if HAVE_OPENSSL
		} else if (pCLServing->iState == S_IDENT &&
			   strcmp(pcCmd, "ssl") == 0) {
		    FileWrite(pCLServing->fd, FLAGFALSE, "ok\r\n", -1);
		    if (!AttemptSSL(pCLServing)) {
			DisconnectClient(pGE, pCLServing, (char *)0,
					 FLAGFALSE);
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
				Verbose("<group> login %s",
					pCLServing->acid->string);
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "ok\r\n", -1);
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
			   strcmp(pcCmd, "call") == 0) {
		    if (pcArgs == (char *)0)
			FileWrite(pCLServing->fd, FLAGFALSE,
				  "call requires argument\r\n", -1);
		    else {
			CONSENT *pCEwant = (CONSENT *)0;

			pCEwant = HuntForConsole(pGE, pcArgs);

			if (pCEwant == (CONSENT *)0) {
			    FilePrint(pCLServing->fd, FLAGFALSE,
				      "%s: no such console\r\n", pcArgs);
			    DisconnectClient(pGE, pCLServing, (char *)0,
					     FLAGFALSE);
			    return;
			}

			pCLServing->fro =
			    ClientAccess(pCEwant,
					 pCLServing->username->string);
			if (pCLServing->fro == -1) {
			    FilePrint(pCLServing->fd, FLAGFALSE,
				      "%s: permission denied\r\n", pcArgs);
			    DisconnectClient(pGE, pCLServing, (char *)0,
					     FLAGFALSE);
			    return;
			}

			if (pCEwant->login != FLAGTRUE) {
			    if (pCEwant->motd == (char *)0) {
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "%s: no logins allowed at this time\r\n",
					  pcArgs);
			    } else {
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "%s: %s\r\n", pcArgs,
					  pCEwant->motd);
			    }
			    DisconnectClient(pGE, pCLServing, (char *)0,
					     FLAGFALSE);
			    return;
			}

			/* remove from current host */
			if ((CONSCLIENT *)0 != pCLServing->pCLnext) {
			    pCLServing->pCLnext->ppCLbnext =
				pCLServing->ppCLbnext;
			}
			*(pCLServing->ppCLbnext) = pCLServing->pCLnext;
			if (pCLServing->fwr) {
			    pCLServing->fwr = 0;
			    pCLServing->fwantwr = 0;
			    TagLogfileAct(pCEServing, "%s detached",
					  pCLServing->acid->string);
			    pCEServing->pCLwr = (CONSCLIENT *)0;
			    FindWrite(pCEServing);
			}

			/* inform operators of the change
			 */
			Verbose("<group> attach %s to %s",
				pCLServing->acid->string, pCEwant->server);
			Msg("[%s] login %s", pCEwant->server,
			    pCLServing->acid->string);

			/* set new host and link into new host list
			 */
			pCEServing = pCEwant;
			pCLServing->pCEto = pCEServing;
			pCLServing->pCLnext = pCEServing->pCLon;
			pCLServing->ppCLbnext = &pCEServing->pCLon;
			if ((CONSCLIENT *)0 != pCLServing->pCLnext) {
			    pCLServing->pCLnext->ppCLbnext =
				&pCLServing->pCLnext;
			}
			pCEServing->pCLon = pCLServing;

			/* try to reopen line if specified at server startup
			 */
			if ((pCEServing->ondemand == FLAGTRUE ||
			     pCEServing->reinitoncc == FLAGTRUE) &&
			    !pCEServing->fup)
			    ConsInit(pCEServing);

			/* try for attach on new console
			 */
			if (pCEServing->fronly) {
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      "[console is read-only]\r\n", -1);
			} else if (((CONSCLIENT *)0 == pCEServing->pCLwr)
				   && !pCLServing->fro) {
			    pCEServing->pCLwr = pCLServing;
			    pCLServing->fwr = 1;
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      "[attached]\r\n", -1);
			    /* this keeps the ops console neat */
			    pCEServing->iend = 0;
			    TagLogfileAct(pCEServing, "%s attached",
					  pCLServing->acid->string);
			} else {
			    ClientWantsWrite(pCLServing);
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      "[spy]\r\n", -1);
			}
			pCLServing->fcon = 0;
			pCLServing->iState = S_NORMAL;
		    }
		} else if (pCLServing->iState == S_NORMAL &&
			   strcmp(pcCmd, "info") == 0) {
		    CommandInfo(pGE, pCLServing, pCEServing, tyme, pcArgs);
		} else if (pCLServing->iState == S_NORMAL &&
			   strcmp(pcCmd, "examine") == 0) {
		    CommandExamine(pGE, pCLServing, pCEServing, tyme,
				   pcArgs);
		} else if (pCLServing->iState == S_NORMAL &&
			   strcmp(pcCmd, "group") == 0) {
		    CommandGroup(pGE, pCLServing, pCEServing, tyme,
				 pcArgs);
		} else if (pCLServing->iState == S_NORMAL &&
			   strcmp(pcCmd, "hosts") == 0) {
		    CommandHosts(pGE, pCLServing, pCEServing, tyme,
				 pcArgs);
		} else if (pCLServing->iState == S_NORMAL &&
			   strcmp(pcCmd, "broadcast") == 0) {
		    if (pcArgs == (char *)0) {
			FileWrite(pCLServing->fd, FLAGFALSE,
				  "broadcast requires argument\r\n", -1);
		    } else {
			BuildString((char *)0, bcast);
			BuildStringChar('[', bcast);
			BuildString(pCLServing->acid->string, bcast);
			BuildString(": ", bcast);
			BuildString(pcArgs, bcast);
			BuildString("]\r\n", bcast);
			SendAllClientsMsg(pGE, bcast->string);
			FileWrite(pCLServing->fd, FLAGFALSE, "ok\r\n", -1);
		    }
		} else if (pCLServing->iState == S_NORMAL &&
			   strcmp(pcCmd, "textmsg") == 0) {
		    char *pcMsg;
		    if (pcArgs == (char *)0) {
			FileWrite(pCLServing->fd, FLAGFALSE,
				  "textmsg requires two arguments\r\n",
				  -1);
		    } else {
			if ((pcMsg = strchr(pcArgs, ' ')) != (char *)0) {
			    *pcMsg++ = '\000';
			}
			if (pcMsg == (char *)0) {
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      "textmsg requires two arguments\r\n",
				      -1);
			} else {
			    pcMsg = PruneSpace(pcMsg);

			    BuildString((char *)0, bcast);
			    BuildStringChar('[', bcast);
			    BuildString(pCLServing->acid->string, bcast);
			    BuildString(": ", bcast);
			    BuildString(pcMsg, bcast);
			    BuildString("]\r\n", bcast);

			    SendCertainClientsMsg(pGE, pcArgs,
						  bcast->string);
			    FileWrite(pCLServing->fd, FLAGFALSE, "ok\r\n",
				      -1);
			}
		    }
		} else if (pCLServing->iState == S_NORMAL &&
			   strcmp(pcCmd, "disconnect") == 0) {
		    if (pcArgs == (char *)0) {
			FileWrite(pCLServing->fd, FLAGFALSE,
				  "disconnect requires argument\r\n", -1);
		    } else {
			if (ConsentUserOk
			    (pADList, pCLServing->username->string) == 1) {
			    int num;
			    Verbose("disconnect command (of `%s') by %s",
				    pcArgs, pCLServing->acid->string);
			    num =
				DisconnectCertainClients(pGE,
							 pCLServing->
							 acid->string,
							 pcArgs);
			    /* client expects this string to be formatted
			     * in this way only.
			     */
			    FilePrint(pCLServing->fd, FLAGFALSE,
				      "ok -- disconnected %d users\r\n",
				      num);
			} else
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      "unauthorized command\r\n", -1);
		    }
		} else {
		    FileWrite(pCLServing->fd, FLAGFALSE,
			      "unknown command\r\n", -1);
		    CONDDEBUG((1, "command %s state %d", pcCmd,
			       pCLServing->iState));
		}
		BuildString((char *)0, pCLServing->accmd);
	    } else
	      statestart:
		switch (pCLServing->iState) {
		    case S_IDENT:
		    case S_PASSWD:
			/* these are not used in this mode */
			break;

		    case S_NOTE:
			if (GatherLine(acIn[i], 0, G_TEXT, pCLServing)) {
			    FileWrite(pCLServing->fd, FLAGFALSE, "]\r\n",
				      3);
			    BuildString((char *)0, bcast);
			    BuildString("NOTE -- ", bcast);
			    BuildString(pCLServing->acid->string, bcast);
			    BuildString(": ", bcast);
			    BuildString(pCLServing->accmd->string, bcast);
			    TagLogfile(pCEServing, bcast->string);
			    BuildString((char *)0, pCLServing->accmd);
			    pCLServing->iState = S_NORMAL;
			}
			continue;

		    case S_BCAST:
			if (GatherLine(acIn[i], 0, G_TEXT, pCLServing)) {
			    FileWrite(pCLServing->fd, FLAGFALSE, "]\r\n",
				      3);
			    BuildString((char *)0, bcast);
			    BuildStringChar('[', bcast);
			    BuildString(pCLServing->acid->string, bcast);
			    BuildString(": ", bcast);
			    BuildString(pCLServing->accmd->string, bcast);
			    BuildString("]\r\n", bcast);
			    SendClientsMsg(pCEServing, bcast->string);

			    BuildString((char *)0, pCLServing->accmd);
			    pCLServing->iState = S_NORMAL;
			}
			continue;

		    case S_REPLAY:
		    case S_PLAYBACK:
			if (GatherLine(acIn[i], 4, G_INT, pCLServing)) {
			    unsigned short *s;

			    if (pCLServing->iState == S_REPLAY)
				s = &(pCLServing->replay);
			    else
				s = &(pCLServing->playback);

			    if (pCLServing->accmd->used > 1) {
				unsigned short u;
				u = (unsigned short)
				    atoi(pCLServing->accmd->string);
				/* i'm limiting the value here to 10000 for a couple
				 * of reasons:
				 *
				 * 1. this process could be busy parsing a file for 
				 *    a long time if the logfile and replay are big.
				 * 2. who needs more than 10000 lines of replay?  if
				 *    you need that much, go find the raw logfile.
				 *    and if you don't have access, find someone who
				 *    does.
				 *
				 * change this to something bigger if you want, but
				 * it would scare me...even 10000 seems a bit large,
				 * but no one *has* to set the value so large.
				 * and watch out...it's an unsigned short, so you
				 * can't go really huge.
				 */
				if (u > 10000)
				    FileWrite(pCLServing->fd, FLAGFALSE,
					      " <value too large>", 18);
				else
				    *s = u;
			    } else
				FilePrint(pCLServing->fd, FLAGFALSE, "%u",
					  *s);

			    FileWrite(pCLServing->fd, FLAGFALSE, "]\r\n",
				      3);
			    pCLServing->iState = S_NORMAL;
			}
			continue;

		    case S_QUOTE:	/* send octal code              */
			/* must type in 3 octal digits */
			if (acIn[i] >= '0' && acIn[i] <= '7') {
			    BuildStringChar(acIn[i], pCLServing->accmd);
			    if (pCLServing->accmd->used < 4) {
				FileWrite(pCLServing->fd, FLAGFALSE,
					  (char *)&acIn[i], 1);
				continue;
			    }
			    FileWrite(pCLServing->fd, FLAGTRUE,
				      (char *)&acIn[i], 1);
			    FileWrite(pCLServing->fd, FLAGFALSE, "]", 1);

			    pCLServing->accmd->string[0] =
				(((pCLServing->accmd->string[0] -
				   '0') * 8 +
				  (pCLServing->accmd->string[1] -
				   '0')) * 8) +
				(pCLServing->accmd->string[2] - '0');
			    PutConsole(pCEServing,
				       pCLServing->accmd->string[0], 1);
			    BuildString((char *)0, pCLServing->accmd);
			} else {
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      " aborted]\r\n", -1);
			}
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_SUSP:
			if (!pCEServing->fup) {
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      " -- line down]\r\n", -1);
			} else if (pCEServing->fronly) {
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      " -- read-only]\r\n", -1);
			} else if (((CONSCLIENT *)0 == pCEServing->pCLwr)
				   && !pCLServing->fro) {
			    pCEServing->pCLwr = pCLServing;
			    pCLServing->fwr = 1;
			    if (pCEServing->nolog) {
				FileWrite(pCLServing->fd, FLAGFALSE,
					  " -- attached (nologging)]\r\n",
					  -1);
			    } else {
				FileWrite(pCLServing->fd, FLAGFALSE,
					  " -- attached]\r\n", -1);
			    }
			    TagLogfileAct(pCEServing, "%s attached",
					  pCLServing->acid->string);
			} else {
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      " -- spy mode]\r\n", -1);
			}
			pCLServing->fcon = 1;
			pCLServing->iState = S_NORMAL;
			continue;

		    case S_CWAIT:
			continue;

		    case S_NORMAL:
			/* if it is an escape sequence shift states
			 */
			if (acInOrig[i] == pCLServing->ic[0]) {
			    pCLServing->iState = S_ESC1;
			    continue;
			}
			/* fall through */
		    case S_CEXEC:
			/* if we can write, write to slave tty
			 */
			if (pCEServing->fup &&
			    pCEServing->initfile == (CONSFILE *)0 &&
			    pCEServing->ioState == ISNORMAL &&
			    pCLServing->fwr && !pCLServing->fiwait) {
			    PutConsole(pCEServing, acIn[i], 1);
			    continue;
			}
			/* if the client is stuck in spy mode
			 * give them a clue as to how to get out
			 * (LLL nice to put chars out as ^Ec, rather
			 * than octal escapes, but....)
			 */
			if (!pCLServing->fiwait &&
			    ('\r' == acIn[i] || '\n' == acIn[i])) {
			    char *m = "";
			    if (pCLServing->fwr)
				m = ConsState(pCEServing);
			    else
				m = "read-only";
			    FilePrint(pCLServing->fd, FLAGFALSE,
				      "[%s -- use %s %s ? for help]\r\n",
				      m, FmtCtl(pCLServing->ic[0], acA1),
				      FmtCtl(pCLServing->ic[1], acA2));
			}
			continue;

		    case S_HALT1:	/* halt sequence? */
			pCLServing->iState = S_NORMAL;
			if (acIn[i] != '?' &&
			    ((acIn[i] < '0' || acIn[i] > '9') &&
			     (acIn[i] < 'a' || acIn[i] > 'z'))) {
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      "aborted]\r\n", -1);
			    continue;
			}

			if (acIn[i] == '?') {
			    int i;
			    int mod;
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      "list]\r\n", -1);
			    i = pCEServing->breakNum;
			    mod = i > 9 ? BREAKALPHAOFFSET : 0;
			    if (i == 0 || breakList[i - 1].seq->used <= 1
				|| pCEServing->breaklist == (char *)0 ||
				((char *)0 ==
				 strchr(pCEServing->breaklist,
					'0' + i + mod)
				 && (char *)0 ==
				 strchr(pCEServing->breaklist, '*')))
				FileWrite(pCLServing->fd, FLAGTRUE,
					  " 0 -   0ms, <undefined>\r\n",
					  -1);
			    else {
				FmtCtlStr(breakList[i - 1].seq->string,
					  breakList[i - 1].seq->used - 1,
					  acA1);
				FilePrint(pCLServing->fd, FLAGTRUE,
					  " 0 - %3dms, `%s'\r\n",
					  breakList[i - 1].delay,
					  acA1->string);
			    }
			    if (pCEServing->breaklist != (char *)0) {
				for (i = 0; i < BREAKLISTSIZE; i++) {
				    char btc;
				    mod = i > 8 ? BREAKALPHAOFFSET : 0;
				    btc = '1' + i + mod;
				    if ((char *)0 ==
					strchr(pCEServing->breaklist, btc)
					&& (char *)0 ==
					strchr(pCEServing->breaklist, '*'))
					continue;
				    if (breakList[i].seq->used > 1) {
					FmtCtlStr(breakList[i].seq->string,
						  breakList[i].seq->used -
						  1, acA1);
					FilePrint(pCLServing->fd, FLAGTRUE,
						  " %c - %3dms, `%s'\r\n",
						  btc, breakList[i].delay,
						  acA1->string);
				    }
				}
			    }
			    FileWrite(pCLServing->fd, FLAGFALSE, (char *)0,
				      0);
			} else {
			    if (pCLServing->fwr) {
				int bt =
				    acIn[i] - '0' - (acIn[i] >
						     '9' ? BREAKALPHAOFFSET
						     : 0);
				SendBreak(pCLServing, pCEServing, bt);
			    } else
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "attach to send break]\r\n", -1);
			}
			continue;

		    case S_TASK:	/* task invocation */
			pCLServing->iState = S_NORMAL;
			if (pCEServing->taskpid != 0 && acIn[i] == '.') {
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      "terminate]\r\n", -1);
			    StopTask(pCEServing);
			    continue;
			}
			if (acIn[i] != '?' &&
			    ((acIn[i] < '0' || acIn[i] > '9') &&
			     (acIn[i] < 'a' || acIn[i] > 'z'))) {
			    FileWrite(pCLServing->fd, FLAGFALSE,
				      "aborted]\r\n", -1);
			    continue;
			}

			if (acIn[i] == '?') {
			    TASKS *t;
			    int saw = 0;
			    if (pCEServing->taskpid != 0) {
				STRING *acA1 = AllocString();
				STRING *acA2 = AllocString();
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "running - pid %lu - use `%s%s!.' to terminate]\r\n",
					  (unsigned long)pGE->pid,
					  FmtCtl(pCLServing->ic[0], acA1),
					  FmtCtl(pCLServing->ic[1], acA2));
				DestroyString(acA1);
				DestroyString(acA2);
				return;
			    } else {
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "list]\r\n", -1);
				if (pCEServing->tasklist != (char *)0) {
				    for (t = taskList; t != (TASKS *)0;
					 t = t->next) {
					if ((char *)0 ==
					    strchr(pCEServing->tasklist,
						   t->id)
					    && (char *)0 ==
					    strchr(pCEServing->tasklist,
						   '*'))
					    continue;

					if (t->descr->used > 1) {
					    FilePrint(pCLServing->fd,
						      FLAGTRUE,
						      " %c - `%s'\r\n",
						      t->id,
						      t->descr->string);
					} else if (t->cmd->used > 1) {
					    FilePrint(pCLServing->fd,
						      FLAGTRUE,
						      " %c - `%s'\r\n",
						      t->id,
						      t->cmd->string);
					}
					saw++;
				    }
				}
				if (saw == 0)
				    FileWrite(pCLServing->fd, FLAGTRUE,
					      " <undefined>\r\n", -1);
				FileWrite(pCLServing->fd, FLAGFALSE,
					  (char *)0, 0);
			    }
			} else {
			    if (pCLServing->fwr) {
				InvokeTask(pCLServing, pCEServing,
					   acIn[i]);
			    } else
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "attach to invoke task]\r\n",
					  -1);
			}
			continue;

		    case S_CONFIRM:
			if (acIn[i] == 'y' || acIn[i] == 'Y') {
			    pCLServing->confirmed = FLAGTRUE;
			    FileWrite(pCLServing->fd, FLAGFALSE, "y ", -1);
			} else {
			    FileWrite(pCLServing->fd, FLAGFALSE, "n ", -1);
			}
			pCLServing->iState = pCLServing->cState;
			acIn[i] = pCLServing->cOption;
			goto statestart;

		    case S_CATTN:	/* redef escape sequence? */
			pCLServing->ic[0] = acInOrig[i];
			FmtCtl(acInOrig[i], acA1);
			FilePrint(pCLServing->fd, FLAGFALSE, "%s ",
				  acA1->string);
			pCLServing->iState = S_CESC;
			continue;

		    case S_CESC:	/* escape sequent 2 */
			pCLServing->ic[1] = acInOrig[i];
			pCLServing->iState = S_NORMAL;
			FmtCtl(acInOrig[i], acA1);
			FilePrint(pCLServing->fd, FLAGFALSE, "%s  ok]\r\n",
				  acA1->string);
			continue;

		    case S_ESC1:	/* first char in escape sequence */
			if (acInOrig[i] == pCLServing->ic[1]) {
			    if (pCLServing->fecho)
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "\r\n[", 3);
			    else
				FileWrite(pCLServing->fd, FLAGFALSE, "[",
					  1);
			    pCLServing->iState = S_CMD;
			    continue;
			}
			/* ^E^Ec or ^_^_^[
			 * pass (possibly stripped) first ^E (^_) and
			 * stay in same state
			 */
			if (acInOrig[i] == pCLServing->ic[0]) {
			    if (pCLServing->fwr) {
				PutConsole(pCEServing, acIn[i], 1);
			    }
			    continue;
			}
			/* ^Ex or ^_x
			 * pass both characters to slave tty (possibly stripped)
			 */
			pCLServing->iState = S_NORMAL;
			if (pCLServing->fwr) {
			    char c = pCLServing->ic[0];
			    if (pCEServing->striphigh == FLAGTRUE)
				c = c & 127;
			    PutConsole(pCEServing, c, 1);
			    PutConsole(pCEServing, acIn[i], 1);
			}
			continue;

		    case S_CMD:	/* have 1/2 of the escape sequence */
			pCLServing->iState = S_NORMAL;
			switch (acIn[i]) {
			    case '=':
				if (!pCLServing->fcon) {
				    char *m = ConsState(pCEServing);
				    if (strcmp(m, "up") == 0)
					FileWrite(pCLServing->fd,
						  FLAGFALSE, "up]\r\n",
						  -1);
				    else
					FilePrint(pCLServing->fd,
						  FLAGFALSE,
						  "`%s' -- console is %s]\r\n",
						  pCEServing->server, m);
				} else
				    goto unknownchar;
				break;
			    case ';':
				if (pCLServing->fcon) {
				    if (ConsentUserOk
					(pLUList,
					 pCLServing->username->string) ==
					1)
					goto unknownchar;
				    FileSetQuoteIAC(pCLServing->fd,
						    FLAGFALSE);
				    FilePrint(pCLServing->fd, FLAGFALSE,
					      "%c%c", OB_IAC, OB_GOTO);
				    FileSetQuoteIAC(pCLServing->fd,
						    FLAGTRUE);
				    goto bottomSuspend;
				} else {
				    FileWrite(pCLServing->fd, FLAGFALSE,
					      "connected]\r\n", -1);
				    pCLServing->fcon = 1;
				}
				break;

			    case 'a':	/* attach */
				CommandAttach(pGE, pCLServing, pCEServing,
					      tyme);
				break;

			    case 'b':	/* broadcast message */
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "Enter message: ", -1);
				BuildString((char *)0, pCLServing->accmd);
				pCLServing->iState = S_BCAST;
				break;

			    case 'c':
				if (!pCLServing->fwr) {
				    goto unknownchar;
				}
				CommandChangeFlow(pGE, pCLServing,
						  pCEServing, tyme);
				break;

			    case 'd':	/* down a console       */
				if (!pCLServing->fwr) {
				    goto unknownchar;
				}
				CommandDown(pGE, pCLServing, pCEServing,
					    tyme);
				break;

			    case 'e':	/* redefine escape keys */
				pCLServing->iState = S_CATTN;
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "redef: ", -1);
				break;

			    case 'f':	/* force attach */
				CommandForce(pGE, pCLServing, pCEServing,
					     tyme);
				break;

			    case 'g':	/* group info */
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "group %s]\r\n",
					  pGE->pCEctl->server);
				CommandGroup(pGE, pCLServing, pCEServing,
					     tyme, (char *)0);
				break;

			    case 'h':	/* help                 */
			    case '?':
				HelpUser(pCLServing);
				break;

			    case 'i':
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "info]\r\n", -1);
				CommandInfo(pGE, pCLServing, pCEServing,
					    tyme, (char *)0);
				break;

			    case 'L':
				if (!pCLServing->fwr) {
				    goto unknownchar;
				}
				CommandLogging(pGE, pCLServing, pCEServing,
					       tyme);
				break;

			    case 'l':	/* halt character 1     */
				if (!pCLServing->fwr) {
				    goto unknownchar;
				}
				if (pCEServing->fronly) {
				    FileWrite(pCLServing->fd, FLAGFALSE,
					      "can't halt read-only console]\r\n",
					      -1);
				    continue;
				}
				pCLServing->iState = S_HALT1;
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "halt ", -1);
				break;

			    case 'm':	/* message of the day */
				if (pCEServing->motd == (char *)0)
				    FileWrite(pCLServing->fd, FLAGFALSE,
					      "-- MOTD --]\r\n", -1);
				else
				    FilePrint(pCLServing->fd, FLAGFALSE,
					      "-- MOTD -- %s]\r\n",
					      pCEServing->motd);
				break;

			    case 'n':	/* note message to log file */
				if (pCEServing->fdlog == (CONSFILE *)0) {
				    FileWrite(pCLServing->fd, FLAGFALSE,
					      "no log file on this console]\r\n",
					      -1);
				} else {
				    FileWrite(pCLServing->fd, FLAGFALSE,
					      "Enter note: ", -1);
				    BuildString((char *)0,
						pCLServing->accmd);
				    pCLServing->iState = S_NOTE;
				}
				break;

			    case 'o':	/* close and re-open line */
				CommandOpen(pGE, pCLServing, pCEServing,
					    tyme);
				break;

			    case 'P':	/* broadcast message */
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "set playback (%d): ",
					  pCLServing->playback);
				BuildString((char *)0, pCLServing->accmd);
				pCLServing->iState = S_PLAYBACK;
				break;

			    case 'p':	/* replay lines (longer, in theory) */
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "playback]\r\n", -1);
				Replay(pCEServing, pCLServing->fd,
				       pCLServing->playback);
				break;

			    case '\022':	/* ^R */
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "^R]\r\n", -1);
				Replay(pCEServing, pCLServing->fd, 1);
				break;

			    case 'R':	/* broadcast message */
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "set replay (%d): ",
					  pCLServing->replay);
				BuildString((char *)0, pCLServing->accmd);
				pCLServing->iState = S_REPLAY;
				break;

			    case 'r':	/* replay lines */
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "replay]\r\n", -1);
				Replay(pCEServing, pCLServing->fd,
				       pCLServing->replay);
				break;

			    case 's':	/* spy mode */
				if (!pCLServing->fwr) {
				    goto unknownchar;
				}
				pCLServing->fwantwr = 0;
				BumpClient(pCEServing, (char *)0);
				TagLogfileAct(pCEServing, "%s detached",
					      pCLServing->acid->string);
				FindWrite(pCEServing);
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "spying]\r\n", -1);
				break;

			    case 'u':	/* hosts on server this */
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "hosts]\r\n", -1);
				CommandHosts(pGE, pCLServing, pCEServing,
					     tyme, (char *)0);
				break;

			    case 'v':	/* version */
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "version `%s']\r\n",
					  MyVersion());
				break;

			    case 'w':	/* who */
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "who %s]\r\n",
					  pCEServing->server);
				CommandWho(pGE, pCLServing, pCEServing,
					   tyme);
				break;

			    case 'x':
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "examine]\r\n", -1);
				CommandExamine(pGE, pCLServing, pCEServing,
					       tyme, (char *)0);
				break;

			    case 'z':	/* suspend the client */
			    case '\032':
				if (ConsentUserOk
				    (pLUList,
				     pCLServing->username->string) == 1)
				    goto unknownchar;
				FileSetQuoteIAC(pCLServing->fd, FLAGFALSE);
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "%c%c", OB_IAC, OB_SUSP);
				FileSetQuoteIAC(pCLServing->fd, FLAGTRUE);
			      bottomSuspend:
				pCLServing->fcon = 0;
				pCLServing->iState = S_SUSP;
				if (pCEServing->pCLwr == pCLServing) {
				    BumpClient(pCEServing, (char *)0);
				    TagLogfileAct(pCEServing,
						  "%s detached",
						  pCLServing->
						  acid->string);
				    FindWrite(pCEServing);
				}
				break;

			    case '!':	/* invoke a task */
				if (!pCLServing->fwr) {
				    goto unknownchar;
				}
				pCLServing->iState = S_TASK;
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "task ", -1);
				break;

			    case '|':	/* wait for client */
				if (!pCLServing->fwr ||
				    ConsentUserOk(pLUList,
						  pCLServing->
						  username->string) == 1)
				    goto unknownchar;
				FileSetQuoteIAC(pCLServing->fd, FLAGFALSE);
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "%c%c", OB_IAC, OB_EXEC);
				FileSetQuoteIAC(pCLServing->fd, FLAGTRUE);
				pCLServing->fcon = 0;
				pCLServing->iState = S_CWAIT;
				break;

			    case '.':	/* disconnect */
			    case '\004':
			    case '\003':
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "disconnect]\r\n", -1);
				DisconnectClient(pGE, pCLServing,
						 (char *)0, FLAGFALSE);
				return;

			    case ' ':	/* abort escape sequence */
			    case '\n':
			    case '\r':
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "ignored]\r\n", -1);
				break;

			    case '\\':	/* quote mode (send ^Q,^S) */
				if (pCEServing->fronly) {
				    FileWrite(pCLServing->fd, FLAGFALSE,
					      "can't write to read-only console]\r\n",
					      -1);
				    continue;
				}
				if (!pCLServing->fwr) {
				    FileWrite(pCLServing->fd, FLAGFALSE,
					      "attach to send character]\r\n",
					      -1);
				    continue;
				}
				BuildString((char *)0, pCLServing->accmd);
				pCLServing->iState = S_QUOTE;
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "quote \\", -1);
				break;

			    case 0xD6:	/* 'v' with high bit set */
				/* this is really just used "behind the scenes",
				 * but of someone wants to type it, fine...we
				 * just need a way to query the server for what
				 * version it is so the client can determine
				 * functionality
				 */
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "%u]\r\n", VERSION_UINT);
				break;

			    default:	/* unknown sequence */
			      unknownchar:
#if USE_EXTENDED_MESSAGES
				FilePrint(pCLServing->fd, FLAGFALSE,
					  "unknown -- use `?'%s]\r\n",
					  Challenge());
#else
				FileWrite(pCLServing->fd, FLAGFALSE,
					  "unknown -- use `?']\r\n", -1);
#endif
				break;
			}
			continue;
		}
	}
	nr -= l;
	MemMove(acIn, acIn + l, nr);
    }
}

void
FlushConsole(CONSENT *pCEServing)
{
    static STRING *buf = (STRING *)0;
    int offset = 0;
    /* we buffered console data in PutConsole() so that we can
     * send more than 1-byte payloads, if we get more than 1-byte
     * of data from a client connection.  here we flush that buffer,
     * possibly putting it into the write buffer (but we don't really
     * need to worry about that here.
     */
    if (pCEServing->wbuf->used <= 1) {
	return;
    }
    if (!(pCEServing->fup && pCEServing->ioState == ISNORMAL)) {
	/* if we have data but aren't up, drop it */
	BuildString((char *)0, pCEServing->wbuf);
	pCEServing->wbufIAC = 0;
	return;
    }

    if (buf == (STRING *)0)
	buf = AllocString();
    BuildString((char *)0, buf);

    /* while wbuf
     *    if wbufIAC == 1, yikes
     *    else if wbufIAC == 0, buffer all data, move offset
     *    else if wbufIAC > 2, buffer data, wbufIAC = 2, move offset
     *    else if wbufIAC == 2, then
     *       if heavy
     *          write buffer
     *          if flushed, do heavy, else break
     *          break
     *       else if light
     *          buffer data
     *       search for new wbufIAC
     */
    {
	static STRING *s;
	if (s == (STRING *)0)
	    s = AllocString();
	BuildString((char *)0, s);
	FmtCtlStr(pCEServing->wbuf->string, pCEServing->wbuf->used, s);
	CONDDEBUG((1, "Kiddie(): wbuf=%s", s->string));
    }

    while (pCEServing->wbuf->used > 1 &&
	   offset < pCEServing->wbuf->used - 1) {
	CONDDEBUG((1, "Kiddie(): wbuf->used=%d, offset=%d, wbufIAC=%d",
		   pCEServing->wbuf->used, offset, pCEServing->wbufIAC));
	if (pCEServing->wbufIAC >= pCEServing->wbuf->used) {
	    /* this should never really happen...but in case it
	     * does, just reset wbufIAC and try again.
	     */
	    CONDDEBUG((1, "Kiddie(): invalid wbufIAC setting for [%s]",
		       pCEServing->server));
	} else if (pCEServing->wbufIAC == 1) {
	    Error("[%s] internal failure: wbufIAC==1", pCEServing->server);
	    offset = pCEServing->wbuf->used - 1;	/* bail */
	} else if (pCEServing->wbufIAC == 0) {
	    CONDDEBUG((1,
		       "Kiddie(): flushing final %d non-IAC bytes to [%s]",
		       pCEServing->wbuf->used - 1 - offset,
		       pCEServing->server));
	    BuildStringN(pCEServing->wbuf->string + offset,
			 pCEServing->wbuf->used - 1 - offset, buf);
	    offset = pCEServing->wbuf->used - 1;
	} else if (pCEServing->wbufIAC > 2) {
	    CONDDEBUG((1, "Kiddie(): flushing %d non-IAC bytes to [%s]",
		       pCEServing->wbufIAC - 2, pCEServing->server));
	    BuildStringN(pCEServing->wbuf->string + offset,
			 pCEServing->wbufIAC - 2, buf);
	    offset += pCEServing->wbufIAC - 2;
	    pCEServing->wbufIAC = 2;
	    continue;
	} else {		/* wbufIAC == 2 */
	    unsigned char next =
		(unsigned char)pCEServing->wbuf->string[offset + 1];
	    if ((next >= '0' && next <= '9') ||
		(next >= 'a' && next <= 'z')
		|| (next == BREAK && pCEServing->type != HOST)) {
		CONDDEBUG((1, "Kiddie(): heavy IAC for [%s]",
			   pCEServing->server));
		offset += 2;
		/* if we have buffered data, send it */
		if (buf->used > 1) {
		    CONDDEBUG((1,
			       "Kiddie(): heavy IAC flushing %d leading bytes for [%s]",
			       buf->used - 1, pCEServing->server));
		    if (FileWrite
			(pCEServing->cofile, FLAGFALSE, buf->string,
			 buf->used - 1) < 0) {
			Error("[%s] write failure", pCEServing->server);
			ConsoleError(pCEServing);
			BuildString((char *)0, buf);
			break;
		    }
		    BuildString((char *)0, buf);
		}
		/* if we didn't flush everything, bail and get
		 * it the next time around (hopefully it'll have
		 * cleared...or will soon.
		 */
		if (!FileBufEmpty(pCEServing->cofile)) {
		    CONDDEBUG((1,
			       "Kiddie(): heavy IAC (wait for flush) for [%s]",
			       pCEServing->server));
		    break;
		}

		/* Do the operation */
		if ((next >= '0' && next <= '9') ||
		    (next >= 'a' && next <= 'z')) {
		    int delay = BREAKDELAYDEFAULT;
		    int bnum =
			next - '1' - (next > '9' ? BREAKALPHAOFFSET : 0);
		    if (next != '0')
			delay = breakList[bnum].delay;
		    /* in theory this sets the break length to whatever
		     * the "default" break sequence is for the console.
		     * but, i think it would be better to just use the
		     * global default (250ms right now) so that you
		     * don't have to change things or get anything
		     * unexpected.  remember, this is really just for
		     * idle strings...
		     else {
		     if (pCEServing->breakNum != 0 &&
		     breakList[pCEServbing->breakNum -
		     1].seq->used <= 1)
		     delay =
		     breakList[pCEServbing->breakNum -
		     1].delay;
		     }
		     */
		    CONDDEBUG((1,
			       "Kiddie(): heavy IAC - doing Sleep() for [%s] (break #%c - delay %dms)",
			       pCEServing->server, next, delay));
		    if (delay != 0)
			Sleep(delay * 1000);
		} else if (next == BREAK) {
		    CONDDEBUG((1,
			       "Kiddie(): heavy IAC - sending break for [%s]",
			       pCEServing->server));
#if HAVE_FREEIPMI
		    if (pCEServing->type == IPMI) {
			if (ipmiconsole_ctx_generate_break
			    (pCEServing->ipmictx) == -1) {
			    if (pCEServing->pCLwr != (CONSCLIENT *)0)
				FilePrint(pCEServing->pCLwr->fd, FLAGFALSE,
					  "[ipmiconsole_ctx_generate_break() failed: %s]\r\n",
					  ipmiconsole_ctx_errormsg
					  (pCEServing->ipmictx));

			}
		    } else {
#endif

			if (tcsendbreak(FileFDNum(pCEServing->cofile), 0)
			    == -1) {
			    if (pCEServing->pCLwr != (CONSCLIENT *)0)
				FileWrite(pCEServing->pCLwr->fd, FLAGFALSE,
					  "[tcsendbreak() failed]\r\n",
					  -1);
			}
#if HAVE_FREEIPMI
		    }
#endif
		}
		/* we do this 'cause we just potentially paused for
		 * a half-second doing a break...or even the
		 * intentional Sleep().  we could take out the
		 * justHadDelay bits and continue with the stream,
		 * but this allows us to process other consoles and
		 * then come around and do more on this one.  you
		 * see, someone could have a '\d\z\d\z\d\z' sequence
		 * as a break string and we'd have about a 2 second
		 * delay added up if we process it all at once.
		 * we're just trying to be nice here.
		 */
		break;
	    } else {
		CONDDEBUG((1, "Kiddie(): soft IAC for fd [%s]",
			   pCEServing->server));
		offset += 2;
		if (next == IAC) {
		    CONDDEBUG((1,
			       "Kiddie(): soft IAC processing IAC for [%s]",
			       pCEServing->server));
		    BuildStringChar((char)IAC, buf);
		} else if (next == BREAK && pCEServing->type == HOST) {
		    CONDDEBUG((1,
			       "Kiddie(): soft IAC processing HOST BREAK for [%s]",
			       pCEServing->server));
		    BuildStringChar((char)IAC, buf);
		    BuildStringChar((char)BREAK, buf);
		} else {
		    CONDDEBUG((1,
			       "Kiddie(): soft IAC unprocessable IAC for [%s]",
			       pCEServing->server));
		}
	    }
	}

	/* hunt for a new IAC position */
	if (offset < pCEServing->wbuf->used - 1) {
	    char *iac = StringChar(pCEServing->wbuf, offset, (char)IAC);
	    CONDDEBUG((1, "Kiddie(): hunting for new IAC for [%s]",
		       pCEServing->server));
	    if (iac == (char *)0)
		pCEServing->wbufIAC = 0;
	    else
		pCEServing->wbufIAC =
		    (iac - pCEServing->wbuf->string - offset) + 2;
	} else
	    pCEServing->wbufIAC = 0;
    }

    if (buf->used > 1) {
	CONDDEBUG((1, "Kiddie(): flushing buffer of %d bytes for [%s]",
		   buf->used - 1, pCEServing->server));
	if (FileWrite
	    (pCEServing->cofile, FLAGFALSE, buf->string,
	     buf->used - 1) < 0) {
	    Error("[%s] write failure", pCEServing->server);
	    ConsoleError(pCEServing);
	    return;
	}
	BuildString((char *)0, buf);
    }

    /* nuke the data alread sent */
    if (offset >= pCEServing->wbuf->used - 1) {
	BuildString((char *)0, pCEServing->wbuf);
    } else if (offset > 0) {
	ShiftString(pCEServing->wbuf, offset);
    }

    if (pCEServing->wbuf->used > 1) {
	char *iac = StringChar(pCEServing->wbuf, 0, (char)IAC);
	CONDDEBUG((1, "Kiddie(): hunting for new IAC for [%s]",
		   pCEServing->server));
	if (iac == (char *)0)
	    pCEServing->wbufIAC = 0;
	else
	    pCEServing->wbufIAC = (iac - pCEServing->wbuf->string) + 2;
	CONDDEBUG((1,
		   "Kiddie(): watching writability for fd %d 'cause we have buffered data",
		   FileFDNum(pCEServing->cofile)));
	FD_SET(FileFDNum(pCEServing->cofile), &winit);
    } else {
	pCEServing->wbufIAC = 0;
	if (FileBufEmpty(pCEServing->cofile)) {
	    CONDDEBUG((1,
		       "Kiddie(): removing writability for fd %d 'cause we don't have buffered data",
		       FileFDNum(pCEServing->cofile)));
	    FD_CLR(FileFDNum(pCEServing->cofile), &winit);
	}
    }
    pCEServing->lastWrite = time((time_t *)0);
    if (pCEServing->idletimeout != (time_t)0 &&
	(timers[T_CIDLE] == (time_t)0 ||
	 timers[T_CIDLE] >
	 pCEServing->lastWrite + pCEServing->idletimeout))
	timers[T_CIDLE] = pCEServing->lastWrite + pCEServing->idletimeout;
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
Kiddie(GRPENT *pGE, int sfd)
{
    CONSCLIENT *pCL,		/* console we must scan/notify          */
     *pCLServing;		/* client we are serving                */
    CONSENT *pCEServing;	/* console we are talking to            */
    GRPENT *pGEtmp;
    REMOTE *pRCtmp;
    int ret;
    time_t tyme;
    time_t tymer;
    int fd;
    socklen_t so;
    fd_set rmask;
    fd_set wmask;
    struct timeval tv;
    struct timeval *tvp;


    /* nuke the other group lists - of no use in the child */
    while (pGroups != (GRPENT *)0) {
	pGEtmp = pGroups->pGEnext;
	if (pGroups != pGE)
	    DestroyGroup(pGroups);
	pGroups = pGEtmp;
    }
    pGroups = pGE;
    pGE->pGEnext = (GRPENT *)0;

    /* nuke the remote consoles - of no use in the child */
    while (pRCList != (REMOTE *)0) {
	pRCtmp = pRCList->pRCnext;
	DestroyRemoteConsole(pRCList);
	pRCList = pRCtmp;
    }

    if ((pGE->pCEctl = (CONSENT *)calloc(1, sizeof(CONSENT)))
	== (CONSENT *)0)
	OutOfMem();

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
#if defined(SIGXFSZ)
    SimpleSignal(SIGXFSZ, SIG_IGN);
#endif
    SimpleSignal(SIGTERM, FlagGoAway);
    SimpleSignal(SIGCHLD, FlagReapVirt);
    SimpleSignal(SIGINT, FlagGoAwayAlso);

    BuildTmpString((char *)0);
    if ((pGE->pCEctl->server =
	 StrDup(BuildTmpStringPrint("ctl_%hu", pGE->port)))
	== (char *)0)
	OutOfMem();

    /* set up stuff for the select() call once, then just copy it
     * rinit is all the fd's we might get data on, we copy it
     * to rmask before we call select, this saves lots of prep work
     * we used to do in the loop, but we have to mod rinit whenever
     * we add a connection or drop one...   (ksb)
     */
    /*maxfd = GetMaxFiles(); */
    FD_ZERO(&rinit);
    FD_ZERO(&winit);
    FD_SET(sfd, &rinit);
    if (maxfd < sfd + 1)
	maxfd = sfd + 1;
    /* open all the files we need for the consoles in our group
     * if we can't get one (bitch and) flag as down
     */
    ReUp(pGE, 0);

    /* prime the list of free connection slots
     */
    if ((pGE->pCLfree = (CONSCLIENT *)calloc(1, sizeof(CONSCLIENT)))
	== (CONSCLIENT *)0)
	OutOfMem();
    pGE->pCLfree->acid = AllocString();
    pGE->pCLfree->username = AllocString();
    pGE->pCLfree->peername = AllocString();
    pGE->pCLfree->accmd = AllocString();

    /* on a SIGHUP we should close and reopen our log files and
     * reread the config file
     */
    SimpleSignal(SIGHUP, FlagSawChldHUP);

    /* on a SIGUSR2 we should close and reopen our log files
     */
    SimpleSignal(SIGUSR2, FlagSawChldUSR2);

    /* on a SIGUSR1 we try to bring up all downed consoles */
    SimpleSignal(SIGUSR1, FlagReUp);

    /* prime the pump */
    RollLogs(pGE);
    Mark(pGE);

    /* the MAIN loop a group server
     */
    pGE->pCLall = (CONSCLIENT *)0;
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
	    ReopenUnifiedlog();
	    ReReadCfg(sfd, -1);
	    pGE = pGroups;
	    ReOpen(pGE);
	    ReUp(pGE, 0);
	}
	if (fSawChldUSR2) {
	    fSawChldUSR2 = 0;
	    ReopenLogfile();
	    ReopenUnifiedlog();
	    ReOpen(pGE);
	    ReUp(pGE, 0);
	}
	if (fSawReUp) {
	    fSawReUp = 0;
	    ReUp(pGE, 0);
	}

	/* check for timeouts with consoles */
	tymer = (time_t)0;
	tyme = time((time_t *)0);

	/* check for state timeouts (currently connect() timeouts) */
	if (timers[T_STATE] != (time_t)0 && tyme >= timers[T_STATE]) {
	    timers[T_STATE] = (time_t)0;
	    for (pCEServing = pGE->pCElist; pCEServing != (CONSENT *)0;
		 pCEServing = pCEServing->pCEnext) {
		if (pCEServing->stateTimer == (time_t)0)
		    continue;
		if (pCEServing->stateTimer > tyme) {
		    if (timers[T_STATE] == (time_t)0 ||
			timers[T_STATE] > pCEServing->stateTimer)
			timers[T_STATE] = pCEServing->stateTimer;
		    continue;
		}
		pCEServing->stateTimer = (time_t)0;
		if (pCEServing->ioState != INCONNECT)
		    continue;
		SendIWaitClientsMsg(pCEServing, "down]\r\n");
		Error("[%s] connect timeout: forcing down",
		      pCEServing->server);
		/* can't use ConsoleError() here otherwise we could reinit
		 * the console repeatedly (immediately).  we know there are
		 * no clients attached, so it's basically the same.
		 */
		ConsDown(pCEServing, FLAGTRUE, FLAGTRUE);
	    }
	}

	/* process any idle timeouts */
	if (timers[T_CIDLE] != (time_t)0 && tyme >= timers[T_CIDLE]) {
	    timers[T_CIDLE] = (time_t)0;
	    for (pCEServing = pGE->pCElist; pCEServing != (CONSENT *)0;
		 pCEServing = pCEServing->pCEnext) {
		/* if we aren't in a normal state, skip it */
		if (!(pCEServing->fup && pCEServing->ioState == ISNORMAL))
		    continue;
		/* should we check for a r/w user too and only idle when
		 * they aren't connected?  right now, i think we want to
		 * do the idle stuff even if we have users
		 */
		if (pCEServing->idletimeout != 0) {
		    time_t chime =
			pCEServing->lastWrite + pCEServing->idletimeout;
		    if (tyme < chime) {
			if (timers[T_CIDLE] == (time_t)0 ||
			    timers[T_CIDLE] > chime)
			    timers[T_CIDLE] = chime;
			continue;
		    }
		    ExpandString(pCEServing->idlestring, pCEServing, 0);
		    TagLogfileAct(pCEServing, "idle timeout");
		    FlushConsole(pCEServing);
		    SendClientsMsg(pCEServing, "[-- idle timeout --]\r\n");
		    /* we're not technically correct here in saying the write
		     * happened, but we don't want to accidentally trigger
		     * another idle action, so we lie...when the buffer gets
		     * flushed, this will be updated and correct.
		     */
		    pCEServing->lastWrite = tyme;
		    chime = tyme + pCEServing->idletimeout;
		    if (timers[T_CIDLE] == (time_t)0 ||
			timers[T_CIDLE] > chime)
			timers[T_CIDLE] = chime;
		}
	    }
	}

	/* see if we need to bring things back up or mark logfiles
	 * or do other such events here.  we call time() each time
	 * in case one of the subroutines actually takes a long time
	 * to complete */
	if (timers[T_MARK] != (time_t)0 &&
	    time((time_t *)0) >= timers[T_MARK])
	    Mark(pGE);

	if (timers[T_INITDELAY] != (time_t)0 &&
	    time((time_t *)0) >= timers[T_INITDELAY]) {
	    timers[T_INITDELAY] = (time_t)0;
	    ReUp(pGE, -1);
	}

	if (timers[T_REINIT] != (time_t)0 &&
	    time((time_t *)0) >= timers[T_REINIT])
	    ReUp(pGE, 2);

	/* must do ReUp(,1) last for timers to work right */
	if (timers[T_AUTOUP] != (time_t)0 &&
	    time((time_t *)0) >= timers[T_AUTOUP])
	    ReUp(pGE, 1);

	/* do we need to check on log file sizes? */
	if (timers[T_ROLL] != (time_t)0 &&
	    time((time_t *)0) >= timers[T_ROLL])
	    RollLogs(pGE);

	/* check on various timers and set the appropriate timeout */
	/* all this so we don't have to use alarm() any more... */

	/* look for the next nearest timeout */
	for (ret = 0; ret < T_MAX; ret++) {
	    if (timers[ret] != (time_t)0 &&
		(tymer == (time_t)0 || tymer > timers[ret]))
		tymer = timers[ret];
	}

	/* if we have a timer, figure out the delay left */
	if (tymer != (time_t)0) {
	    tyme = time((time_t *)0);
	    if (tymer > tyme)	/* in the future */
		tv.tv_sec = tymer - tyme;
	    else		/* now or in the past */
		tv.tv_sec = 1;
	    tv.tv_usec = 0;
	    tvp = &tv;
	} else			/* no timeout */
	    tvp = (struct timeval *)0;
	if (tvp == (struct timeval *)0) {
	    CONDDEBUG((1, "Kiddie(): no select timeout"));
	} else {
	    CONDDEBUG((1, "Kiddie(): select timeout of %d seconds",
		       tv.tv_sec));
	}

	rmask = rinit;
	wmask = winit;

	if ((ret = select(maxfd, &rmask, &wmask, (fd_set *)0, tvp)) == -1) {
	    if (errno != EINTR) {
		Error("Kiddie(): select(): %s", strerror(errno));
		break;
	    }
	    continue;
	}

	if (ret == 0)		/* timeout -- loop back up and handle it */
	    continue;

	/* anything on a console? */
	for (pCEServing = pGE->pCElist; pCEServing != (CONSENT *)0;
	     pCEServing = pCEServing->pCEnext) {
	    if (!pCEServing->fup || pCEServing->type == NOOP)
		continue;
	    switch (pCEServing->ioState) {
		case INCONNECT:
#if HAVE_FREEIPMI
		    if (pCEServing->type == IPMI) {
			if (FileCanRead
			    (pCEServing->cofile, &rmask, &wmask)) {
			    if (IPMICONSOLE_CTX_STATUS_SOL_ESTABLISHED ==
				ipmiconsole_ctx_status
				(pCEServing->ipmictx)) {
				/* Read in the NULL from OUTPUT_ON_SOL_ESTABLISHED flag */
				char b[1];
				FileRead(pCEServing->cofile, b, 1);	/* trust it's NULL */
			    } else {
				Error("[%s] IPMI error: %s: forcing down",
				      pCEServing->server,
				      ipmiconsole_ctx_errormsg(pCEServing->
							       ipmictx));
				/* no ConsoleError() for same reason as above */
				SendIWaitClientsMsg(pCEServing,
						    "down]\r\n");
				ConsDown(pCEServing, FLAGTRUE, FLAGTRUE);
				break;
			    }
			} else
			    break;
		    } else {
#endif /* freeipmi */
			/* deal with this state above as well */
			if (FileCanWrite
			    (pCEServing->cofile, &rmask, &wmask)) {
			    socklen_t slen;
			    int flags = 0;
			    int cofile = FileFDNum(pCEServing->cofile);
			    slen = sizeof(flags);
			    /* So, getsockopt seems to return -1 if there is
			     * something interesting in SO_ERROR under
			     * solaris...sheesh.  So, the error message has
			     * the small change it's not accurate.
			     */
			    if (getsockopt
				(cofile, SOL_SOCKET, SO_ERROR,
				 (char *)&flags, &slen) < 0) {
				Error
				    ("[%s] getsockopt(%u,SO_ERROR): %s: forcing down",
				     pCEServing->server, cofile,
				     strerror(errno));
				/* no ConsoleError() for same reason as above */
				SendIWaitClientsMsg(pCEServing,
						    "down]\r\n");
				ConsDown(pCEServing, FLAGTRUE, FLAGTRUE);
				break;
			    }
			    if (flags != 0) {
				Error("[%s] connect(%u): %s: forcing down",
				      pCEServing->server, cofile,
				      strerror(flags));
				/* no ConsoleError() for same reason as above */
				SendIWaitClientsMsg(pCEServing,
						    "down]\r\n");
				ConsDown(pCEServing, FLAGTRUE, FLAGTRUE);
				break;
			    }

			    /* waiting for a connect(), we watch the write bit,
			     * so switch around and now watch for the read and
			     * start gathering data
			     */
			    FD_SET(cofile, &rinit);
			    FD_CLR(cofile, &winit);
			} else
			    break;
#if HAVE_FREEIPMI
		    }
#endif

		    pCEServing->ioState = ISNORMAL;
		    pCEServing->lastWrite = time((time_t *)0);
#if HAVE_GETTIMEOFDAY
		    if (gettimeofday(&tv, (void *)0) == 0)
			pCEServing->lastInit = tv;
#else
		    if ((tv = time((time_t *)0)) != (time_t)-1)
			pCEServing->lastInit = tv;
#endif
		    if (pCEServing->idletimeout != (time_t)0 &&
			(timers[T_CIDLE] == (time_t)0 ||
			 timers[T_CIDLE] >
			 pCEServing->lastWrite + pCEServing->idletimeout))
			timers[T_CIDLE] =
			    pCEServing->lastWrite +
			    pCEServing->idletimeout;
		    if (pCEServing->downHard == FLAGTRUE) {
			Msg("[%s] console up", pCEServing->server);
			pCEServing->downHard = FLAGFALSE;
		    }
		    SendIWaitClientsMsg(pCEServing, "up]\r\n");
		    StartInit(pCEServing);
		    break;
		case ISNORMAL:
		    if (FileCanRead(pCEServing->cofile, &rmask, &wmask))
			DoConsoleRead(pCEServing);
		    if (FileCanRead(pCEServing->initfile, &rmask, &wmask))
			DoCommandRead(pCEServing);
		    if (FileCanRead(pCEServing->taskfile, &rmask, &wmask))
			DoTaskRead(pCEServing);
		    /* fall through to ISFLUSHING for buffered data */
		case ISFLUSHING:
		    /* write cofile data */
		    if (!FileBufEmpty(pCEServing->cofile) &&
			FileCanWrite(pCEServing->cofile, &rmask, &wmask)) {
			CONDDEBUG((1, "Master(): flushing fd %d",
				   FileFDNum(pCEServing->cofile)));
			if (FileWrite
			    (pCEServing->cofile, FLAGFALSE, (char *)0,
			     0) < 0) {
			    Error("[%s] write failure",
				  pCEServing->server);
			    ConsoleError(pCEServing);
			    break;
			}
		    }
		    /* write fdlog data */
		    if (!FileBufEmpty(pCEServing->fdlog) &&
			FileCanWrite(pCEServing->fdlog, &rmask, &wmask)) {
			CONDDEBUG((1, "Kiddie(): flushing fd %d",
				   FileFDNum(pCEServing->fdlog)));
			if (FileWrite
			    (pCEServing->fdlog, FLAGFALSE, (char *)0,
			     0) < 0) {
			    Error("[%s] write failure",
				  pCEServing->server);
			    ConsoleError(pCEServing);
			    break;
			}
		    }
		    /* write initfile data */
		    if (!FileBufEmpty(pCEServing->initfile) &&
			FileCanWrite(pCEServing->initfile, &rmask,
				     &wmask)) {
			CONDDEBUG((1, "Kiddie(): flushing fd %d",
				   FileFDNum(pCEServing->initfile)));
			if (FileWrite
			    (pCEServing->initfile, FLAGFALSE, (char *)0,
			     0) < 0) {
			    Error("[%s] write failure",
				  pCEServing->server);
			    ConsoleError(pCEServing);
			    break;
			}
		    }
		    /* stop if we're in ISFLUSHING state and out of data */
		    if ((pCEServing->ioState == ISFLUSHING) &&
			FileBufEmpty(pCEServing->cofile) &&
			FileBufEmpty(pCEServing->fdlog) &&
			FileBufEmpty(pCEServing->initfile))
			/* no ConsoleError() for same reason as above */
			ConsDown(pCEServing, FLAGFALSE, FLAGTRUE);
		    break;
		default:
		    /* this really can't ever happen */
		    Error
			("Kiddie(): console socket state == %d -- THIS IS A BUG",
			 pCEServing->ioState);
		    /* no ConsoleError() for same reason as above */
		    ConsDown(pCEServing, FLAGTRUE, FLAGTRUE);
		    break;
	    }
	}

	/* anything on a client? */
	for (pCLServing = pGE->pCLall; (CONSCLIENT *)0 != pCLServing;
	     pCLServing = pCLServing->pCLscan) {
	    switch (pCLServing->ioState) {
#if HAVE_OPENSSL
		case INSSLACCEPT:
		    if (FileCanSSLAccept(pCLServing->fd, &rmask, &wmask)) {
			int r;
			if ((r = FileSSLAccept(pCLServing->fd)) < 0)
			    DisconnectClient(pGE, pCLServing, (char *)0,
					     FLAGFALSE);
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
			    DisconnectClient(pGE, pCLServing, (char *)0,
					     FLAGFALSE);
			else if (r == 1)
			    pCLServing->ioState = ISNORMAL;
		    }
		    break;
#endif
		case ISNORMAL:
		    if (FileCanRead(pCLServing->fd, &rmask, &wmask))
			DoClientRead(pGE, pCLServing);
		    /* fall through to ISFLUSHING for buffered data */
		case ISFLUSHING:
		    if (!FileBufEmpty(pCLServing->fd) &&
			FileCanWrite(pCLServing->fd, &rmask, &wmask)) {
			CONDDEBUG((1, "Kiddie(): flushing fd %d",
				   FileFDNum(pCLServing->fd)));
			if (FileWrite
			    (pCLServing->fd, FLAGFALSE, (char *)0, 0)
			    < 0) {
			    DisconnectClient(pGE, pCLServing, (char *)0,
					     FLAGTRUE);
			    break;
			}
		    }
		    if ((pCLServing->ioState == ISFLUSHING) &&
			FileBufEmpty(pCLServing->fd))
			DisconnectClient(pGE, pCLServing, (char *)0,
					 FLAGFALSE);
		    break;
		default:
		    /* this really can't ever happen */
		    Error
			("Kiddie(): client socket state == %d -- THIS IS A BUG",
			 pCLServing->ioState);
		    DisconnectClient(pGE, pCLServing, (char *)0,
				     FLAGFALSE);
		    break;
	    }
	}

	/* we buffered console data in PutConsole() so that we can
	 * send more than 1-byte payloads, if we get more than 1-byte
	 * of data from a client connection.  here we flush that buffer,
	 * possibly putting it into the write buffer (but we don't really
	 * need to worry about that here).
	 */
	for (pCEServing = pGE->pCElist; pCEServing != (CONSENT *)0;
	     pCEServing = pCEServing->pCEnext)
	    FlushConsole(pCEServing);

	/* if nothing on control line, get more
	 */
	if (!FD_ISSET(sfd, &rmask)) {
	    continue;
	}

	/* accept new connections and deal with them
	 */
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	dmallocMarkClientConnection = dmalloc_mark();
#endif
	so = sizeof(INADDR_STYPE);
	fd = accept(sfd, (struct sockaddr *)&pGE->pCLfree->cnct_port, &so);
	if (fd < 0) {
	    Error("Kiddie(): accept(): %s", strerror(errno));
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	    CONDDEBUG((1, "Kiddie(): dmalloc / MarkClientConnection"));
	    dmalloc_log_changed(dmallocMarkClientConnection, 1, 0, 1);
#endif
	    continue;
	}

	if (SetFlags(fd, O_NONBLOCK, 0)) {
	    pGE->pCLfree->fd = FileOpenFD(fd, simpleSocket);
	    FileSetQuoteIAC(pGE->pCLfree->fd, FLAGTRUE);
	} else
	    pGE->pCLfree->fd = (CONSFILE *)0;

	if ((CONSFILE *)0 == pGE->pCLfree->fd) {
	    Error("Kiddie(): FileOpenFD(): %s", strerror(errno));
	    close(fd);
#if HAVE_DMALLOC && DMALLOC_MARK_CLIENT_CONNECTION
	    CONDDEBUG((1, "Kiddie(): dmalloc / MarkClientConnection"));
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
	BuildString((char *)0, pCL->peername);
	BuildString((char *)0, pCL->acid);
	BuildString("<unknown>@", pCL->acid);
	BuildString((char *)0, pCL->username);
	BuildString("<unknown>", pCL->username);
	StrCpy(pCL->actym, StrTime(&(pCL->tym)), sizeof(pCL->actym));
	pCL->typetym = pCL->tym;

	/* link into the control list for the dummy console
	 */
	pCL->pCEto = pGE->pCEctl;
	pCL->pCLnext = pGE->pCEctl->pCLon;
	pCL->ppCLbnext = &pGE->pCEctl->pCLon;
	if ((CONSCLIENT *)0 != pCL->pCLnext) {
	    pCL->pCLnext->ppCLbnext = &pCL->pCLnext;
	}
	pGE->pCEctl->pCLon = pCL;

	/* link into all clients list
	 */
	pCL->pCLscan = pGE->pCLall;
	pCL->ppCLbscan = &pGE->pCLall;
	if ((CONSCLIENT *)0 != pCL->pCLscan) {
	    pCL->pCLscan->ppCLbscan = &pCL->pCLscan;
	}
	pGE->pCLall = pCL;

	FD_SET(FileFDNum(pCL->fd), &rinit);
	if (maxfd < FileFDNum(pCL->fd) + 1)
	    maxfd = FileFDNum(pCL->fd) + 1;

	/* init the fsm
	 */
	pCL->fecho = 0;
	pCL->iState = S_IDENT;
	pCL->ic[0] = DEFATTN;
	pCL->ic[1] = DEFESC;
	pCL->replay = DEFREPLAY;
	pCL->playback = DEFPLAYBACK;
	BuildString((char *)0, pCL->accmd);

	/* mark as stopped (no output from console)
	 * and spy only (on chars to console)
	 */
	pCL->fcon = 0;
	pCL->fwr = 0;
	pCL->fwantwr = 0;

	/* remove from the free list
	 * if we ran out of free slots, calloc one...
	 */
	if ((CONSCLIENT *)0 == pGE->pCLfree) {
	    if ((pGE->pCLfree =
		 (CONSCLIENT *)calloc(1, sizeof(CONSCLIENT)))
		== (CONSCLIENT *)0)
		OutOfMem();
	    pGE->pCLfree->acid = AllocString();
	    pGE->pCLfree->username = AllocString();
	    pGE->pCLfree->peername = AllocString();
	    pGE->pCLfree->accmd = AllocString();
	}

	if (ClientAccessOk(pCL)) {
	    pCL->ioState = ISNORMAL;
	    /* say hi to start */
	    FileWrite(pCL->fd, FLAGFALSE, "ok\r\n", -1);
	    BuildString(pCL->peername->string, pCL->acid);
	    CONDDEBUG((1, "Kiddie(): client acid initialized to `%s'",
		       pCL->acid->string));
	} else
	    DisconnectClient(pGE, pCL, (char *)0, FLAGFALSE);
    }
}

/* create a child process:						(fine)
 * fork off a process for each group with an open socket for connections
 */
void
Spawn(GRPENT *pGE, int msfd)
{
    pid_t pid;
    int sfd;
#if USE_IPV6 || !USE_UNIX_DOMAIN_SOCKETS
# if USE_IPV6
    int error;
    struct addrinfo *rp, hints, *res;
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    unsigned short bindBasePort;
# else
    socklen_t so;
    struct sockaddr_in lstn_port;
# endif
# if HAVE_SETSOCKOPT
    int true = 1;
# endif
    unsigned short portInc = 0;
#else
    struct sockaddr_un lstn_port;
    static STRING *portPath = (STRING *)0;
#endif

#if !USE_IPV6
    /* get a socket for listening */
# if HAVE_MEMSET
    memset((void *)&lstn_port, 0, sizeof(lstn_port));
# else
    bzero((char *)&lstn_port, sizeof(lstn_port));
# endif
#endif

#if USE_IPV6
    for (rp = bindBaseAddr; rp != NULL; rp = rp->ai_next) {
	if ((sfd =
	     socket(rp->ai_family, rp->ai_socktype,
		    rp->ai_protocol)) < 0) {
	    Error("Spawn(): socket(): %s", strerror(errno));
	    continue;
	}
# if HAVE_SETSOCKOPT
	if (setsockopt
	    (sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&true,
	     sizeof(true)) < 0) {
	    Error("Spawn(): setsockopt(%u,SO_REUSEADDR): %s", sfd,
		  strerror(errno));
	    return;
	}
# endif
	if (!SetFlags(sfd, O_NONBLOCK, 0))
	    return;

	error =
	    getnameinfo(rp->ai_addr, rp->ai_addrlen, host, sizeof(host),
			serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV);
	if (error) {
	    Error("Spawn(): getnameinfo failed: %s", gai_strerror(error));
	    return;
	}
	bindBasePort = (unsigned short)strtol(serv, NULL, 10);

	while (bind(sfd, rp->ai_addr, rp->ai_addrlen) < 0) {
	    if (bindBasePort && (
# if defined(EADDRINUSE)
				    (errno == EADDRINUSE) ||
# endif
				    (errno == EACCES)) && ++portInc) {
		/*
		 * instead of checking for ai_family and modifying
		 * the structure directly we will generate new addrinfo
		 * structure, copy over first entry and release it.
		 */
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags =
		    AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;
		snprintf(serv, sizeof(serv), "%hu",
			 (short)(bindBasePort + portInc));
		error = getaddrinfo(host, serv, &hints, &res);
		if (error)
		    goto OUT;

		memcpy(rp->ai_addr, res->ai_addr, rp->ai_addrlen);
		freeaddrinfo(res);
		continue;
	    } else
		goto OUT;
	}
	break;			/* if we're here bind was succesful so get out */

      OUT:
	portInc = 0;
	close(sfd);
    }

    /* if rp is null we did not bind */
    if (rp == NULL) {
	Error("Spawn(): could not bind");
	Bye(EX_OSERR);
    }

    if (-1 == getsockname(sfd, rp->ai_addr, &rp->ai_addrlen)) {
	Error("Spawn(): getsockname(%u): %s", sfd, strerror(errno));
	Bye(EX_OSERR);
    }

    /* 
     * if bindBasePort is 0 we did auto-assign our port. to find out
     * what we bind to we need to call getsockname (above) and call
     * getnameinfo again. otherwise we have the port info in
     * bindBasePort + portInc
     */
    if (!bindBasePort) {
	error =
	    getnameinfo(rp->ai_addr, rp->ai_addrlen, NULL, 0, serv,
			sizeof(serv), NI_NUMERICSERV);
	if (error) {
	    Error("Spawn(): getnameinfo failed: %s", gai_strerror(error));
	    Bye(EX_OSERR);
	}
	pGE->port = (unsigned short)strtol(serv, NULL, 10);
    } else
	pGE->port = bindBasePort + portInc;
#elif USE_UNIX_DOMAIN_SOCKETS
    lstn_port.sun_family = AF_UNIX;

    if (portPath == (STRING *)0)
	portPath = AllocString();
    BuildStringPrint(portPath, "%s/%u", interface, pGE->id);
    if (portPath->used > sizeof(lstn_port.sun_path)) {
	Error("Spawn(): path to socket too long: %s", portPath->string);
	Bye(EX_OSERR);
    }
    StrCpy(lstn_port.sun_path, portPath->string,
	   sizeof(lstn_port.sun_path));

    /* create a socket to listen on
     * (prepared by master so he can see the port number of the kid)
     */
    if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	Error("Spawn(): socket(): %s", strerror(errno));
	Bye(EX_OSERR);
    }

    if (!SetFlags(sfd, O_NONBLOCK, 0))
	Bye(EX_OSERR);

    if (bind(sfd, (struct sockaddr *)&lstn_port, sizeof(lstn_port)) < 0) {
	Error("Spawn(): bind(%s): %s", lstn_port.sun_path,
	      strerror(errno));
	Bye(EX_OSERR);
    }
# ifdef TRUST_UDS_CRED
    /* Allow everyone to connect, but we later auth them via SO_PEERCRED */
    chmod(lstn_port.sun_path, 0666);
# endif

    pGE->port = pGE->id;
#else
    lstn_port.sin_family = AF_INET;
    lstn_port.sin_addr.s_addr = bindAddr;
    lstn_port.sin_port = htons(bindBasePort);

    /* create a socket to listen on
     * (prepared by master so he can see the port number of the kid)
     */
    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	Error("Spawn(): socket(): %s", strerror(errno));
	Bye(EX_OSERR);
    }
# if HAVE_SETSOCKOPT
    if (setsockopt
	(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&true, sizeof(true))
	< 0) {
	Error("Spawn(): setsockopt(%u,SO_REUSEADDR): %s", sfd,
	      strerror(errno));
	Bye(EX_OSERR);
    }
# endif

    if (!SetFlags(sfd, O_NONBLOCK, 0))
	Bye(EX_OSERR);

    while (bind(sfd, (struct sockaddr *)&lstn_port, sizeof(lstn_port))
	   < 0) {
	if (bindBasePort && (
# if defined(EADDRINUSE)
				(errno == EADDRINUSE) ||
# endif
				(errno == EACCES)) && ++portInc) {
	    lstn_port.sin_port = htons(bindBasePort + portInc);
	} else {
	    Error("Spawn(): bind(%hu): %s", ntohs(lstn_port.sin_port),
		  strerror(errno));
	    Bye(EX_OSERR);
	}
    }
    so = sizeof(lstn_port);

    if (-1 == getsockname(sfd, (struct sockaddr *)&lstn_port, &so)) {
	Error("Spawn(): getsockname(%u): %s", sfd, strerror(errno));
	Bye(EX_OSERR);
    }
    pGE->port = ntohs(lstn_port.sin_port);
#endif

    fflush(stderr);
    fflush(stdout);
    switch (pid = fork()) {
	case -1:
	    Error("Spawn(): fork(): %s", strerror(errno));
	    Bye(EX_OSERR);
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
	    Sleep(750000);	/* pause 0.75 sec to throttle startup a bit */
	    pGE->pid = pid;
	    return;
	case 0:
	    pGE->pid = thepid = getpid();
	    isMaster = 0;
	    break;
    }

#if HAVE_SETPROCTITLE
    if (config->setproctitle == FLAGTRUE)
	setproctitle("group %u: port %hu, %d %s", pGE->id, pGE->port,
		     pGE->imembers,
		     pGE->imembers == 1 ? "console" : "consoles");
#endif

    /* close the master fd - which is there *except* on startup */
    if (msfd != -1)
	close(msfd);

    /* clean out the master client lists - they aren't useful here and just
     * cause extra file descriptors and memory allocation to lie around,
     * not a very good thing!
     */
    while (pCLmall != (CONSCLIENT *)0) {
	CONSCLIENT *pCL;
	if (pCLmall->fd != (CONSFILE *)0) {
	    int fd;
	    fd = FileUnopen(pCLmall->fd);
	    pCLmall->fd = (CONSFILE *)0;
	    CONDDEBUG((1, "Spawn(): closing Master() client fd %d", fd));
	    close(fd);
	    FD_CLR(fd, &rinit);
	    FD_CLR(fd, &winit);
	}
	pCL = pCLmall->pCLscan;
	DestroyClient(pCLmall);
	pCLmall = pCL;
    }
    while (pCLmfree != (CONSCLIENT *)0) {
	CONSCLIENT *pCL;
	pCL = pCLmfree->pCLnext;
	DestroyClient(pCLmfree);
	pCLmfree = pCL;
    }

    if (listen(sfd, SOMAXCONN) < 0) {
#if USE_UNIX_DOMAIN_SOCKETS
	Error("Spawn(): listen(%s): %s", lstn_port.sun_path,
	      strerror(errno));
#else
	Error("Spawn(): listen(%hu): %s", pGE->port, strerror(errno));
#endif
	Bye(EX_OSERR);
    }
    Kiddie(pGE, sfd);

    /* should never get here...but on errors we could */
    close(sfd);
#if USE_UNIX_DOMAIN_SOCKETS
    unlink(lstn_port.sun_path);
#endif
    Bye(EX_SOFTWARE);
}
