/*
 *  $Id: readcfg.c,v 5.144 2003-10-03 06:32:34-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

/*
 * Notes/Thoughts:
 *
 * - building access lists doesn't remove any dups in AccessDestroy().
 *   it just joins lists that match the current host.  it would be nice
 *   to have only unique items in the list.
 *
 * - the *Abort() stuff may not play well with the *Begin() stuff - if
 *   it's reusing the space, could we not have values trickle over into
 *   the next section?  -  i think i may have fixed that.
 *
 * - add the flow tag at some point
 *
 *  s+ m max      maximum consoles managed per process
 *
 */

#include <compat.h>

#include <util.h>
#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <readcfg.h>
#include <main.h>

/*****  external things *****/
NAMES *userList = (NAMES *)0;
GRPENT *pGroups = (GRPENT *)0;
REMOTE *pRCList = (REMOTE *)0;
ACCESS *pACList = (ACCESS *)0;
CONSENTUSERS *pADList = (CONSENTUSERS *)0;
REMOTE *pRCUniq = (REMOTE *)0;
CONFIG *pConfig = (CONFIG *)0;
BREAKS breakList[9] = {
    {(STRING *)0, 0}, {(STRING *)0, 0}, {(STRING *)0, 0},
    {(STRING *)0, 0}, {(STRING *)0, 0}, {(STRING *)0, 0},
    {(STRING *)0, 0}, {(STRING *)0, 0}, {(STRING *)0, 0}
};

void
#if PROTOTYPES
DestroyBreakList(void)
#else
DestroyBreakList()
#endif
{
    int i;

    for (i = 0; i < 9; i++) {
	if (breakList[i].seq != (STRING *)0) {
	    DestroyString(breakList[i].seq);
	    breakList[i].seq = (STRING *)0;
	}
    }
}

void
#if PROTOTYPES
DestroyUserList(void)
#else
DestroyUserList()
#endif
{
    NAMES *n;
    while (userList != (NAMES *)0) {
	n = userList->next;
	if (userList->name != (char *)0)
	    free(userList->name);
	free(userList);
	userList = n;
    }
}

NAMES *
#if PROTOTYPES
FindUserList(char *id)
#else
FindUserList(id)
    char *id;
#endif
{
    NAMES *u;
    for (u = userList; u != (NAMES *)0; u = u->next) {
	if (strcmp(u->name, id) == 0)
	    return u;
    }
    return u;
}

NAMES *
#if PROTOTYPES
AddUserList(char *id)
#else
AddUserList(id)
    char *id;
#endif
{
    NAMES *u;

    if ((u = FindUserList(id)) == (NAMES *)0) {
	if ((u = (NAMES *)calloc(1, sizeof(NAMES)))
	    == (NAMES *)0)
	    OutOfMem();
	if ((u->name = StrDup(id))
	    == (char *)0)
	    OutOfMem();
	u->next = userList;
	userList = u;
    }
    return u;
}

/***** internal things *****/
typedef struct item {
    char *id;
    void (*reg) PARAMS((char *));
} ITEM;

typedef struct section {
    char *id;
    void (*begin) PARAMS((char *));
    void (*end) PARAMS((void));
    void (*abort) PARAMS((void));
    void (*destroy) PARAMS((void));
    ITEM *items;
} SECTION;

#define BREAKDELAYDEFAULT 250
#define ALLWORDSEP ", \f\v\t\n\r"

int line = 1;			/* current line number */
char *file = (char *)0;
int isStartup = 0;
GRPENT *pGroupsOld = (GRPENT *)0;
GRPENT *pGEstage = (GRPENT *)0;
GRPENT *pGE = (GRPENT *)0;
static unsigned int groupID = 0;
REMOTE **ppRC = (REMOTE **)0;

/* 'break' handling */
STRING *parserBreak = (STRING *)0;
int parserBreakDelay = 0;
int parserBreakNum = 0;

CONSENTUSERS *
#if PROTOTYPES
ConsentAddUser(CONSENTUSERS **ppCU, char *id)
#else
ConsentAddUser(ppCU, id)
    CONSENTUSERS **ppCU;
    char *id;
#endif
{
    CONSENTUSERS *u = (CONSENTUSERS *)0;

    if ((u = ConsentFindUser(*ppCU, id)) == (CONSENTUSERS *)0) {
	if ((u = (CONSENTUSERS *)calloc(1, sizeof(CONSENTUSERS)))
	    == (CONSENTUSERS *)0)
	    OutOfMem();
	u->user = AddUserList(id);
	u->next = *ppCU;
	*ppCU = u;
    }
    return u;
}

void
#if PROTOTYPES
BreakBegin(char *id)
#else
BreakBegin(id)
    char *id;
#endif
{
    CONDDEBUG((1, "BreakBegin(%s) [%s:%d]", id, file, line));
    if ((id == (char *)0) || (*id == '\000') || id[0] < '1' || id[0] > '9'
	|| id[1] != '\000') {
	if (isMaster)
	    Error("invalid break number `%s' [%s:%d]", id, file, line);
	parserBreakNum = 0;
    } else {
	parserBreakNum = id[0] - '0';
	if (parserBreak == (STRING *)0)
	    parserBreak = AllocString();
	else
	    BuildString((char *)0, parserBreak);
	parserBreakDelay = BREAKDELAYDEFAULT;
    }
}

void
#if PROTOTYPES
BreakEnd(void)
#else
BreakEnd()
#endif
{
    CONDDEBUG((1, "BreakEnd() [%s:%d]", file, line));

    if (parserBreakNum == 0)
	return;

    BuildString((char *)0, breakList[parserBreakNum - 1].seq);
    BuildString(parserBreak->string, breakList[parserBreakNum - 1].seq);
    CleanupBreak(parserBreakNum);
    breakList[parserBreakNum - 1].delay = parserBreakDelay;
    parserBreakNum = 0;
}

void
#if PROTOTYPES
BreakAbort(void)
#else
BreakAbort()
#endif
{
    CONDDEBUG((1, "BreakAbort() [%s:%d]", file, line));
    parserBreakNum = 0;
}

void
#if PROTOTYPES
BreakDestroy(void)
#else
BreakDestroy()
#endif
{
    CONDDEBUG((1, "BreakDestroy() [%s:%d]", file, line));
    if (parserBreak != (STRING *)0) {
	DestroyString(parserBreak);
	parserBreak = (STRING *)0;
    }
#if DUMPDATA
    {
	int i;
	for (i = 0; i < 9; i++) {
	    Msg("Break[%d] = `%s', delay=%d", i, breakList[i].seq->string,
		breakList[i].delay);
	}
    }
#endif
}

void
#if PROTOTYPES
BreakItemString(char *id)
#else
BreakItemString(id)
    char *id;
#endif
{
    CONDDEBUG((1, "BreakItemString(%s) [%s:%d]", id, file, line));
    BuildString((char *)0, parserBreak);
    if ((id == (char *)0) || (*id == '\000'))
	return;
    BuildString(id, parserBreak);
}

void
#if PROTOTYPES
BreakItemDelay(char *id)
#else
BreakItemDelay(id)
    char *id;
#endif
{
    char *p;
    int delay;

    CONDDEBUG((1, "BreakItemDelay(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000')) {
	parserBreakDelay = 0;
	return;
    }

    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;
    /* if it wasn't a number or the number is out of bounds */
    if ((*p != '\000') || ((delay = atoi(id)) > 999)) {
	if (isMaster)
	    Error("invalid port number `%s' [%s:%d]", id, file, line);
	return;
    }
    parserBreakDelay = delay;
}

/* 'group' handling */
typedef struct parserGroupUsers {
    NAMES *user;
    struct parserGroupUsers *next;
} PARSERGROUPUSERS;

typedef struct parserGroup {
    STRING *name;
    PARSERGROUPUSERS *users;
    struct parserGroup *next;
} PARSERGROUP;

PARSERGROUP *parserGroups = (PARSERGROUP *)0;
PARSERGROUP *parserGroupTemp = (PARSERGROUP *)0;

void
#if PROTOTYPES
DestroyParserGroup(PARSERGROUP *pg)
#else
DestroyParserGroup(pg)
    PARSERGROUP *pg;
#endif
{
    PARSERGROUP **ppg = &parserGroups;
    PARSERGROUPUSERS *u = (PARSERGROUPUSERS *)0;
    char *m = (char *)0;

    if (pg == (PARSERGROUP *)0)
	return;
    while (*ppg != (PARSERGROUP *)0) {
	if (*ppg == pg) {
	    break;
	} else {
	    ppg = &((*ppg)->next);
	}
    }

    BuildTmpString((char *)0);
    m = BuildTmpString(pg->name->string);
    if (*ppg != (PARSERGROUP *)0)
	*ppg = pg->next;
    DestroyString(pg->name);
    for (u = pg->users; u != (PARSERGROUPUSERS *)0;) {
	PARSERGROUPUSERS *n = u->next;
	BuildTmpStringChar(',');
	m = BuildTmpString(u->user->name);
	free(u);
	u = n;
    }
    free(pg);
    CONDDEBUG((2, "DestroyParserGroup(): %s", m));
}

PARSERGROUP *
#if PROTOTYPES
GroupFind(char *id)
#else
GroupFind(id)
    char *id;
#endif
{
    PARSERGROUP *pg;
    for (pg = parserGroups; pg != (PARSERGROUP *)0; pg = pg->next) {
	if (strcmp(id, pg->name->string) == 0)
	    return pg;
    }
    return pg;
}

void
#if PROTOTYPES
GroupBegin(char *id)
#else
GroupBegin(id)
    char *id;
#endif
{
    CONDDEBUG((1, "GroupBegin(%s) [%s:%d]", id, file, line));
    if (id == (char *)0 || id[0] == '\000') {
	if (isMaster)
	    Error("empty group name [%s:%d]", file, line);
	return;
    }
    if (parserGroupTemp != (PARSERGROUP *)0)
	DestroyParserGroup(parserGroupTemp);
    if ((parserGroupTemp = (PARSERGROUP *)calloc(1, sizeof(PARSERGROUP)))
	== (PARSERGROUP *)0)
	OutOfMem();
    parserGroupTemp->name = AllocString();
    BuildString(id, parserGroupTemp->name);
}

void
#if PROTOTYPES
GroupEnd(void)
#else
GroupEnd()
#endif
{
    PARSERGROUP *pg = (PARSERGROUP *)0;

    CONDDEBUG((1, "GroupEnd() [%s:%d]", file, line));

    if (parserGroupTemp->name->used <= 1) {
	DestroyParserGroup(parserGroupTemp);
	parserGroupTemp = (PARSERGROUP *)0;
	return;
    }

    /* if we're overriding an existing group, nuke it */
    if ((pg =
	 GroupFind(parserGroupTemp->name->string)) != (PARSERGROUP *)0) {
	DestroyParserGroup(pg);
    }
    /* add the temp to the head of the list */
    parserGroupTemp->next = parserGroups;
    parserGroups = parserGroupTemp;
    parserGroupTemp = (PARSERGROUP *)0;
}

void
#if PROTOTYPES
GroupAbort(void)
#else
GroupAbort()
#endif
{
    CONDDEBUG((1, "GroupAbort() [%s:%d]", file, line));
    DestroyParserGroup(parserGroupTemp);
    parserGroupTemp = (PARSERGROUP *)0;
}

void
#if PROTOTYPES
GroupDestroy(void)
#else
GroupDestroy()
#endif
{
    CONDDEBUG((1, "GroupDestroy() [%s:%d]", file, line));
#if DUMPDATA
    {
	PARSERGROUP *pg;
	NAMES *u;
	for (pg = parserGroups; pg != (PARSERGROUP *)0; pg = pg->next) {
	    PARSERGROUPUSERS *pgu;
	    Msg("Group = %s", pg->name->string);
	    for (pgu = pg->users; pgu != (PARSERGROUPUSERS *)0;
		 pgu = pgu->next) {
		Msg("    User = %s", pgu->user->name);
	    }
	}
	Msg("UserList...");
	for (u = userList; u != (NAMES *)0; u = u->next) {
	    Msg("    User = %s", u->name);
	}
    }
#endif
    while (parserGroups != (PARSERGROUP *)0)
	DestroyParserGroup(parserGroups);
    DestroyParserGroup(parserGroupTemp);
    parserGroups = parserGroupTemp = (PARSERGROUP *)0;
}

PARSERGROUPUSERS *
#if PROTOTYPES
GroupFindUser(PARSERGROUP *pg, char *id)
#else
GroupFindUser(pg, id)
    PARSERGROUP *pg;
    char *id;
#endif
{
    PARSERGROUPUSERS *pgu;
    for (pgu = pg->users; pgu != (PARSERGROUPUSERS *)0; pgu = pgu->next) {
	if (strcmp(pgu->user->name, id) == 0) {
	    return pgu;
	}
    }
    return pgu;
}

PARSERGROUPUSERS *
#if PROTOTYPES
GroupAddUser(PARSERGROUP *pg, char *id)
#else
GroupAddUser(pg, id)
    PARSERGROUP *pg;
    char *id;
#endif
{
    PARSERGROUPUSERS *pgu = (PARSERGROUPUSERS *)0;

    if ((pgu = GroupFindUser(pg, id)) == (PARSERGROUPUSERS *)0) {
	if ((pgu = (PARSERGROUPUSERS *)calloc(1, sizeof(PARSERGROUPUSERS)))
	    == (PARSERGROUPUSERS *)0)
	    OutOfMem();
	pgu->user = AddUserList(id);
	pgu->next = pg->users;
	pg->users = pgu;
    }
    return pgu;
}

void
#if PROTOTYPES
GroupItemInclude(char *id)
#else
GroupItemInclude(id)
    char *id;
#endif
{
    char *token = (char *)0;
    PARSERGROUP *pg = (PARSERGROUP *)0;

    CONDDEBUG((1, "GroupItemInclude(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000'))
	return;

    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	if ((pg = GroupFind(token)) == (PARSERGROUP *)0) {
	    if (isMaster)
		Error("unknown group name `%s' [%s:%d]", token, file,
		      line);
	} else {
	    PARSERGROUPUSERS *pgu;
	    for (pgu = pg->users; pgu != (PARSERGROUPUSERS *)0;
		 pgu = pgu->next) {
		GroupAddUser(parserGroupTemp, pgu->user->name);
	    }
	}
    }
}

void
#if PROTOTYPES
GroupItemUsers(char *id)
#else
GroupItemUsers(id)
    char *id;
#endif
{
    char *token = (char *)0;
    PARSERGROUP *pg = (PARSERGROUP *)0;

    CONDDEBUG((1, "GroupItemUsers(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000')) {
	PARSERGROUPUSERS *u;
	for (u = parserGroupTemp->users; u != (PARSERGROUPUSERS *)0;) {
	    PARSERGROUPUSERS *n = u->next;
	    free(u);
	    u = n;
	}
	return;
    }

    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	if ((pg = GroupFind(token)) == (PARSERGROUP *)0) {
	    GroupAddUser(parserGroupTemp, token);
	} else {
	    PARSERGROUPUSERS *pgu;
	    for (pgu = pg->users; pgu != (PARSERGROUPUSERS *)0;
		 pgu = pgu->next) {
		GroupAddUser(parserGroupTemp, pgu->user->name);
	    }
	}
    }
}

/* 'default' handling */
CONSENT *parserDefaults = (CONSENT *)0;
CONSENT **parserDefaultsTail = &parserDefaults;
CONSENT *parserDefaultTemp = (CONSENT *)0;

void
#if PROTOTYPES
DestroyParserDefaultOrConsole(CONSENT *c, CONSENT **ph, CONSENT ***pt)
#else
DestroyParserDefaultOrConsole(c, ph, pt)
    CONSENT *c;
    CONSENT **ph;
    CONSENT ***pt;
#endif
{
    if (c == (CONSENT *)0)
	return;

    CONDDEBUG((2, "DestroyParserDefaultOrConsole(): %s", c->server));

    if (ph != (CONSENT **)0) {
	while (*ph != (CONSENT *)0) {
	    if (*ph == c) {
		break;
	    } else {
		ph = &((*ph)->pCEnext);
	    }
	}

	/* if we were in a chain... */
	if (*ph != (CONSENT *)0) {
	    /* unlink from the chain */
	    *ph = c->pCEnext;
	    /* and possibly fix tail ptr... */
	    if (c->pCEnext == (CONSENT *)0)
		(*pt) = ph;
	}
    }

    DestroyConsentUsers(&(c->ro));
    DestroyConsentUsers(&(c->rw));

    if (c->server != (char *)0)
	free(c->server);
    if (c->host != (char *)0)
	free(c->host);
    if (c->master != (char *)0)
	free(c->master);
    if (c->exec != (char *)0)
	free(c->exec);
    if (c->device != (char *)0)
	free(c->device);
    if (c->logfile != (char *)0)
	free(c->logfile);
    if (c->initcmd != (char *)0)
	free(c->initcmd);
    if (c->motd != (char *)0)
	free(c->motd);
    if (c->execSlave != (char *)0)
	free(c->execSlave);
    if (c->wbuf != (STRING *)0)
	DestroyString(c->wbuf);
    free(c);
}

CONSENT *
#if PROTOTYPES
FindParserDefaultOrConsole(CONSENT *c, char *id)
#else
FindParserDefaultOrConsole(c, id)
    CONSENT *c;
    char *id;
#endif
{
    for (; c != (CONSENT *)0; c = c->pCEnext) {
	if (strcasecmp(id, c->server) == 0)
	    return c;
    }
    return c;
}

void
#if PROTOTYPES
ApplyDefault(CONSENT *d, CONSENT *c)
#else
ApplyDefault(d, c)
    CONSENT *d;
    CONSENT *c;
#endif
{
    if (d->type != UNKNOWN)
	c->type = d->type;
    if (d->breakNum != 0)
	c->breakNum = d->breakNum;
    if (d->baud != (BAUD *)0)
	c->baud = d->baud;
    if (d->parity != (PARITY *)0)
	c->parity = d->parity;
    if (d->port != 0)
	c->port = d->port;
    if (d->mark != 0)
	c->mark = d->mark;
    if (d->nextMark != 0)
	c->nextMark = d->nextMark;
    if (d->activitylog != FLAGUNKNOWN)
	c->activitylog = d->activitylog;
    if (d->breaklog != FLAGUNKNOWN)
	c->breaklog = d->breaklog;
    if (d->hupcl != FLAGUNKNOWN)
	c->hupcl = d->hupcl;
    if (d->cstopb != FLAGUNKNOWN)
	c->cstopb = d->cstopb;
    if (d->ixany != FLAGUNKNOWN)
	c->ixany = d->ixany;
    if (d->ixon != FLAGUNKNOWN)
	c->ixon = d->ixon;
    if (d->ixoff != FLAGUNKNOWN)
	c->ixoff = d->ixoff;
#if defined(CRTSCTS)
    if (d->crtscts != FLAGUNKNOWN)
	c->crtscts = d->crtscts;
#endif
    if (d->ondemand != FLAGUNKNOWN)
	c->ondemand = d->ondemand;
    if (d->striphigh != FLAGUNKNOWN)
	c->striphigh = d->striphigh;
    if (d->reinitoncc != FLAGUNKNOWN)
	c->reinitoncc = d->reinitoncc;
    if (d->autoreinit != FLAGUNKNOWN)
	c->autoreinit = d->autoreinit;
    if (d->unloved != FLAGUNKNOWN)
	c->unloved = d->unloved;
    if (d->host != (char *)0) {
	if (c->host != (char *)0)
	    free(c->host);
	if ((c->host = StrDup(d->host)) == (char *)0)
	    OutOfMem();
    }
    if (d->master != (char *)0) {
	if (c->master != (char *)0)
	    free(c->master);
	if ((c->master = StrDup(d->master)) == (char *)0)
	    OutOfMem();
    }
    if (d->exec != (char *)0) {
	if (c->exec != (char *)0)
	    free(c->exec);
	if ((c->exec = StrDup(d->exec)) == (char *)0)
	    OutOfMem();
    }
    if (d->device != (char *)0) {
	if (c->device != (char *)0)
	    free(c->device);
	if ((c->device = StrDup(d->device)) == (char *)0)
	    OutOfMem();
    }
    if (d->logfile != (char *)0) {
	if (c->logfile != (char *)0)
	    free(c->logfile);
	if ((c->logfile = StrDup(d->logfile)) == (char *)0)
	    OutOfMem();
    }
    if (d->initcmd != (char *)0) {
	if (c->initcmd != (char *)0)
	    free(c->initcmd);
	if ((c->initcmd = StrDup(d->initcmd)) == (char *)0)
	    OutOfMem();
    }
    if (d->motd != (char *)0) {
	if (c->motd != (char *)0)
	    free(c->motd);
	if ((c->motd = StrDup(d->motd)) == (char *)0)
	    OutOfMem();
    }
    if (d->ro != (CONSENTUSERS *)0) {
	CONSENTUSERS *u;
	for (u = d->ro; u != (CONSENTUSERS *)0; u = u->next) {
	    ConsentAddUser(&(c->ro), u->user->name);
	}
    }
    if (d->rw != (CONSENTUSERS *)0) {
	CONSENTUSERS *u;
	for (u = d->rw; u != (CONSENTUSERS *)0; u = u->next) {
	    ConsentAddUser(&(c->rw), u->user->name);
	}
    }
}

void
#if PROTOTYPES
DefaultBegin(char *id)
#else
DefaultBegin(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultBegin(%s) [%s: %d]", id, file, line));
    if (id == (char *)0 || id[0] == '\000') {
	if (isMaster)
	    Error("empty default name [%s:%d]", file, line);
	return;
    }
    if (parserDefaultTemp != (CONSENT *)0)
	DestroyParserDefaultOrConsole(parserDefaultTemp, (CONSENT **)0,
				      (CONSENT ***)0);
    if ((parserDefaultTemp = (CONSENT *)calloc(1, sizeof(CONSENT)))
	== (CONSENT *)0)
	OutOfMem();

    if ((parserDefaultTemp->server = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
DefaultEnd(void)
#else
DefaultEnd()
#endif
{
    CONSENT *c = (CONSENT *)0;

    CONDDEBUG((1, "DefaultEnd() [%s:%d]", file, line));

    if (parserDefaultTemp->server == (char *)0) {
	DestroyParserDefaultOrConsole(parserDefaultTemp, (CONSENT **)0,
				      (CONSENT ***)0);
	parserDefaultTemp = (CONSENT *)0;
	return;
    }

    /* if we're overriding an existing default, nuke it */
    if ((c =
	 FindParserDefaultOrConsole(parserDefaults,
				    parserDefaultTemp->server)) !=
	(CONSENT *)0) {
	DestroyParserDefaultOrConsole(c, &parserDefaults,
				      &parserDefaultsTail);
    }

    /* add the temp to the tail of the list */
    *parserDefaultsTail = parserDefaultTemp;
    parserDefaultsTail = &(parserDefaultTemp->pCEnext);
    parserDefaultTemp = (CONSENT *)0;
}

void
#if PROTOTYPES
DefaultAbort(void)
#else
DefaultAbort()
#endif
{
    CONDDEBUG((1, "DefaultAbort() [%s:%d]", file, line));
    DestroyParserDefaultOrConsole(parserDefaultTemp, (CONSENT **)0,
				  (CONSENT ***)0);
    parserDefaultTemp = (CONSENT *)0;
}

void
#if PROTOTYPES
DefaultDestroy(void)
#else
DefaultDestroy()
#endif
{
    CONDDEBUG((1, "DefaultDestroy() [%s:%d]", file, line));

    while (parserDefaults != (CONSENT *)0)
	DestroyParserDefaultOrConsole(parserDefaults, &parserDefaults,
				      &parserDefaultsTail);
    DestroyParserDefaultOrConsole(parserDefaultTemp, (CONSENT **)0,
				  (CONSENT ***)0);
    parserDefaults = parserDefaultTemp = (CONSENT *)0;
}

void
#if PROTOTYPES
ProcessBaud(CONSENT *c, char *id)
#else
ProcessBaud(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if ((id == (char *)0) || (*id == '\000')) {
	c->baud = (BAUD *)0;
	return;
    }
    c->baud = FindBaud(id);
    if (c->baud == (BAUD *)0) {
	if (isMaster)
	    Error("invalid baud rate `%s' [%s:%d]", id, file, line);
    }
}

void
#if PROTOTYPES
DefaultItemBaud(char *id)
#else
DefaultItemBaud(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemBaud(%s) [%s:%d]", id, file, line));
    ProcessBaud(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessBreak(CONSENT *c, char *id)
#else
ProcessBreak(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if ((id == (char *)0) || (*id == '\000')) {
	c->breakNum = 0;
	return;
    }
    if ((id[0] >= '1') && (id[0] <= '9') && (id[1] == '\000')) {
	c->breakNum = id[0] - '0';
	return;
    }
    if (isMaster)
	Error("invalid break number `%s' [%s:%d]", id, file, line);
}

void
#if PROTOTYPES
DefaultItemBreak(char *id)
#else
DefaultItemBreak(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemBreak(%s) [%s:%d]", id, file, line));
    ProcessBreak(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessDevice(CONSENT *c, char *id)
#else
ProcessDevice(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if (c->device != (char *)0) {
	free(c->device);
	c->device = (char *)0;
    }
    if ((id == (char *)0) || (*id == '\000'))
	return;
    if ((c->device = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
DefaultItemDevice(char *id)
#else
DefaultItemDevice(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemDevice(%s) [%s:%d]", id, file, line));
    ProcessDevice(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessExec(CONSENT *c, char *id)
#else
ProcessExec(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if (c->exec != (char *)0) {
	free(c->exec);
	c->exec = (char *)0;
    }
    if (id == (char *)0 || id[0] == '\000') {
	return;
    }
    if ((c->exec = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
DefaultItemExec(char *id)
#else
DefaultItemExec(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemExec(%s) [%s:%d]", id, file, line));
    ProcessExec(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessFlow(CONSENT *c, char *id)
#else
ProcessFlow(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if (isMaster)
	Error("unimplemented code for `flow' [%s:%d]", file, line);
}

void
#if PROTOTYPES
DefaultItemFlow(char *id)
#else
DefaultItemFlow(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemFlow(%s) [%s:%d]", id, file, line));
    ProcessFlow(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessHost(CONSENT *c, char *id)
#else
ProcessHost(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if (c->host != (char *)0) {
	free(c->host);
	c->host = (char *)0;
    }
    if ((id == (char *)0) || (*id == '\000'))
	return;
    if ((c->host = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
DefaultItemHost(char *id)
#else
DefaultItemHost(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemHost(%s) [%s:%d]", id, file, line));
    ProcessHost(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessInclude(CONSENT *c, char *id)
#else
ProcessInclude(c, id)
    CONSENT *c;
    char *id;
#endif
{
    CONSENT *inc = (CONSENT *)0;
    if ((id == (char *)0) || (*id == '\000'))
	return;
    if ((inc =
	 FindParserDefaultOrConsole(parserDefaults, id)) != (CONSENT *)0) {
	ApplyDefault(inc, c);
    } else {
	if (isMaster)
	    Error("invalid default name `%s' [%s:%d]", id, file, line);
    }
}

void
#if PROTOTYPES
DefaultItemInclude(char *id)
#else
DefaultItemInclude(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemInclude(%s) [%s:%d]", id, file, line));
    ProcessInclude(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessLogfile(CONSENT *c, char *id)
#else
ProcessLogfile(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if (c->logfile != (char *)0) {
	free(c->logfile);
	c->logfile = (char *)0;
    }
    if (id == (char *)0 || id[0] == '\000') {
	return;
    }
    if ((c->logfile = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
ProcessInitcmd(CONSENT *c, char *id)
#else
ProcessInitcmd(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if (c->initcmd != (char *)0) {
	free(c->initcmd);
	c->initcmd = (char *)0;
    }
    if (id == (char *)0 || id[0] == '\000') {
	return;
    }
    if ((c->initcmd = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
ProcessMOTD(CONSENT *c, char *id)
#else
ProcessMOTD(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if (c->motd != (char *)0) {
	free(c->motd);
	c->motd = (char *)0;
    }
    if (id == (char *)0 || id[0] == '\000') {
	return;
    }
    if ((c->motd = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
DefaultItemLogfile(char *id)
#else
DefaultItemLogfile(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemLogfile(%s) [%s:%d]", id, file, line));
    ProcessLogfile(parserDefaultTemp, id);
}

void
#if PROTOTYPES
DefaultItemInitcmd(char *id)
#else
DefaultItemInitcmd(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemInitcmd(%s) [%s:%d]", id, file, line));
    ProcessInitcmd(parserDefaultTemp, id);
}

void
#if PROTOTYPES
DefaultItemMOTD(char *id)
#else
DefaultItemMOTD(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemMOTD(%s) [%s:%d]", id, file, line));
    ProcessMOTD(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessMaster(CONSENT *c, char *id)
#else
ProcessMaster(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if (c->master != (char *)0) {
	free(c->master);
	c->master = (char *)0;
    }
    if ((id == (char *)0) || (*id == '\000'))
	return;
    if ((c->master = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
DefaultItemMaster(char *id)
#else
DefaultItemMaster(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemMaster(%s) [%s:%d]", id, file, line));
    ProcessMaster(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessOptions(CONSENT *c, char *id)
#else
ProcessOptions(c, id)
    CONSENT *c;
    char *id;
#endif
{
    char *token = (char *)0;
    int negative = 0;

    if ((id == (char *)0) || (*id == '\000')) {
	c->hupcl = FLAGUNKNOWN;
	c->cstopb = FLAGUNKNOWN;
	c->ixany = FLAGUNKNOWN;
	c->ixon = FLAGUNKNOWN;
	c->ixoff = FLAGUNKNOWN;
#if defined(CRTSCTS)
	c->crtscts = FLAGUNKNOWN;
#endif
	c->ondemand = FLAGUNKNOWN;
	c->striphigh = FLAGUNKNOWN;
	c->reinitoncc = FLAGUNKNOWN;
	c->autoreinit = FLAGUNKNOWN;
	c->unloved = FLAGUNKNOWN;
	return;
    }

    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	if (token[0] == '!') {
	    negative = 1;
	    token++;
	} else {
	    negative = 0;
	}
	if (strcasecmp("hupcl", token) == 0)
	    c->hupcl = negative ? FLAGFALSE : FLAGTRUE;
	else if (strcasecmp("ixany", token) == 0)
	    c->ixany = negative ? FLAGFALSE : FLAGTRUE;
	else if (strcasecmp("ixon", token) == 0)
	    c->ixon = negative ? FLAGFALSE : FLAGTRUE;
	else if (strcasecmp("ixoff", token) == 0)
	    c->ixoff = negative ? FLAGFALSE : FLAGTRUE;
	else if (strcasecmp("cstopb", token) == 0)
	    c->cstopb = negative ? FLAGFALSE : FLAGTRUE;
#if defined(CRTSCTS)
	else if (strcasecmp("crtscts", token) == 0)
	    c->crtscts = negative ? FLAGFALSE : FLAGTRUE;
#endif
	else if (strcasecmp("ondemand", token) == 0)
	    c->ondemand = negative ? FLAGFALSE : FLAGTRUE;
	else if (strcasecmp("striphigh", token) == 0)
	    c->striphigh = negative ? FLAGFALSE : FLAGTRUE;
	else if (strcasecmp("reinitoncc", token) == 0)
	    c->reinitoncc = negative ? FLAGFALSE : FLAGTRUE;
	else if (strcasecmp("autoreinit", token) == 0)
	    c->autoreinit = negative ? FLAGFALSE : FLAGTRUE;
	else if (strcasecmp("unloved", token) == 0)
	    c->unloved = negative ? FLAGFALSE : FLAGTRUE;
	else
	    Error("invalid option `%s' [%s:%d]", token, file, line);
    }
}

void
#if PROTOTYPES
DefaultItemOptions(char *id)
#else
DefaultItemOptions(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemOptions(%s) [%s:%d]", id, file, line));
    ProcessOptions(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessParity(CONSENT *c, char *id)
#else
ProcessParity(c, id)
    CONSENT *c;
    char *id;
#endif
{
    if ((id == (char *)0) || (*id == '\000')) {
	c->parity = (PARITY *)0;
	return;
    }
    c->parity = FindParity(id);
    if (c->parity == (PARITY *)0) {
	if (isMaster)
	    Error("invalid parity type `%s' [%s:%d]", id, file, line);
    }
}

void
#if PROTOTYPES
DefaultItemParity(char *id)
#else
DefaultItemParity(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemParity(%s) [%s:%d]", id, file, line));
    ProcessParity(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessPort(CONSENT *c, char *id)
#else
ProcessPort(c, id)
    CONSENT *c;
    char *id;
#endif
{
    char *p;

    if ((id == (char *)0) || (*id == '\000')) {
	c->port = 0;
	return;
    }
    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;
    /* if it wasn't a number or the number was zero */
    if ((*p != '\000') || ((c->port = (unsigned short)atoi(id)) == 0)) {
	if (isMaster)
	    Error("invalid port number `%s' [%s:%d]", id, file, line);
	return;
    }
}

void
#if PROTOTYPES
DefaultItemPort(char *id)
#else
DefaultItemPort(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemPort(%s) [%s:%d]", id, file, line));
    ProcessPort(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessRoRw(CONSENTUSERS **ppCU, char *id)
#else
ProcessRoRw(ppCU, id)
    CONSENTUSERS **ppCU;
    char *id;
#endif
{
    char *token = (char *)0;
    PARSERGROUP *pg = (PARSERGROUP *)0;

    CONDDEBUG((1, "ProcessRoRw(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000')) {
	DestroyConsentUsers(ppCU);
	return;
    }

    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	if ((pg = GroupFind(token)) == (PARSERGROUP *)0) {
	    ConsentAddUser(ppCU, token);
	} else {
	    PARSERGROUPUSERS *pgu;
	    for (pgu = pg->users; pgu != (PARSERGROUPUSERS *)0;
		 pgu = pgu->next) {
		ConsentAddUser(ppCU, pgu->user->name);
	    }
	}
    }
}

void
#if PROTOTYPES
DefaultItemRo(char *id)
#else
DefaultItemRo(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemRo(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserDefaultTemp->ro), id);
}

void
#if PROTOTYPES
DefaultItemRw(char *id)
#else
DefaultItemRw(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemRw(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserDefaultTemp->rw), id);
}

void
#if PROTOTYPES
ProcessTimestamp(CONSENT *c, char *id)
#else
ProcessTimestamp(c, id)
    CONSENT *c;
    char *id;
#endif
{
    time_t tyme;
    char *p = (char *)0, *n = (char *)0;
    FLAG activity = FLAGFALSE, bactivity = FLAGFALSE;
    int factor = 0, pfactor = 0;
    int value = 0, pvalue = 0;

    if ((id == (char *)0) || (*id == '\000')) {
	c->breaklog = FLAGFALSE;
	c->activitylog = FLAGFALSE;
	c->nextMark = 0;
	c->mark = 0;
	return;
    }

    /* Parse the [number(m|h|d|l)[a][b]] spec */
    tyme = time((time_t *)0);

    for (p = id; *p != '\000'; p++) {
	if (*p == 'a' || *p == 'A') {
	    if (n != (char *)0) {
		if (isMaster)
		    Error
			("invalid timestamp specification `%s': numeral before `a' (ignoring numeral) [%s:%d]",
			 id, file, line);
	    }
	    activity = FLAGTRUE;
	} else if (*p == 'b' || *p == 'B') {
	    if (n != (char *)0) {
		if (isMaster)
		    Error
			("invalid timestamp specification `%s': numeral before `b' (ignoring numeral) [%s:%d]",
			 id, file, line);
	    }
	    bactivity = FLAGTRUE;
	} else if (*p == 'm' || *p == 'M') {
	    pfactor = 60;
	} else if (*p == 'h' || *p == 'H') {
	    pfactor = 60 * 60;
	} else if (*p == 'd' || *p == 'D') {
	    pfactor = 60 * 60 * 24;
	} else if (*p == 'l' || *p == 'L') {
	    pfactor = -1;
	} else if (isdigit((int)*p)) {
	    if (n == (char *)0)
		n = p;
	} else if (isspace((int)*p)) {
	    if (n != (char *)0) {
		pfactor = 60;
	    }
	} else {
	    if (isMaster)
		Error
		    ("invalid timestamp specification `%s': unknown character `%c' [%s:%d]",
		     id, *p, file, line);
	    return;
	}
	if (pfactor) {
	    if (n == (char *)0) {
		if (isMaster)
		    Error
			("invalid timestamp specification `%s': missing numeric prefix for `%c' [%s:%d]",
			 id, *p, file, line);
		return;
	    } else {
		*p = '\000';
		pvalue = atoi(n);
		if (pvalue < 0) {
		    if (isMaster)
			Error
			    ("negative timestamp specification `%s' [%s:%d]",
			     id, file, line);
		    return;
		}
		n = (char *)0;
		factor = pfactor;
		value = pvalue * pfactor;
		pvalue = pfactor = 0;
	    }
	}
    }

    if (n != (char *)0) {
	pvalue = atoi(n);
	if (pvalue < 0) {
	    if (isMaster)
		Error("negative timestamp specification `%s' [%s:%d]", id,
		      file, line);
	    return;
	}
	factor = 60;
	value = pvalue * factor;
    }

    CONDDEBUG((1,
	       "ProcessTimestamp(): mark spec of `%s' parsed: factor=%d, value=%d, activity=%d, bactivity=%d",
	       id, factor, value, activity, bactivity));

    c->activitylog = activity;
    c->breaklog = bactivity;
    if (factor && value) {
	c->mark = value;
	if (factor > 0) {
	    tyme -= (tyme % 60);	/* minute boundary */
	    if ((value <= 60 * 60 && (60 * 60) % value == 0)
		|| (value > 60 * 60 && (60 * 60 * 24) % value == 0)) {
		struct tm *tm;
		time_t now;

		/* the increment is a "nice" subdivision of an hour
		 * or a day
		 */
		now = tyme;
		if ((struct tm *)0 != (tm = localtime(&tyme))) {
		    tyme -= tm->tm_min * 60;	/* hour boundary */
		    tyme -= tm->tm_hour * 60 * 60;	/* day boundary */
		    tyme += ((now - tyme) / value) * value;
		    /* up to nice bound */
		}
	    }
	    c->nextMark = tyme + value;	/* next boundary */
	} else {
	    c->nextMark = value;
	}
    } else {
	c->nextMark = c->mark = 0;
    }
}

void
#if PROTOTYPES
DefaultItemTimestamp(char *id)
#else
DefaultItemTimestamp(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemTimestamp(%s) [%s:%d]", id, file, line));
    ProcessTimestamp(parserDefaultTemp, id);
}

void
#if PROTOTYPES
ProcessType(CONSENT *c, char *id)
#else
ProcessType(c, id)
    CONSENT *c;
    char *id;
#endif
{
    CONSTYPE t = UNKNOWN;
    if ((id == (char *)0) || (*id == '\000')) {
	c->type = t;
	return;
    }
    if (strcasecmp("device", id) == 0)
	t = DEVICE;
    else if (strcasecmp("exec", id) == 0)
	t = EXEC;
    else if (strcasecmp("host", id) == 0)
	t = HOST;
    if (t == UNKNOWN) {
	if (isMaster)
	    Error("invalid console type `%s' [%s:%d]", id, file, line);
    } else
	c->type = t;
}

void
#if PROTOTYPES
DefaultItemType(char *id)
#else
DefaultItemType(id)
    char *id;
#endif
{
    CONDDEBUG((1, "DefaultItemType(%s) [%s:%d]", id, file, line));
    ProcessType(parserDefaultTemp, id);
}

/* 'console' handling */
CONSENT *parserConsoles = (CONSENT *)0;
CONSENT **parserConsolesTail = &parserConsoles;
CONSENT *parserConsoleTemp = (CONSENT *)0;

void
#if PROTOTYPES
ConsoleBegin(char *id)
#else
ConsoleBegin(id)
    char *id;
#endif
{
    CONSENT *c;

    CONDDEBUG((1, "ConsoleBegin(%s) [%s:%d]", id, file, line));
    if (id == (char *)0 || id[0] == '\000') {
	if (isMaster)
	    Error("empty console name [%s:%d]", file, line);
	return;
    }
    if (parserConsoleTemp != (CONSENT *)0)
	DestroyParserDefaultOrConsole(parserConsoleTemp, (CONSENT **)0,
				      (CONSENT ***)0);
    if ((parserConsoleTemp = (CONSENT *)calloc(1, sizeof(CONSENT)))
	== (CONSENT *)0)
	OutOfMem();

    /* prime the pump with a default of "*" */
    if ((c =
	 FindParserDefaultOrConsole(parserDefaults,
				    "*")) != (CONSENT *)0) {
	ApplyDefault(c, parserConsoleTemp);
    }
    if ((parserConsoleTemp->server = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
ConsoleEnd(void)
#else
ConsoleEnd()
#endif
{
    int invalid = 0;

    CONSENT *c = (CONSENT *)0;

    CONDDEBUG((1, "ConsoleEnd() [%s:%d]", file, line));

    if (parserConsoleTemp->master == (char *)0) {
	if (isMaster)
	    Error("[%s] console missing 'master' attribute [%s:%d]",
		  parserConsoleTemp->server, file, line);
	invalid = 1;
    }

    switch (parserConsoleTemp->type) {
	case EXEC:
	    break;
	case DEVICE:
	    if (parserConsoleTemp->device == (char *)0) {
		if (isMaster)
		    Error
			("[%s] console missing 'device' attribute [%s:%d]",
			 parserConsoleTemp->server, file, line);
		invalid = 1;
	    }
	    if (parserConsoleTemp->baud == (BAUD *)0) {
		if (isMaster)
		    Error("[%s] console missing 'baud' attribute [%s:%d]",
			  parserConsoleTemp->server, file, line);
		invalid = 1;
	    }
	    if (parserConsoleTemp->parity == (PARITY *)0) {
		if (isMaster)
		    Error
			("[%s] console missing 'parity' attribute [%s:%d]",
			 parserConsoleTemp->server, file, line);
		invalid = 1;
	    }
	    break;
	case HOST:
	    if (parserConsoleTemp->host == (char *)0) {
		if (isMaster)
		    Error("[%s] console missing 'host' attribute [%s:%d]",
			  parserConsoleTemp->server, file, line);
		invalid = 1;
	    }
	    if (parserConsoleTemp->port == 0) {
		if (isMaster)
		    Error("[%s] console missing 'port' attribute [%s:%d]",
			  parserConsoleTemp->server, file, line);
		invalid = 1;
	    }
	    break;
	case UNKNOWN:
	    if (isMaster)
		Error("[%s] console type unknown [%s:%d]",
		      parserConsoleTemp->server, file, line);
	    invalid = 1;
	    break;
    }

    if (invalid != 0) {
	DestroyParserDefaultOrConsole(parserConsoleTemp, (CONSENT **)0,
				      (CONSENT ***)0);
	parserConsoleTemp = (CONSENT *)0;
	return;
    }

    /* if we're overriding an existing console, nuke it */
    if ((c =
	 FindParserDefaultOrConsole(parserConsoles,
				    parserConsoleTemp->server)) !=
	(CONSENT *)0) {
	if (isMaster)
	    Error("console definition for `%s' overridden [%s:%d]",
		  parserConsoleTemp->server, file, line);
	DestroyParserDefaultOrConsole(c, &parserConsoles,
				      &parserConsolesTail);
    }

    /* add the temp to the tail of the list */
    *parserConsolesTail = parserConsoleTemp;
    parserConsolesTail = &(parserConsoleTemp->pCEnext);
    parserConsoleTemp = (CONSENT *)0;
}

void
#if PROTOTYPES
ConsoleAbort(void)
#else
ConsoleAbort()
#endif
{
    CONDDEBUG((1, "ConsoleAbort() [%s:%d]", file, line));
    DestroyParserDefaultOrConsole(parserConsoleTemp, (CONSENT **)0,
				  (CONSENT ***)0);
    parserConsoleTemp = (CONSENT *)0;
}

void
#if PROTOTYPES
SwapStr(char *s1, char *s2)
#else
SwapStr(s1, s2)
    char *s1;
    char *s2;
#endif
{
    char *s;
    s = s1;
    s1 = s2;
    s2 = s;
}

void
#if PROTOTYPES
ExpandLogfile(CONSENT *c, char *id)
#else
ExpandLogfile(c, id)
    CONSENT *c;
    char *id;
#endif
{
    char *amp = (char *)0;
    char *p = (char *)0;
    char *tmp = (char *)0;

    if (id == (char *)0)
	return;
    /*
     *  Here we substitute the console name for any '&' character in the
     *  logfile name.  That way you can just have something like
     *  "/var/console/&" for each of the conserver.cf entries.
     */
    p = id;
    BuildTmpString((char *)0);
    while ((amp = strchr(p, '&')) != (char *)0) {
	*amp = '\000';
	BuildTmpString(p);
	BuildTmpString(c->server);
	p = amp + 1;
	*amp = '&';
    }
    tmp = BuildTmpString(p);
    if ((c->logfile = StrDup(tmp))
	== (char *)0)
	OutOfMem();
}

/* this will adjust parserConsoles/parserConsolesTail if we're adding
 * a new console.
 */
void
#if PROTOTYPES
ConsoleAdd(CONSENT *c)
#else
ConsoleAdd(c)
    CONSENT *c;
#endif
{
    CONSENT *pCEmatch = (CONSENT *)0;
    GRPENT *pGEmatch = (GRPENT *)0, *pGEtmp = (GRPENT *)0;
    CONSCLIENT *pCLtmp = (CONSCLIENT *)0;
    CONSENTUSERS *u;

    /* check for remote consoles */
    if (!IsMe(c->master)) {
	if (isMaster) {
	    REMOTE *pRCTemp;
	    if ((pRCTemp = (REMOTE *)calloc(1, sizeof(REMOTE)))
		== (REMOTE *)0)
		OutOfMem();
	    if ((pRCTemp->rhost = StrDup(c->master))
		== (char *)0)
		OutOfMem();
	    if ((pRCTemp->rserver = StrDup(c->server))
		== (char *)0)
		OutOfMem();
	    pRCTemp->aliases = c->aliases;
	    c->aliases = (NAMES *)0;
	    *ppRC = pRCTemp;
	    ppRC = &pRCTemp->pRCnext;
	    CONDDEBUG((1, "[%s] remote on %s", c->server, c->master));
	}
	return;
    }

    /*
     * i hope this is right:
     *   in master during startup,
     *     pGroupsOld = *empty*
     *     pGroups = filling with groups of consoles
     *     pGEstage = *empty*
     *   in master during reread,
     *     pGroupsOld = shrinking groups as they move to pGEstage
     *     pGroups = filling with groups of new consoles
     *     pGEstage = filling with groups from pGroupsOld
     *   in slave during reread,
     *     pGroupsOld = shrinking groups as they move to pGEstage
     *     pGroups = *empty*
     *     pGEstage = filling with groups from pGroupsOld
     *
     * now, pGroups in the slave during a reread may actually be
     * temporarily used to hold stuff that's moving to pGEstage.
     * in the master it might also have group stubs as well.
     * but by the end, if it has anything, it's all empty groups
     * in the slave and a mix of real (new) and empty in the master.
     */
    if (!isStartup) {
	CONSENT **ppCE;
	/* hunt for a local match, "pCEmatch != (CONSENT *)0" if found */
	pCEmatch = (CONSENT *)0;
	for (pGEmatch = pGroupsOld; pGEmatch != (GRPENT *)0;
	     pGEmatch = pGEmatch->pGEnext) {
	    for (ppCE = &pGEmatch->pCElist, pCEmatch = pGEmatch->pCElist;
		 pCEmatch != (CONSENT *)0;
		 ppCE = &pCEmatch->pCEnext, pCEmatch = pCEmatch->pCEnext) {
		if (strcasecmp(c->server, pCEmatch->server) == 0) {
		    /* extract pCEmatch from the linked list */
		    *ppCE = pCEmatch->pCEnext;
		    pGEmatch->imembers--;
		    break;
		}
	    }
	    if (pCEmatch != (CONSENT *)0)
		break;
	}

	/* we're a child and we didn't find a match, next! */
	if (!isMaster && (pCEmatch == (CONSENT *)0))
	    return;

	/* otherwise....we'll fall through and build a group with a
	 * single console.  at then end we'll do all the hard work
	 * of shuffling things around, comparing, etc.  this way we
	 * end up with the same parsed/pruned strings in the same
	 * fields and we don't have to do a lot of the same work here
	 * (especially the whitespace pruning)
	 */
    }

    /* ok, we're ready to rock and roll...first, lets make
     * sure we have a group to go in and then we'll pop
     * out a console and start filling it up
     */
    /* let's get going with a group */
    if (pGroups == (GRPENT *)0) {
	if ((pGroups = (GRPENT *)calloc(1, sizeof(GRPENT)))
	    == (GRPENT *)0)
	    OutOfMem();
	pGE = pGroups;
	pGE->pid = -1;
	pGE->id = groupID++;
    }

    /* if we've filled up the group, get another...
     */
    if (cMaxMemb == pGE->imembers) {
	if ((pGE->pGEnext = (GRPENT *)calloc(1, sizeof(GRPENT)))
	    == (GRPENT *)0)
	    OutOfMem();
	pGE = pGE->pGEnext;
	pGE->pid = -1;
	pGE->id = groupID++;
    }

    /* ok, now for the hard part of the reread */
    if (pCEmatch == (CONSENT *)0) {	/* add new console */
	CONSENT **ph = &parserConsoles;
	while (*ph != (CONSENT *)0) {
	    if (*ph == c) {
		break;
	    } else {
		ph = &((*ph)->pCEnext);
	    }
	}

	/* if we were in a chain... */
	if (*ph != (CONSENT *)0) {
	    /* unlink from the chain */
	    *ph = c->pCEnext;
	    /* and possibly fix tail ptr... */
	    if (c->pCEnext == (CONSENT *)0)
		parserConsolesTail = ph;
	}

	/* putting into action, so allocate runtime items */
	if (c->wbuf == (STRING *)0)
	    c->wbuf = AllocString();
	c->pCEnext = pGE->pCElist;
	pGE->pCElist = c;
	pGE->imembers++;
    } else {			/* pCEmatch != (CONSENT *) 0  - modify console */
	short closeMatch = 1;
	/* see if the group is already staged */
	for (pGEtmp = pGEstage; pGEtmp != (GRPENT *)0;
	     pGEtmp = pGEtmp->pGEnext) {
	    if (pGEtmp->id == pGEmatch->id)
		break;
	}

	/* if not, allocate one, copy the data, and reset things */
	if (pGEtmp == (GRPENT *)0) {
	    if ((pGEtmp =
		 (GRPENT *)calloc(1, sizeof(GRPENT))) == (GRPENT *)0)
		OutOfMem();

	    /* copy the data */
	    *pGEtmp = *pGEmatch;

	    /* don't destroy the fake console */
	    pGEmatch->pCEctl = (CONSENT *)0;

	    /* prep counters and such */
	    pGEtmp->pCElist = (CONSENT *)0;
	    pGEtmp->pCLall = (CONSCLIENT *)0;
	    pGEtmp->imembers = 0;

	    /* link in to the staging area */
	    pGEtmp->pGEnext = pGEstage;
	    pGEstage = pGEtmp;

	    /* fix the free list (the easy one) */
	    /* the ppCLbnext link needs to point to the new group */
	    if (pGEtmp->pCLfree != (CONSCLIENT *)0)
		pGEtmp->pCLfree->ppCLbnext = &pGEtmp->pCLfree;
	    pGEmatch->pCLfree = (CONSCLIENT *)0;

	    if (pGEtmp->pCEctl) {
		/* fix the half-logged in clients */
		/* the pCLscan list needs to be rebuilt */
		/* file descriptors need to be watched */
		for (pCLtmp = pGEtmp->pCEctl->pCLon;
		     pCLtmp != (CONSCLIENT *)0; pCLtmp = pCLtmp->pCLnext) {
		    /* remove cleanly from the old group */
		    if ((CONSCLIENT *)0 != pCLtmp->pCLscan) {
			pCLtmp->pCLscan->ppCLbscan = pCLtmp->ppCLbscan;
		    }
		    *(pCLtmp->ppCLbscan) = pCLtmp->pCLscan;
		    /* insert into the new group */
		    pCLtmp->pCLscan = pGEtmp->pCLall;
		    pCLtmp->ppCLbscan = &pGEtmp->pCLall;
		    if (pCLtmp->pCLscan != (CONSCLIENT *)0) {
			pCLtmp->pCLscan->ppCLbscan = &pCLtmp->pCLscan;
		    }
		    pGEtmp->pCLall = pCLtmp;
		    /* set file descriptors */
		    FD_SET(FileFDNum(pCLtmp->fd), &rinit);
		    if (maxfd < FileFDNum(pCLtmp->fd) + 1)
			maxfd = FileFDNum(pCLtmp->fd) + 1;
		    if (!FileBufEmpty(pCLtmp->fd))
			FD_SET(FileFDNum(pCLtmp->fd), &winit);
		}
	    }
	}
	/* fix the real clients */
	/* the pCLscan list needs to be rebuilt */
	/* file descriptors need to be watched */
	for (pCLtmp = pCEmatch->pCLon; pCLtmp != (CONSCLIENT *)0;
	     pCLtmp = pCLtmp->pCLnext) {
	    /* remove cleanly from the old group */
	    if ((CONSCLIENT *)0 != pCLtmp->pCLscan) {
		pCLtmp->pCLscan->ppCLbscan = pCLtmp->ppCLbscan;
	    }
	    *(pCLtmp->ppCLbscan) = pCLtmp->pCLscan;
	    /* insert into the new group */
	    pCLtmp->pCLscan = pGEtmp->pCLall;
	    pCLtmp->ppCLbscan = &pGEtmp->pCLall;
	    if (pCLtmp->pCLscan != (CONSCLIENT *)0) {
		pCLtmp->pCLscan->ppCLbscan = &pCLtmp->pCLscan;
	    }
	    pGEtmp->pCLall = pCLtmp;
	    /* set file descriptors */
	    FD_SET(FileFDNum(pCLtmp->fd), &rinit);
	    if (maxfd < FileFDNum(pCLtmp->fd) + 1)
		maxfd = FileFDNum(pCLtmp->fd) + 1;
	    if (!FileBufEmpty(pCLtmp->fd))
		FD_SET(FileFDNum(pCLtmp->fd), &winit);
	}

	/* add the original console to the new group */
	pCEmatch->pCEnext = pGEtmp->pCElist;
	pGEtmp->pCElist = pCEmatch;
	pGEtmp->imembers++;
	if (pCEmatch->cofile != (CONSFILE *)0) {
	    int cofile = FileFDNum(pCEmatch->cofile);
	    FD_SET(cofile, &rinit);
	    if (maxfd < cofile + 1)
		maxfd = cofile + 1;
	    if (!FileBufEmpty(pCEmatch->cofile))
		FD_SET(cofile, &winit);
	}
	if (pCEmatch->initfile != (CONSFILE *)0) {
	    int initfile = FileFDNum(pCEmatch->initfile);
	    FD_SET(initfile, &rinit);
	    if (maxfd < initfile + 1)
		maxfd = initfile + 1;
	    if (!FileBufEmpty(pCEmatch->initfile))
		FD_SET(FileFDOutNum(pCEmatch->initfile), &winit);
	}

	/* now check for any changes between pCEmatch & c.
	 * we can munch the pCEmatch structure 'cause ConsDown()
	 * doesn't depend on anything we touch here
	 */
	if (pCEmatch->type != c->type) {
	    pCEmatch->type = c->type;
	    closeMatch = 0;
	}
	if (pCEmatch->logfile != (char *)0 && c->logfile != (char *)0) {
	    if (strcmp(pCEmatch->logfile, c->logfile) != 0) {
		SwapStr(pCEmatch->logfile, c->logfile);
		closeMatch = 0;
	    }
	} else if (pCEmatch->logfile != (char *)0 ||
		   c->logfile != (char *)0) {
	    SwapStr(pCEmatch->logfile, c->logfile);
	    closeMatch = 0;
	}
	if (pCEmatch->initcmd != (char *)0 && c->initcmd != (char *)0) {
	    if (strcmp(pCEmatch->initcmd, c->initcmd) != 0) {
		SwapStr(pCEmatch->initcmd, c->initcmd);
		/* only trigger reinit if we're running the old command */
		if (pCEmatch->initpid != 0)
		    closeMatch = 0;
	    }
	} else if (pCEmatch->initcmd != (char *)0 ||
		   c->initcmd != (char *)0) {
	    SwapStr(pCEmatch->initcmd, c->initcmd);
	    /* only trigger reinit if we're running the old command */
	    if (pCEmatch->initpid != 0)
		closeMatch = 0;
	}

	switch (pCEmatch->type) {
	    case EXEC:
		if (pCEmatch->exec != (char *)0 && c->exec != (char *)0) {
		    if (strcmp(pCEmatch->exec, c->exec) != 0) {
			SwapStr(pCEmatch->exec, c->exec);
			closeMatch = 0;
		    }
		} else if (pCEmatch->exec != (char *)0 ||
			   c->exec != (char *)0) {
		    SwapStr(pCEmatch->exec, c->exec);
		    closeMatch = 0;
		}
		if (pCEmatch->ixany != c->ixany) {
		    pCEmatch->ixany = c->ixany;
		    closeMatch = 0;
		}
		if (pCEmatch->ixon != c->ixon) {
		    pCEmatch->ixon = c->ixon;
		    closeMatch = 0;
		}
		if (pCEmatch->ixoff != c->ixoff) {
		    pCEmatch->ixoff = c->ixoff;
		    closeMatch = 0;
		}
#if defined(CRTSCTS)
		if (pCEmatch->crtscts != c->crtscts) {
		    pCEmatch->crtscts = c->crtscts;
		    closeMatch = 0;
		}
#endif
		break;
	    case DEVICE:
		if (pCEmatch->device != (char *)0 &&
		    c->device != (char *)0) {
		    if (strcmp(pCEmatch->device, c->device) != 0) {
			SwapStr(pCEmatch->device, c->device);
			closeMatch = 0;
		    }
		} else if (pCEmatch->device != (char *)0 ||
			   c->device != (char *)0) {
		    SwapStr(pCEmatch->device, c->device);
		    closeMatch = 0;
		}
		if (pCEmatch->baud != c->baud) {
		    pCEmatch->baud = c->baud;
		    closeMatch = 0;
		}
		if (pCEmatch->parity != c->parity) {
		    pCEmatch->parity = c->parity;
		    closeMatch = 0;
		}
		if (pCEmatch->hupcl != c->hupcl) {
		    pCEmatch->hupcl = c->hupcl;
		    closeMatch = 0;
		}
		if (pCEmatch->cstopb != c->cstopb) {
		    pCEmatch->cstopb = c->cstopb;
		    closeMatch = 0;
		}
		if (pCEmatch->ixany != c->ixany) {
		    pCEmatch->ixany = c->ixany;
		    closeMatch = 0;
		}
		if (pCEmatch->ixon != c->ixon) {
		    pCEmatch->ixon = c->ixon;
		    closeMatch = 0;
		}
		if (pCEmatch->ixoff != c->ixoff) {
		    pCEmatch->ixoff = c->ixoff;
		    closeMatch = 0;
		}
#if defined(CRTSCTS)
		if (pCEmatch->crtscts != c->crtscts) {
		    pCEmatch->crtscts = c->crtscts;
		    closeMatch = 0;
		}
#endif
		break;
	    case HOST:
		if (pCEmatch->host != (char *)0 && c->host != (char *)0) {
		    if (strcasecmp(pCEmatch->host, c->host) != 0) {
			SwapStr(pCEmatch->host, c->host);
			closeMatch = 0;
		    }
		} else if (pCEmatch->host != (char *)0 ||
			   c->host != (char *)0) {
		    SwapStr(pCEmatch->host, c->host);
		    closeMatch = 0;
		}
		if (pCEmatch->port != c->port) {
		    pCEmatch->port = c->port;
		    closeMatch = 0;
		}
		break;
	    case UNKNOWN:
		break;
	}

	/* and now the rest (minus the "runtime" members - see below) */
	SwapStr(pCEmatch->motd, c->motd);
	pCEmatch->activitylog = c->activitylog;
	pCEmatch->breaklog = c->breaklog;
	pCEmatch->mark = c->mark;
	pCEmatch->nextMark = c->nextMark;
	pCEmatch->breakNum = c->breakNum;
	pCEmatch->ondemand = c->ondemand;
	pCEmatch->striphigh = c->striphigh;
	pCEmatch->reinitoncc = c->reinitoncc;
	pCEmatch->autoreinit = c->autoreinit;
	pCEmatch->unloved = c->unloved;

	/* we have to override the ro/rw lists... */
	/* so first destroy the existing (which point to freed space anyway) */
	DestroyConsentUsers(&(pCEmatch->ro));
	DestroyConsentUsers(&(pCEmatch->rw));
	/* now copy over the new stuff */
	for (u = c->ro; u != (CONSENTUSERS *)0; u = u->next) {
	    ConsentAddUser(&(pCEmatch->ro), u->user->name);
	}
	for (u = c->rw; u != (CONSENTUSERS *)0; u = u->next) {
	    ConsentAddUser(&(pCEmatch->rw), u->user->name);
	}

	/* the code above shouldn't touch any of the "runtime" members
	 * 'cause the ConsDown() code needs to be able to rely on those
	 * to shut things down.
	 */
	if (!closeMatch && !isMaster) {
	    SendClientsMsg(pCEmatch,
			   "[-- Conserver reconfigured - console reset --]\r\n");
	    ConsDown(pCEmatch, FLAGFALSE, FLAGTRUE);
	}
    }
}

void
#if PROTOTYPES
ConsoleDestroy(void)
#else
ConsoleDestroy()
#endif
{
    GRPENT **ppGE = (GRPENT **)0;
    GRPENT *pGEtmp = (GRPENT *)0;
    CONSENT *c = (CONSENT *)0;
    CONSENT *cNext = (CONSENT *)0;
    REMOTE *pRCtmp = (REMOTE *)0;

    CONDDEBUG((1, "ConsoleDestroy() [%s:%d]", file, line));

    /* move aside any existing groups */
    pGroupsOld = pGroups;
    pGroups = (GRPENT *)0;

    /* init other trackers */
    pGE = pGEstage = (GRPENT *)0;

    /* nuke the old remote consoles */
    while (pRCList != (REMOTE *)0) {
	pRCtmp = pRCList->pRCnext;
	DestroyRemoteConsole(pRCList);
	pRCList = pRCtmp;
    }
    ppRC = &pRCList;

    /* add and reconfigure consoles
     * this will potentially adjust parserConsoles/parserConsolesTail
     * so we need to peek at the pCEnext pointer ahead of time
     */
    for (c = parserConsoles; c != (CONSENT *)0; c = cNext) {
	/* time to set some defaults and fix up values */

	/* default break number */
	if (c->breakNum == 0)
	    c->breakNum = 1;

	/* go ahead and do the '&' substitution */
	if (c->logfile != (char *)0) {
	    char *lf;
	    lf = c->logfile;
	    ExpandLogfile(c, lf);
	    free(lf);
	}

	/* set the options that default true */
	if (c->autoreinit == FLAGUNKNOWN)
	    c->autoreinit = FLAGTRUE;
	if (c->ixon == FLAGUNKNOWN)
	    c->ixon = FLAGTRUE;
	if (c->ixoff == FLAGUNKNOWN) {
	    if (c->type == EXEC)
		c->ixoff = FLAGFALSE;
	    else
		c->ixoff = FLAGTRUE;
	}

	/* set the options that default false */
	if (c->activitylog == FLAGUNKNOWN)
	    c->activitylog = FLAGFALSE;
	if (c->breaklog == FLAGUNKNOWN)
	    c->breaklog = FLAGFALSE;
	if (c->hupcl == FLAGUNKNOWN)
	    c->hupcl = FLAGFALSE;
	if (c->ixany == FLAGUNKNOWN)
	    c->ixany = FLAGFALSE;
	if (c->cstopb == FLAGUNKNOWN)
	    c->cstopb = FLAGFALSE;
#if defined(CRTSCTS)
	if (c->crtscts == FLAGUNKNOWN)
	    c->crtscts = FLAGFALSE;
#endif
	if (c->ondemand == FLAGUNKNOWN)
	    c->ondemand = FLAGFALSE;
	if (c->reinitoncc == FLAGUNKNOWN)
	    c->reinitoncc = FLAGFALSE;
	if (c->striphigh == FLAGUNKNOWN)
	    c->striphigh = FLAGFALSE;
	if (c->unloved == FLAGUNKNOWN)
	    c->unloved = FLAGFALSE;

	/* now let command-line args override things */
	if (fNoautoreup)
	    c->autoreinit = FLAGFALSE;
	if (fNoinit)
	    c->ondemand = FLAGTRUE;
	if (fStrip)
	    c->striphigh = FLAGTRUE;
	if (fReopen)
	    c->reinitoncc = FLAGTRUE;
	if (fAll)
	    c->unloved = FLAGTRUE;

	/* now remember where we're headed and do the dirty work */
	cNext = c->pCEnext;
	ConsoleAdd(c);
    }

    /* go through and nuke groups (if a child or are empty) */
    for (ppGE = &pGroups; *ppGE != (GRPENT *)0;) {
	if (!isMaster || (*ppGE)->imembers == 0) {
	    pGEtmp = *ppGE;
	    *ppGE = (*ppGE)->pGEnext;
	    DestroyGroup(pGEtmp);
	} else {
	    ppGE = &((*ppGE)->pGEnext);
	}
    }
    /* now append the staged groups (old matching groups/consoles) */
    *ppGE = pGEstage;

    /* reset the trackers */
    pGE = pGEstage = (GRPENT *)0;

    /* nuke the old groups lists (non-matching groups/consoles) */
    while (pGroupsOld != (GRPENT *)0) {
	pGEtmp = pGroupsOld->pGEnext;
	DestroyGroup(pGroupsOld);
	pGroupsOld = pGEtmp;
    }

    while (parserConsoles != (CONSENT *)0)
	DestroyParserDefaultOrConsole(parserConsoles, &parserConsoles,
				      &parserConsolesTail);
    DestroyParserDefaultOrConsole(parserConsoleTemp, (CONSENT **)0,
				  (CONSENT ***)0);
    parserConsoles = parserConsoleTemp = (CONSENT *)0;

    /* here we check on the client permissions and adjust accordingly */
    if (!isMaster) {
	CONSENT *pCE = (CONSENT *)0;
	CONSCLIENT *pCL = (CONSCLIENT *)0;
	CONSCLIENT *pCLnext = (CONSCLIENT *)0;
	int access = -1;

	for (pCE = pGroups->pCElist; pCE != (CONSENT *)0;
	     pCE = pCE->pCEnext) {
	    for (pCL = pCE->pCLon; pCL != (CONSCLIENT *)0; pCL = pCLnext) {
		pCLnext = pCL->pCLnext;	/* in case we drop client */
		access = ClientAccess(pCE, pCL->username->string);
		if (access == -1) {
		    DisconnectClient(pGroups, pCL,
				     "[Conserver reconfigured - access denied]\r\n",
				     FLAGFALSE);
		    continue;
		}
		if (pCL->fro == access)
		    continue;
		pCL->fro = access;
		if (access) {
		    FileWrite(pCL->fd, FLAGFALSE,
			      "[Conserver reconfigured - r/w access removed]\r\n",
			      -1);
		    if (pCL->fwr) {
			pCL->fwr = 0;
			pCL->fwantwr = 0;
			TagLogfileAct(pCE, "%s detached",
				      pCL->acid->string);
			if (pCE->nolog) {
			    pCE->nolog = 0;
			    TagLogfile(pCE,
				       "Console logging restored (bumped)");
			}
			pCE->pCLwr = (CONSCLIENT *)0;
			FindWrite(pCE);
		    }
		} else {
		    FileWrite(pCL->fd, FLAGFALSE,
			      "[Conserver reconfigured - r/w access granted]\r\n",
			      -1);
		}
	    }
	}
    }
}

CONSENT *
#if PROTOTYPES
FindConsoleName(CONSENT *c, char *id)
#else
FindConsoleName(c, id)
    CONSENT *c;
    char *id;
#endif
{
    NAMES *a = (NAMES *)0;
    for (; c != (CONSENT *)0; c = c->pCEnext) {
	if (strcasecmp(id, c->server) == 0)
	    return c;
	for (a = c->aliases; a != (NAMES *)0; a = a->next)
	    if (strcasecmp(id, a->name) == 0)
		return c;
    }
    return c;
}

void
#if PROTOTYPES
ConsoleItemAliases(char *id)
#else
ConsoleItemAliases(id)
    char *id;
#endif
{
    char *token = (char *)0;
    NAMES *name = (NAMES *)0;
    CONSENT *c = (CONSENT *)0;

    CONDDEBUG((1, "ConsoleItemAliases(%s) [%s:%d]", id, file, line));
    if ((id == (char *)0) || (*id == '\000')) {
	while (parserConsoleTemp->aliases != (NAMES *)0) {
	    name = parserConsoleTemp->aliases->next;
	    if (parserConsoleTemp->aliases->name != (char *)0)
		free(parserConsoleTemp->aliases->name);
	    free(parserConsoleTemp->aliases);
	    parserConsoleTemp->aliases = name;
	}
	return;
    }
    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	if ((c = FindConsoleName(parserConsoles, token)) != (CONSENT *)0) {
	    if (isMaster)
		Error
		    ("alias name `%s' invalid: already in use by console `%s' [%s:%d]",
		     token, c->server, file, line);
	    continue;
	}
	if ((c =
	     FindConsoleName(parserConsoleTemp, token)) != (CONSENT *)0) {
	    if (isMaster)
		Error("alias name `%s' repeated: ignored [%s:%d]", token,
		      file, line);
	    continue;
	}
	if ((name = (NAMES *)calloc(1, sizeof(NAMES))) == (NAMES *)0)
	    OutOfMem();
	if ((name->name = StrDup(token)) == (char *)0)
	    OutOfMem();
	name->next = parserConsoleTemp->aliases;
	parserConsoleTemp->aliases = name;
    }
}

void
#if PROTOTYPES
ConsoleItemBaud(char *id)
#else
ConsoleItemBaud(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemBaud(%s) [%s:%d]", id, file, line));
    ProcessBaud(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemBreak(char *id)
#else
ConsoleItemBreak(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemBreak(%s) [%s:%d]", id, file, line));
    ProcessBreak(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemDevice(char *id)
#else
ConsoleItemDevice(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemDevice(%s) [%s:%d]", id, file, line));
    ProcessDevice(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemExec(char *id)
#else
ConsoleItemExec(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemExec(%s) [%s:%d]", id, file, line));
    ProcessExec(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemFlow(char *id)
#else
ConsoleItemFlow(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemFlow(%s) [%s:%d]", id, file, line));
    ProcessFlow(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemHost(char *id)
#else
ConsoleItemHost(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemHost(%s) [%s:%d]", id, file, line));
    ProcessHost(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemInclude(char *id)
#else
ConsoleItemInclude(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemInclude(%s) [%s:%d]", id, file, line));
    ProcessInclude(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemLogfile(char *id)
#else
ConsoleItemLogfile(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemLogfile(%s) [%s:%d]", id, file, line));
    ProcessLogfile(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemInitcmd(char *id)
#else
ConsoleItemInitcmd(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemInitcmd(%s) [%s:%d]", id, file, line));
    ProcessInitcmd(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemMOTD(char *id)
#else
ConsoleItemMOTD(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemMOTD(%s) [%s:%d]", id, file, line));
    ProcessMOTD(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemMaster(char *id)
#else
ConsoleItemMaster(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemMaster(%s) [%s:%d]", id, file, line));
    ProcessMaster(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemOptions(char *id)
#else
ConsoleItemOptions(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemOptions(%s) [%s:%d]", id, file, line));
    ProcessOptions(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemParity(char *id)
#else
ConsoleItemParity(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemParity(%s) [%s:%d]", id, file, line));
    ProcessParity(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemPort(char *id)
#else
ConsoleItemPort(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemPort(%s) [%s:%d]", id, file, line));
    ProcessPort(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemRo(char *id)
#else
ConsoleItemRo(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemRo(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserConsoleTemp->ro), id);
}

void
#if PROTOTYPES
ConsoleItemRw(char *id)
#else
ConsoleItemRw(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemRw(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserConsoleTemp->rw), id);
}

void
#if PROTOTYPES
ConsoleItemTimestamp(char *id)
#else
ConsoleItemTimestamp(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemTimestamp(%s) [%s:%d]", id, file, line));
    ProcessTimestamp(parserConsoleTemp, id);
}

void
#if PROTOTYPES
ConsoleItemType(char *id)
#else
ConsoleItemType(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConsoleItemType(%s) [%s:%d]", id, file, line));
    ProcessType(parserConsoleTemp, id);
}

/* 'access' handling */
typedef struct parserAccess {
    STRING *name;
    ACCESS *access;
    CONSENTUSERS *admin;
    struct parserAccess *next;
} PARSERACCESS;

PARSERACCESS *parserAccesses = (PARSERACCESS *)0;
PARSERACCESS **parserAccessesTail = &parserAccesses;
PARSERACCESS *parserAccessTemp = (PARSERACCESS *)0;

void
#if PROTOTYPES
DestroyParserAccess(PARSERACCESS *pa)
#else
DestroyParserAccess(pa)
    PARSERACCESS *pa;
#endif
{
    PARSERACCESS **ppa = &parserAccesses;
    ACCESS *a = (ACCESS *)0;
    char *m = (char *)0;

    if (pa == (PARSERACCESS *)0)
	return;

    while (*ppa != (PARSERACCESS *)0) {
	if (*ppa == pa) {
	    break;
	} else {
	    ppa = &((*ppa)->next);
	}
    }

    BuildTmpString((char *)0);
    m = BuildTmpString(pa->name->string);
    /* if we were in a chain... */
    if (*ppa != (PARSERACCESS *)0) {
	/* unlink from the chain */
	*ppa = pa->next;
	/* and possibly fix tail ptr... */
	if (pa->next == (PARSERACCESS *)0)
	    parserAccessesTail = ppa;
    }
    DestroyString(pa->name);
    for (a = pa->access; a != (ACCESS *)0;) {
	ACCESS *n = a->pACnext;
	BuildTmpStringChar(',');
	m = BuildTmpString(a->pcwho);
	DestroyAccessList(a);
	a = n;
    }
    DestroyConsentUsers(&(pa->admin));
    free(pa);
    CONDDEBUG((2, "DestroyParserAccess(): %s", m));
}

PARSERACCESS *
#if PROTOTYPES
AccessFind(char *id)
#else
AccessFind(id)
    char *id;
#endif
{
    PARSERACCESS *pa;
    for (pa = parserAccesses; pa != (PARSERACCESS *)0; pa = pa->next) {
	if (strcasecmp(id, pa->name->string) == 0)
	    return pa;
    }
    return pa;
}

void
#if PROTOTYPES
AccessAddACL(PARSERACCESS *pa, ACCESS *access)
#else
AccessAddACL(pa, access)
    PARSERACCESS *pa;
    ACCESS *access;
#endif
{
    ACCESS **ppa = (ACCESS **)0;
    ACCESS *new = (ACCESS *)0;

    for (ppa = &(pa->access); *ppa != (ACCESS *)0;
	 ppa = &((*ppa)->pACnext)) {
	if ((*ppa)->ctrust == access->ctrust &&
	    (*ppa)->isCIDR == access->isCIDR &&
	    strcasecmp((*ppa)->pcwho, access->pcwho) == 0) {
	    return;
	}
    }

    if ((new = (ACCESS *)calloc(1, sizeof(ACCESS)))
	== (ACCESS *)0)
	OutOfMem();
    *new = *access;
    if ((new->pcwho = StrDup(access->pcwho))
	== (char *)0)
	OutOfMem();
    /* link into the list at the end */
    new->pACnext = (ACCESS *)0;
    *ppa = new;
}

void
#if PROTOTYPES
AccessBegin(char *id)
#else
AccessBegin(id)
    char *id;
#endif
{
    CONDDEBUG((1, "AccessBegin(%s) [%s:%d]", id, file, line));
    if (id == (char *)0 || id[0] == '\000') {
	if (isMaster)
	    Error("empty access name [%s:%d]", file, line);
	return;
    }
    if (parserAccessTemp != (PARSERACCESS *)0)
	DestroyParserAccess(parserAccessTemp);
    if ((parserAccessTemp =
	 (PARSERACCESS *)calloc(1, sizeof(PARSERACCESS)))
	== (PARSERACCESS *)0)
	OutOfMem();
    parserAccessTemp->name = AllocString();
    BuildString(id, parserAccessTemp->name);
}

void
#if PROTOTYPES
AccessEnd(void)
#else
AccessEnd()
#endif
{
    PARSERACCESS *pa = (PARSERACCESS *)0;

    CONDDEBUG((1, "AccessEnd() [%s:%d]", file, line));

    if (parserAccessTemp->name->used <= 1) {
	DestroyParserAccess(parserAccessTemp);
	parserAccessTemp = (PARSERACCESS *)0;
	return;
    }

    /* if we're overriding an existing group, nuke it */
    if ((pa =
	 AccessFind(parserAccessTemp->name->string)) !=
	(PARSERACCESS *)0) {
	DestroyParserAccess(pa);
    }

    /* add the temp to the tail of the list */
    *parserAccessesTail = parserAccessTemp;
    parserAccessesTail = &(parserAccessTemp->next);
    parserAccessTemp = (PARSERACCESS *)0;
}

void
#if PROTOTYPES
AccessAbort(void)
#else
AccessAbort()
#endif
{
    CONDDEBUG((1, "AccessAbort() [%s:%d]", file, line));
    DestroyParserAccess(parserAccessTemp);
    parserAccessTemp = (PARSERACCESS *)0;
}

void
#if PROTOTYPES
AccessDestroy(void)
#else
AccessDestroy()
#endif
{
    ACCESS *a;
    PARSERACCESS *p;
    ACCESS **ppa;
    CONSENTUSERS **pad;

    CONDDEBUG((1, "AccessDestroy() [%s:%d]", file, line));

    /* clean out the access restrictions */
    while (pACList != (ACCESS *)0) {
	a = pACList->pACnext;
	DestroyAccessList(pACList);
	pACList = a;
    }
    pACList = (ACCESS *)0;

    DestroyConsentUsers(&(pADList));
    pADList = (CONSENTUSERS *)0;

    ppa = &(pACList);
    pad = &(pADList);

    for (p = parserAccesses; p != (PARSERACCESS *)0; p = p->next) {
#if DUMPDATA
	Msg("ParserAccess = %s", p->name->string);
	for (a = p->access; a != (ACCESS *)0; a = a->pACnext) {
	    Msg("    Access = %c, %d, %s", a->ctrust, a->isCIDR, a->pcwho);
	}
	{
	    CONSENTUSERS *u;
	    for (u = p->admin; u != (CONSENTUSERS *)0; u = u->next) {
		Msg("    Admin = %s", u->user->name);
	    }
	}
#endif
	if ((p->name->used == 2 && p->name->string[0] == '*') ||
	    IsMe(p->name->string)) {
	    CONDDEBUG((1, "AccessDestroy(): adding ACL `%s'",
		       p->name->string));
	    *ppa = p->access;
	    p->access = (ACCESS *)0;
	    /* add any admin users to the list */
	    if (p->admin != (CONSENTUSERS *)0) {
		*pad = p->admin;
		p->admin = (CONSENTUSERS *)0;
	    }

	    /* advance to the end of the list so we can append more 
	     * this will potentially have duplicates in the access
	     * list, but since we're using the first seen, it's more
	     * overhead, but no big deal
	     */
	    while (*ppa != (ACCESS *)0) {
		ppa = &((*ppa)->pACnext);
	    }
	    while (*pad != (CONSENTUSERS *)0) {
		pad = &((*pad)->next);
	    }
	}
    }

    while (parserAccesses != (PARSERACCESS *)0)
	DestroyParserAccess(parserAccesses);
    DestroyParserAccess(parserAccessTemp);
    parserAccesses = parserAccessTemp = (PARSERACCESS *)0;
}

void
#if PROTOTYPES
AccessItemAdmin(char *id)
#else
AccessItemAdmin(id)
    char *id;
#endif
{
    CONDDEBUG((1, "AccessItemAdmin(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserAccessTemp->admin), id);
}

void
#if PROTOTYPES
AccessItemInclude(char *id)
#else
AccessItemInclude(id)
    char *id;
#endif
{
    char *token = (char *)0;
    PARSERACCESS *pa = (PARSERACCESS *)0;

    CONDDEBUG((1, "AccessItemInclude(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000'))
	return;

    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	if ((pa = AccessFind(token)) == (PARSERACCESS *)0) {
	    if (isMaster)
		Error("unknown access name `%s' [%s:%d]", token, file,
		      line);
	} else {
	    ACCESS *a;
	    for (a = pa->access; a != (ACCESS *)0; a = a->pACnext) {
		AccessAddACL(parserAccessTemp, a);
	    }
	    if (pa->admin != (CONSENTUSERS *)0) {
		CONSENTUSERS *u;
		for (u = pa->admin; u != (CONSENTUSERS *)0; u = u->next) {
		    ConsentAddUser(&(parserAccessTemp->admin),
				   u->user->name);
		}
	    }
	}
    }
}

void
#if PROTOTYPES
AccessProcessACL(char trust, char *acl)
#else
AccessProcessACL(trust, acl)
    char trust;
    char *acl;
#endif
{
    char *token = (char *)0;
    ACCESS **ppa = (ACCESS **)0;
    ACCESS *pa = (ACCESS *)0;
    in_addr_t addr;
#if HAVE_INET_ATON
    struct in_addr inetaddr;
#endif

    /* an empty acl will clear out that type of acl */
    if ((acl == (char *)0) || (*acl == '\000')) {
	/* move the old access list aside */
	ACCESS *a = parserAccessTemp->access;
	parserAccessTemp->access = (ACCESS *)0;
	/* go through the access list */
	while (a != (ACCESS *)0) {
	    ACCESS *n = a->pACnext;
	    /* if it's not the trust that we see, add it back */
	    if (a->ctrust != trust)
		AccessAddACL(parserAccessTemp, a);
	    /* destroy the old one */
	    DestroyAccessList(a);
	    a = n;
	}
    }

    for (token = strtok(acl, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	int i = 0, isCIDR = 0;
	int nCount = 0, dCount = 0, sCount = 0, mCount = 0, sPos = 0;
	/* Scan for [0-9./], and stop if you find something else */
	for (i = 0; token[i] != '\000'; i++) {
	    if (isdigit((int)(token[i]))) {
		/* count up digits before and after the slash */
		if (sCount)
		    nCount++;
		else
		    mCount++;
	    } else if (token[i] == '/') {
		sCount++;
		sPos = i;
	    } else if (token[i] == '.') {
		/* if we see non-digits after the slash, cause error */
		if (sCount)
		    dCount += 10;
		dCount++;
	    } else
		break;
	}
	if (token[i] == '\000') {
	    /* assuming CIDR notation */
	    if (dCount == 3 &&
		((sCount == 1 && nCount > 0) ||
		 (sCount == 0 && nCount == 0))) {
		if (sCount == 1) {
		    int mask = atoi(&(token[sPos + 1]));
		    if (mask < 0 || mask > 255) {
			goto cidrerror;
		    }
		    token[sPos] = '\000';
		}
#if HAVE_INET_ATON
		if (inet_aton(token, &inetaddr) == 0)
		    goto cidrerror;
		addr = inetaddr.s_addr;
#else
		addr = inet_addr(token);
		if (addr == (in_addr_t) (-1))
		    goto cidrerror;
#endif
		if (sCount == 1) {
		    token[sPos] = '/';
		}
	    } else {
	      cidrerror:
		if (isMaster)
		    Error("invalid ACL CIDR notation `%s' [%s:%d]", token,
			  file, line);
		return;
	    }
	    isCIDR = 1;
	}

	/* ok...either a hostname or CIDR notation */
	if ((pa = (ACCESS *)calloc(1, sizeof(ACCESS)))
	    == (ACCESS *)0)
	    OutOfMem();
	pa->ctrust = trust;
	pa->isCIDR = isCIDR;
	if ((pa->pcwho = StrDup(token))
	    == (char *)0)
	    OutOfMem();

	for (ppa = &(parserAccessTemp->access); *ppa != (ACCESS *)0;
	     ppa = &((*ppa)->pACnext)) {
	    if ((*ppa)->ctrust == pa->ctrust &&
		(*ppa)->isCIDR == pa->isCIDR &&
		strcasecmp((*ppa)->pcwho, pa->pcwho) == 0) {
		/* already exists, so skip it */
		DestroyAccessList(pa);
		return;
	    }
	}
	*ppa = pa;		/* add to end of list */
    }
}

void
#if PROTOTYPES
AccessItemAllowed(char *id)
#else
AccessItemAllowed(id)
    char *id;
#endif
{
    CONDDEBUG((1, "AccessItemAllowed(%s) [%s:%d]", id, file, line));
    AccessProcessACL('a', id);
}

void
#if PROTOTYPES
AccessItemRejected(char *id)
#else
AccessItemRejected(id)
    char *id;
#endif
{
    CONDDEBUG((1, "AccessItemRejected(%s) [%s:%d]", id, file, line));
    AccessProcessACL('r', id);
}

void
#if PROTOTYPES
AccessItemTrusted(char *id)
#else
AccessItemTrusted(id)
    char *id;
#endif
{
    CONDDEBUG((1, "AccessItemTrusted(%s) [%s:%d]", id, file, line));
    AccessProcessACL('t', id);
}

/* 'config' handling */
CONFIG *parserConfigTemp = (CONFIG *)0;

void
#if PROTOTYPES
DestroyConfig(CONFIG *c)
#else
DestroyConfig(c)
    CONFIG *c;
#endif
{
    if (c == (CONFIG *)0)
	return;
    if (c->logfile != (char *)0)
	free(c->logfile);
    if (c->initcmd != (char *)0)
	free(c->initcmd);
    if (c->motd != (char *)0)
	free(c->motd);
    if (c->passwdfile != (char *)0)
	free(c->passwdfile);
    if (c->primaryport != (char *)0)
	free(c->primaryport);
    if (c->secondaryport != (char *)0)
	free(c->secondaryport);
#if HAVE_OPENSSL
    if (c->sslcredentials != (char *)0)
	free(c->sslcredentials);
#endif
    free(c);
}

void
#if PROTOTYPES
ConfigBegin(char *id)
#else
ConfigBegin(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigBegin(%s) [%s:%d]", id, file, line));
    if (id == (char *)0 || id[0] == '\000') {
	if (isMaster)
	    Error("empty config name [%s:%d]", file, line);
	return;
    }
    if (parserConfigTemp != (CONFIG *)0)
	DestroyConfig(parserConfigTemp);
    if ((parserConfigTemp = (CONFIG *)calloc(1, sizeof(CONFIG)))
	== (CONFIG *)0)
	OutOfMem();
    parserConfigTemp->name = AllocString();
    BuildString(id, parserConfigTemp->name);
}

void
#if PROTOTYPES
ConfigEnd(void)
#else
ConfigEnd()
#endif
{
    CONDDEBUG((1, "ConfigEnd() [%s:%d]", file, line));

    if (parserConfigTemp == (CONFIG *)0)
	return;

    if (parserConfigTemp->name->used > 1) {
	if ((parserConfigTemp->name->string[0] == '*' &&
	     parserConfigTemp->name->string[1] == '\000') ||
	    IsMe(parserConfigTemp->name->string)) {
	    /* go through and copy over any items seen */
	    if (parserConfigTemp->logfile != (char *)0) {
		if (pConfig->logfile != (char *)0)
		    free(pConfig->logfile);
		pConfig->logfile = parserConfigTemp->logfile;
		parserConfigTemp->logfile = (char *)0;
	    }
	    if (parserConfigTemp->initcmd != (char *)0) {
		if (pConfig->initcmd != (char *)0)
		    free(pConfig->initcmd);
		pConfig->initcmd = parserConfigTemp->initcmd;
		parserConfigTemp->initcmd = (char *)0;
	    }
	    if (parserConfigTemp->motd != (char *)0) {
		if (pConfig->motd != (char *)0)
		    free(pConfig->motd);
		pConfig->motd = parserConfigTemp->motd;
		parserConfigTemp->motd = (char *)0;
	    }
	    if (parserConfigTemp->passwdfile != (char *)0) {
		if (pConfig->passwdfile != (char *)0)
		    free(pConfig->passwdfile);
		pConfig->passwdfile = parserConfigTemp->passwdfile;
		parserConfigTemp->passwdfile = (char *)0;
	    }
	    if (parserConfigTemp->primaryport != (char *)0) {
		if (pConfig->primaryport != (char *)0)
		    free(pConfig->primaryport);
		pConfig->primaryport = parserConfigTemp->primaryport;
		parserConfigTemp->primaryport = (char *)0;
	    }
	    if (parserConfigTemp->defaultaccess != '\000')
		pConfig->defaultaccess = parserConfigTemp->defaultaccess;
	    if (parserConfigTemp->daemonmode != FLAGUNKNOWN)
		pConfig->daemonmode = parserConfigTemp->daemonmode;
	    if (parserConfigTemp->redirect != FLAGUNKNOWN)
		pConfig->redirect = parserConfigTemp->redirect;
	    if (parserConfigTemp->reinitcheck != 0)
		pConfig->reinitcheck = parserConfigTemp->reinitcheck;
	    if (parserConfigTemp->secondaryport != (char *)0) {
		if (pConfig->secondaryport != (char *)0)
		    free(pConfig->secondaryport);
		pConfig->secondaryport = parserConfigTemp->secondaryport;
		parserConfigTemp->secondaryport = (char *)0;
	    }
#if HAVE_OPENSSL
	    if (parserConfigTemp->sslcredentials != (char *)0) {
		if (pConfig->sslcredentials != (char *)0)
		    free(pConfig->sslcredentials);
		pConfig->sslcredentials = parserConfigTemp->sslcredentials;
		parserConfigTemp->sslcredentials = (char *)0;
	    }
	    if (parserConfigTemp->sslrequired != FLAGUNKNOWN)
		pConfig->sslrequired = parserConfigTemp->sslrequired;
#endif
	}
    }

    DestroyConfig(parserConfigTemp);
    parserConfigTemp = (CONFIG *)0;
}

void
#if PROTOTYPES
ConfigAbort(void)
#else
ConfigAbort()
#endif
{
    CONDDEBUG((1, "ConfigAbort() [%s:%d]", file, line));
    if (parserConfigTemp == (CONFIG *)0)
	return;

    DestroyConfig(parserConfigTemp);
    parserConfigTemp = (CONFIG *)0;
}

void
#if PROTOTYPES
ConfigDestroy(void)
#else
ConfigDestroy()
#endif
{
    CONDDEBUG((1, "ConfigDestroy() [%s:%d]", file, line));
    if (parserConfigTemp == (CONFIG *)0)
	return;

    DestroyConfig(parserConfigTemp);
    parserConfigTemp = (CONFIG *)0;
}

void
#if PROTOTYPES
ConfigItemDefaultaccess(char *id)
#else
ConfigItemDefaultaccess(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigItemDefaultaccess(%s) [%s:%d]", id, file, line));

    if (id == (char *)0 || id[0] == '\000') {
	parserConfigTemp->defaultaccess = '\000';
	return;
    }
    if (strcasecmp("allowed", id) == 0)
	parserConfigTemp->defaultaccess = 'a';
    else if (strcasecmp("rejected", id) == 0)
	parserConfigTemp->defaultaccess = 'r';
    else if (strcasecmp("trusted", id) == 0)
	parserConfigTemp->defaultaccess = 't';
    else {
	if (isMaster)
	    Error("invalid access type `%s' [%s:%d]", id, file, line);
    }
}

void
#if PROTOTYPES
ProcessYesNo(char *id, FLAG *flag)
#else
ProcessYesNo(id, flag)
    char *id;
    FLAG *flag;
#endif
{
    if (id == (char *)0 || id[0] == '\000')
	*flag = FLAGFALSE;
    else if (strcasecmp("yes", id) == 0 || strcasecmp("true", id) == 0 ||
	     strcasecmp("on", id) == 0)
	*flag = FLAGTRUE;
    else if (strcasecmp("no", id) == 0 || strcasecmp("false", id) == 0 ||
	     strcasecmp("off", id) == 0)
	*flag = FLAGFALSE;
}

void
#if PROTOTYPES
ConfigItemDaemonmode(char *id)
#else
ConfigItemDaemonmode(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigItemDaemonmode(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserConfigTemp->daemonmode));
}

void
#if PROTOTYPES
ConfigItemLogfile(char *id)
#else
ConfigItemLogfile(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigItemLogfile(%s) [%s:%d]", id, file, line));
    if ((id == (char *)0) || (*id == '\000')) {
	if (parserConfigTemp->logfile != (char *)0) {
	    free(parserConfigTemp->logfile);
	    parserConfigTemp->logfile = (char *)0;
	}
	return;
    }
    if ((parserConfigTemp->logfile = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
ConfigItemPasswordfile(char *id)
#else
ConfigItemPasswordfile(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigItemPasswordfile(%s) [%s:%d]", id, file, line));
    if ((id == (char *)0) || (*id == '\000')) {
	if (parserConfigTemp->passwdfile != (char *)0) {
	    free(parserConfigTemp->passwdfile);
	    parserConfigTemp->passwdfile = (char *)0;
	}
	return;
    }
    if ((parserConfigTemp->passwdfile = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
ConfigItemPrimaryport(char *id)
#else
ConfigItemPrimaryport(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigItemPrimaryport(%s) [%s:%d]", id, file, line));
    if ((id == (char *)0) || (*id == '\000')) {
	if (parserConfigTemp->primaryport != (char *)0) {
	    free(parserConfigTemp->primaryport);
	    parserConfigTemp->primaryport = (char *)0;
	}
	return;
    }
    if ((parserConfigTemp->primaryport = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
ConfigItemRedirect(char *id)
#else
ConfigItemRedirect(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigItemRedirect(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserConfigTemp->redirect));
}

void
#if PROTOTYPES
ConfigItemReinitcheck(char *id)
#else
ConfigItemReinitcheck(id)
    char *id;
#endif
{
    char *p;

    CONDDEBUG((1, "ConfigItemReinitcheck(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->reinitcheck = 0;
	return;
    }

    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;

    /* if it wasn't a number or the number was zero */
    if (*p != '\000') {
	if (isMaster)
	    Error("invalid reinitcheck value `%s' [%s:%d]", id, file,
		  line);
	return;
    }
    parserConfigTemp->reinitcheck = atoi(id);
}

void
#if PROTOTYPES
ConfigItemSecondaryport(char *id)
#else
ConfigItemSecondaryport(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigItemSecondaryport(%s) [%s:%d]", id, file, line));
    if ((id == (char *)0) || (*id == '\000')) {
	if (parserConfigTemp->secondaryport != (char *)0) {
	    free(parserConfigTemp->secondaryport);
	    parserConfigTemp->secondaryport = (char *)0;
	}
	return;
    }
    if ((parserConfigTemp->secondaryport = StrDup(id))
	== (char *)0)
	OutOfMem();
}

#if HAVE_OPENSSL
void
#if PROTOTYPES
ConfigItemSslcredentials(char *id)
#else
ConfigItemSslcredentials(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigItemSslcredentials(%s) [%s:%d]", id, file, line));
    if ((id == (char *)0) || (*id == '\000')) {
	if (parserConfigTemp->sslcredentials != (char *)0) {
	    free(parserConfigTemp->sslcredentials);
	    parserConfigTemp->sslcredentials = (char *)0;
	}
	return;
    }
    if ((parserConfigTemp->sslcredentials = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
#if PROTOTYPES
ConfigItemSslrequired(char *id)
#else
ConfigItemSslrequired(id)
    char *id;
#endif
{
    CONDDEBUG((1, "ConfigItemSslrequired(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserConfigTemp->sslrequired));
}
#endif

/* now all the real nitty-gritty bits for making things work */
ITEM keyBreak[] = {
    {"string", BreakItemString},
    {"delay", BreakItemDelay},
    {(char *)0, (void *)0}
};

ITEM keyGroup[] = {
    {"users", GroupItemUsers},
    {(char *)0, (void *)0}
};

ITEM keyDefault[] = {
    {"baud", DefaultItemBaud},
    {"break", DefaultItemBreak},
    {"device", DefaultItemDevice},
    {"exec", DefaultItemExec},
/*  {"flow", DefaultItemFlow}, */
    {"host", DefaultItemHost},
    {"include", DefaultItemInclude},
    {"initcmd", DefaultItemInitcmd},
    {"logfile", DefaultItemLogfile},
    {"master", DefaultItemMaster},
    {"motd", DefaultItemMOTD},
    {"options", DefaultItemOptions},
    {"parity", DefaultItemParity},
    {"port", DefaultItemPort},
    {"ro", DefaultItemRo},
    {"rw", DefaultItemRw},
    {"timestamp", DefaultItemTimestamp},
    {"type", DefaultItemType},
    {(char *)0, (void *)0}
};

ITEM keyConsole[] = {
    {"aliases", ConsoleItemAliases},
    {"baud", ConsoleItemBaud},
    {"break", ConsoleItemBreak},
    {"device", ConsoleItemDevice},
    {"exec", ConsoleItemExec},
/*  {"flow", ConsoleItemFlow}, */
    {"host", ConsoleItemHost},
    {"include", ConsoleItemInclude},
    {"initcmd", ConsoleItemInitcmd},
    {"logfile", ConsoleItemLogfile},
    {"master", ConsoleItemMaster},
    {"motd", ConsoleItemMOTD},
    {"options", ConsoleItemOptions},
    {"parity", ConsoleItemParity},
    {"port", ConsoleItemPort},
    {"ro", ConsoleItemRo},
    {"rw", ConsoleItemRw},
    {"timestamp", ConsoleItemTimestamp},
    {"type", ConsoleItemType},
    {(char *)0, (void *)0}
};

ITEM keyAccess[] = {
    {"admin", AccessItemAdmin},
    {"allowed", AccessItemAllowed},
    {"include", AccessItemInclude},
    {"rejected", AccessItemRejected},
    {"trusted", AccessItemTrusted},
    {(char *)0, (void *)0}
};

ITEM keyConfig[] = {
    {"defaultaccess", ConfigItemDefaultaccess},
    {"daemonmode", ConfigItemDaemonmode},
    {"logfile", ConfigItemLogfile},
    {"passwdfile", ConfigItemPasswordfile},
    {"primaryport", ConfigItemPrimaryport},
    {"redirect", ConfigItemRedirect},
    {"reinitcheck", ConfigItemReinitcheck},
    {"secondaryport", ConfigItemSecondaryport},
#if HAVE_OPENSSL
    {"sslcredentials", ConfigItemSslcredentials},
    {"sslrequired", ConfigItemSslrequired},
#endif
    {(char *)0, (void *)0}
};

SECTION sections[] = {
    {"break", BreakBegin, BreakEnd, BreakAbort, BreakDestroy, keyBreak},
    {"group", GroupBegin, GroupEnd, GroupAbort, GroupDestroy, keyGroup},
    {"default", DefaultBegin, DefaultEnd, DefaultAbort, DefaultDestroy,
     keyDefault},
    {"console", ConsoleBegin, ConsoleEnd, ConsoleAbort, ConsoleDestroy,
     keyConsole},
    {"access", AccessBegin, AccessEnd, AccessAbort, AccessDestroy,
     keyAccess},
    {"config", ConfigBegin, ConfigEnd, ConfigAbort, ConfigDestroy,
     keyConfig},
    {(char *)0, (void *)0, (void *)0, (void *)0, (void *)0}
};

/* the format of the file should be as follows
 *
 * <section keyword> [section name] {
 *      <item keyword> [item value];
 *                   .
 *                   .
 * }
 *
 * whitespace gets retained in [section name], and [item value]
 * values.  for example,
 *
 *    users  bryan  todd ;
 *
 *  will give users the value of 'bryan  todd'.  the leading and
 *  trailing whitespace is nuked, but the middle stuff isn't.
 *
 *  a little note about the 'state' var...
 *      START = before <section keyword>
 *      NAME = before [section name]
 *      LEFTB = before left curly brace
 *      KEY = before <item keyword>
 *      VALUE = before [item value]
 *      SEMI = before semi-colon
 */

typedef enum states {
    START,
    NAME,
    LEFTB,
    KEY,
    VALUE,
    SEMI
} STATES;

typedef enum tokens {
    DONE,
    LEFTBRACE,
    RIGHTBRACE,
    SEMICOLON,
    WORD
} TOKEN;

TOKEN
#if PROTOTYPES
GetWord(FILE *fp, int *line, short spaceok, STRING *word)
#else
GetWord(fp, line, spaceok, word)
    FILE *fp;
    int *line;
    short spaceok;
    STRING *word;
#endif
{
    int c;
    short backslash = 0;
    short quote = 0;
    short comment = 0;
    short sawQuote = 0;
    short quotedBackslash = 0;

    BuildString((char *)0, word);
    while ((c = fgetc(fp)) != EOF) {
	if (c == '\n')
	    (*line)++;
	if (comment) {
	    if (c == '\n')
		comment = 0;
	    continue;
	}
	if (backslash) {
	    BuildStringChar(c, word);
	    backslash = 0;
	    continue;
	}
	if (quote) {
	    if (c == '"') {
		if (quotedBackslash) {
		    BuildStringChar(c, word);
		    quotedBackslash = 0;
		} else
		    quote = 0;
	    } else {
		if (quotedBackslash) {
		    BuildStringChar('\\', word);
		    quotedBackslash = 0;
		}
		if (c == '\\')
		    quotedBackslash = 1;
		else
		    BuildStringChar(c, word);
	    }
	    continue;
	}
	if (c == '\\') {
	    backslash = 1;
	} else if (c == '#') {
	    comment = 1;
	} else if (c == '"') {
	    quote = 1;
	    sawQuote = 1;
	} else if (isspace(c)) {
	    if (word->used <= 1)
		continue;
	    if (spaceok) {
		BuildStringChar(c, word);
		continue;
	    }
	  gotword:
	    while (word->used > 1 &&
		   isspace((int)(word->string[word->used - 2])))
		word->used--;
	    if (word->used > 0)
		word->string[word->used - 1] = '\000';
	    return WORD;
	} else if (c == '{') {
	    if (word->used <= 1 && !sawQuote) {
		BuildStringChar(c, word);
		return LEFTBRACE;
	    } else {
		ungetc(c, fp);
		goto gotword;
	    }
	} else if (c == '}') {
	    if (word->used <= 1 && !sawQuote) {
		BuildStringChar(c, word);
		return RIGHTBRACE;
	    } else {
		ungetc(c, fp);
		goto gotword;
	    }
	} else if (c == ';') {
	    if (word->used <= 1 && !sawQuote) {
		BuildStringChar(c, word);
		return SEMICOLON;
	    } else {
		ungetc(c, fp);
		goto gotword;
	    }
	} else {
	    BuildStringChar(c, word);
	}
    }
    /* this should only happen in rare cases */
    if (quotedBackslash) {
	BuildStringChar('\\', word);
	quotedBackslash = 0;
    }
    /* if we saw "valid" data, it's a word */
    if (word->used > 1 || sawQuote)
	goto gotword;
    return DONE;
}

void
#if PROTOTYPES
ReadCfg(char *filename, FILE *fp)
#else
ReadCfg(filename, fp)
    char *filename;
    FILE *fp;
#endif
{
    static STRING *word = (STRING *)0;
    STATES state = START;
    int secIndex = 0;
    int keyIndex = 0;
    TOKEN token = DONE;
    short spaceok = 0;
    char *p;
    int nextline = 1;		/* "next" line number */
    int i;
#if HAVE_DMALLOC && DMALLOC_MARK_READCFG
    unsigned long dmallocMarkReadCfg = 0;
#endif

#if HAVE_DMALLOC && DMALLOC_MARK_READCFG
    dmallocMarkReadCfg = dmalloc_mark();
#endif
    isStartup = (pGroups == (GRPENT *)0 && pRCList == (REMOTE *)0);

    /* inititalize local things */
    if (word == (STRING *)0)
	word = AllocString();
    line = 1;
    file = filename;

    /* initialize the break lists */
    for (i = 0; i < 9; i++) {
	if (breakList[i].seq == (STRING *)0) {
	    breakList[i].seq = AllocString();
	} else {
	    BuildString((char *)0, breakList[i].seq);
	}
	breakList[i].delay = BREAKDELAYDEFAULT;
    }
    BuildString("\\z", breakList[0].seq);
    BuildString("\\r~^b", breakList[1].seq);
    BuildString("#.", breakList[2].seq);
    BuildString("\\r\\d~\\d^b", breakList[3].seq);
    breakList[3].delay = 600;

    /* initialize the user list */
    DestroyUserList();

    /* initialize the config set */
    if (pConfig != (CONFIG *)0) {
	DestroyConfig(pConfig);
	pConfig = (CONFIG *)0;
    }
    if ((pConfig = (CONFIG *)calloc(1, sizeof(CONFIG)))
	== (CONFIG *)0)
	OutOfMem();

    /* ready to read in the data */
    while ((token = GetWord(fp, &nextline, spaceok, word)) != DONE) {
	switch (state) {
	    case START:
		switch (token) {
		    case WORD:
			for (secIndex = 0;
			     (p = sections[secIndex].id) != (char *)0;
			     secIndex++) {
			    if (strcasecmp(word->string, p) == 0) {
				CONDDEBUG((1,
					   "ReadCfg(): got keyword '%s' [%s:%d]",
					   word->string, file, line));
				state = NAME;
				break;
			    }
			}
			if (state == START) {
			    if (isMaster)
				Error("invalid keyword '%s' [%s:%d]",
				      word->string, file, line);
			}
			break;
		    case LEFTBRACE:
		    case RIGHTBRACE:
		    case SEMICOLON:
			if (isMaster)
			    Error("invalid token '%s' [%s:%d]",
				  word->string, file, line);
			break;
		    case DONE:	/* just shutting up gcc */
			break;
		}
		break;
	    case NAME:
		switch (token) {
		    case WORD:
			(*sections[secIndex].begin) (word->string);
			state = LEFTB;
			break;
		    case RIGHTBRACE:
			if (isMaster)
			    Error("premature token '%s' [%s:%d]",
				  word->string, file, line);
			state = START;
			break;
		    case LEFTBRACE:
		    case SEMICOLON:
			if (isMaster)
			    Error("invalid token '%s' [%s:%d]",
				  word->string, file, line);
			break;
		    case DONE:	/* just shutting up gcc */
			break;
		}
		break;
	    case LEFTB:
		switch (token) {
		    case LEFTBRACE:
			state = KEY;
			break;
		    case RIGHTBRACE:
			if (isMaster)
			    Error("premature token '%s' [%s:%d]",
				  word->string, file, line);
			(*sections[secIndex].abort) ();
			state = START;
			break;
		    case SEMICOLON:
			if (isMaster)
			    Error("invalid token '%s' [%s:%d]",
				  word->string, file, line);
			break;
		    case WORD:
			if (isMaster)
			    Error("invalid word '%s' [%s:%d]",
				  word->string, file, line);
			break;
		    case DONE:	/* just shutting up gcc */
			break;
		}
		break;
	    case KEY:
		switch (token) {
		    case WORD:
			for (keyIndex = 0;
			     (p =
			      sections[secIndex].items[keyIndex].id) !=
			     (char *)0; keyIndex++) {
			    if (strcasecmp(word->string, p) == 0) {
				CONDDEBUG((1, "got keyword '%s' [%s:%d]",
					   word->string, file, line));
				state = VALUE;
				break;
			    }
			}
			if (state == KEY) {
			    if (isMaster)
				Error("invalid keyword '%s' [%s:%d]",
				      word->string, file, line);
			}
			break;
		    case RIGHTBRACE:
			(*sections[secIndex].end) ();
			state = START;
			break;
		    case LEFTBRACE:
			if (isMaster)
			    Error("invalid token '%s' [%s:%d]",
				  word->string, file, line);
			break;
		    case SEMICOLON:
			if (isMaster)
			    Error("premature token '%s' [%s:%d]",
				  word->string, file, line);
		    case DONE:	/* just shutting up gcc */
			break;
		}
		break;
	    case VALUE:
		switch (token) {
		    case WORD:
			(*sections[secIndex].items[keyIndex].reg) (word->
								   string);
			state = SEMI;
			break;
		    case SEMICOLON:
			if (isMaster)
			    Error("invalid token '%s' [%s:%d]",
				  word->string, file, line);
			state = KEY;
			break;
		    case RIGHTBRACE:
			if (isMaster)
			    Error("premature token '%s' [%s:%d]",
				  word->string, file, line);
			(*sections[secIndex].abort) ();
			state = START;
			break;
		    case LEFTBRACE:
			if (isMaster)
			    Error("invalid token '%s' [%s:%d]",
				  word->string, file, line);
			break;
		    case DONE:	/* just shutting up gcc */
			break;
		}
		break;
	    case SEMI:
		switch (token) {
		    case SEMICOLON:
			state = KEY;
			break;
		    case RIGHTBRACE:
			if (isMaster)
			    Error("premature token '%s' [%s:%d]",
				  word->string, file, line);
			(*sections[secIndex].abort) ();
			state = START;
			break;
		    case LEFTBRACE:
			if (isMaster)
			    Error("invalid token '%s' [%s:%d]",
				  word->string, file, line);
			break;
		    case WORD:
			if (isMaster)
			    Error("invalid word '%s' [%s:%d]",
				  word->string, file, line);
			break;
		    case DONE:	/* just shutting up gcc */
			break;
		}
		break;
	}
	switch (state) {
	    case NAME:
	    case VALUE:
		spaceok = 1;
		break;
	    case KEY:
	    case LEFTB:
	    case START:
	    case SEMI:
		spaceok = 0;
		break;
	}
	line = nextline;
    }

    /* check for proper ending of file and do any cleanup */
    switch (state) {
	case START:
	    break;
	case KEY:
	case LEFTB:
	case VALUE:
	case SEMI:
	    (*sections[secIndex].abort) ();
	    /* fall through */
	case NAME:
	    if (isMaster)
		Error("premature EOF seen [%s:%d]", file, line);
	    break;
    }

    /* now clean up all the temporary space used */
    for (nextline = 0; (p = sections[nextline].id) != (char *)0;
	 nextline++) {
	(*sections[nextline].destroy) ();
    }

#if HAVE_DMALLOC && DMALLOC_MARK_READCFG
    CONDDEBUG((1, "ReadCfg(): dmalloc / MarkReadCfg"));
    dmalloc_log_changed(dmallocMarkReadCfg, 1, 0, 1);
#endif
}

void
#if PROTOTYPES
ReReadCfg(int fd)
#else
ReReadCfg(fd)
    int fd;
#endif
{
    FILE *fpConfig;

    if ((FILE *)0 == (fpConfig = fopen(pcConfig, "r"))) {
	if (isMaster)
	    Error("ReReadCfg(): fopen(%s): %s", pcConfig, strerror(errno));
	return;
    }

    FD_ZERO(&rinit);
    FD_ZERO(&winit);
    if (fd > 0) {
	FD_SET(fd, &rinit);
	if (maxfd < fd + 1)
	    maxfd = fd + 1;
    }

    ReadCfg(pcConfig, fpConfig);

    fclose(fpConfig);

    if (pGroups == (GRPENT *)0 && pRCList == (REMOTE *)0) {
	if (isMaster) {
	    Error("no consoles found in configuration file");
	    kill(thepid, SIGTERM);	/* shoot myself in the head */
	    return;
	} else {
	    Error("no consoles to manage after reconfiguration - exiting");
	    Bye(EX_OK);
	}
    }

    /* check for changes to master & child values */
    if (optConf->logfile == (char *)0 && pConfig->logfile != (char *)0 &&
	(config->logfile == (char *)0 ||
	 strcmp(pConfig->logfile, config->logfile) != 0)) {
	if (config->logfile != (char *)0)
	    free(config->logfile);
	if ((config->logfile = StrDup(pConfig->logfile))
	    == (char *)0)
	    OutOfMem();
	ReopenLogfile();
    }
    if (optConf->defaultaccess == '\000' &&
	pConfig->defaultaccess != '\000' &&
	pConfig->defaultaccess != config->defaultaccess) {
	config->defaultaccess = pConfig->defaultaccess;
	/* gets used below by SetDefAccess() */
    }
    if (optConf->passwdfile == (char *)0 &&
	pConfig->passwdfile != (char *)0 &&
	(config->passwdfile == (char *)0 ||
	 strcmp(pConfig->passwdfile, config->passwdfile) != 0)) {
	if (config->passwdfile != (char *)0)
	    free(config->passwdfile);
	if ((config->passwdfile = StrDup(pConfig->passwdfile))
	    == (char *)0)
	    OutOfMem();
	/* gets used on-the-fly */
    }
    if (optConf->redirect == FLAGUNKNOWN &&
	pConfig->redirect != FLAGUNKNOWN &&
	pConfig->redirect != config->redirect) {
	config->redirect = pConfig->redirect;
	/* gets used on-the-fly */
    }
    if (optConf->reinitcheck == 0 && pConfig->reinitcheck != 0 &&
	pConfig->reinitcheck != config->reinitcheck) {
	config->reinitcheck = pConfig->reinitcheck;
	/* gets used on-the-fly */
    }
#if HAVE_OPENSSL
    if (optConf->sslrequired == FLAGUNKNOWN &&
	pConfig->sslrequired != FLAGUNKNOWN &&
	pConfig->sslrequired != config->sslrequired) {
	config->sslrequired = pConfig->sslrequired;
	/* gets used on-the-fly */
    }
#endif

    /* if no one can use us we need to come up with a default
     */
    if (pACList == (ACCESS *)0)
	SetDefAccess(myAddrs, myHostname);

    if (isMaster) {
	GRPENT *pGE;

	/* process any new options (command-line flags might have
	 * overridden things, so just need to check on new pConfig
	 * values for changes)
	 */
	if (optConf->daemonmode == FLAGUNKNOWN &&
	    pConfig->daemonmode != FLAGUNKNOWN &&
	    pConfig->daemonmode != config->daemonmode) {
	    config->daemonmode = pConfig->daemonmode;
	    Msg("warning: `daemonmode' config option changed - you must restart for it to take effect");
	}
	if (optConf->primaryport == (char *)0 &&
	    pConfig->primaryport != (char *)0 &&
	    (config->primaryport == (char *)0 ||
	     strcasecmp(pConfig->primaryport, config->primaryport) != 0)) {
	    if (config->primaryport != (char *)0)
		free(config->primaryport);
	    if ((config->primaryport = StrDup(pConfig->primaryport))
		== (char *)0)
		OutOfMem();
	    Msg("warning: `primaryport' config option changed - you must restart for it to take effect");
	}
	if (optConf->secondaryport == (char *)0 &&
	    pConfig->secondaryport != (char *)0 &&
	    (config->secondaryport == (char *)0 ||
	     strcasecmp(pConfig->secondaryport,
			config->secondaryport) != 0)) {
	    if (config->secondaryport != (char *)0)
		free(config->secondaryport);
	    if ((config->secondaryport = StrDup(pConfig->secondaryport))
		== (char *)0)
		OutOfMem();
	    Msg("warning: `secondaryport' config option changed - you must restart for it to take effect");
	}
#if HAVE_OPENSSL
	if (optConf->sslcredentials == (char *)0 &&
	    pConfig->sslcredentials != (char *)0 &&
	    (config->sslcredentials == (char *)0 ||
	     strcasecmp(pConfig->sslcredentials,
			config->sslcredentials) != 0)) {
	    if (config->sslcredentials != (char *)0)
		free(config->sslcredentials);
	    if ((config->sslcredentials = StrDup(pConfig->sslcredentials))
		== (char *)0)
		OutOfMem();
	    Msg("warning: `sslcredentials' config option changed - you must restart for it to take effect");
	}
#endif

	/* spawn all the children, so fix kids has an initial pid */
	for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
	    if (pGE->imembers == 0 || pGE->pid != -1)
		continue;

	    Spawn(pGE);

	    Verbose("group #%d pid %lu on port %hu", pGE->id,
		    (unsigned long)pGE->pid, pGE->port);
	}

	if (fVerbose) {
	    ACCESS *pACtmp;
	    for (pACtmp = pACList; pACtmp != (ACCESS *)0;
		 pACtmp = pACtmp->pACnext) {
		Verbose("access type `%c' for `%s'", pACtmp->ctrust,
			pACtmp->pcwho);
	    }
	}

	pRCUniq = FindUniq(pRCList);

	/* output unique console server peers?
	 */
	if (fVerbose) {
	    REMOTE *pRC;
	    for (pRC = pRCUniq; (REMOTE *)0 != pRC; pRC = pRC->pRCuniq) {
		Verbose("peer server on `%s'", pRC->rhost);
	    }
	}
    }
}
