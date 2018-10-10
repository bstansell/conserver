/*
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

#include <pwd.h>
#include <grp.h>

#include <cutil.h>
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
CONSENTUSERS *pLUList = (CONSENTUSERS *)0;
REMOTE *pRCUniq = (REMOTE *)0;
CONFIG *pConfig = (CONFIG *)0;
BREAKS breakList[BREAKLISTSIZE];

TASKS *taskList = (TASKS *)0;
SUBST *taskSubst = (SUBST *)0;

/***** internal things *****/
#define ALLWORDSEP ", \f\v\t\n\r"

int isStartup = 0;
GRPENT *pGroupsOld = (GRPENT *)0;
GRPENT *pGEstage = (GRPENT *)0;
GRPENT *pGE = (GRPENT *)0;
static unsigned int groupID = 1;
REMOTE **ppRC = (REMOTE **)0;

/* 'task' handling (plus) */
void
ProcessYesNo(char *id, FLAG *flag)
{
    if (id == (char *)0 || id[0] == '\000')
	*flag = FLAGFALSE;
    else if (strcasecmp("yes", id) == 0 || strcasecmp("true", id) == 0 ||
	     strcasecmp("on", id) == 0)
	*flag = FLAGTRUE;
    else if (strcasecmp("no", id) == 0 || strcasecmp("false", id) == 0 ||
	     strcasecmp("off", id) == 0)
	*flag = FLAGFALSE;
    else if (isMaster)
	Error("invalid boolean entry `%s' [%s:%d]", id, file, line);
}

void
DestroyTask(TASKS *task)
{
    if (task->cmd != (STRING *)0) {
	DestroyString(task->cmd);
	task->cmd = (STRING *)0;
    }
    if (task->descr != (STRING *)0) {
	DestroyString(task->descr);
	task->descr = (STRING *)0;
    }
    if (task->subst != (char *)0)
	free(task->subst);
    free(task);
}

void
DestroyTaskList(void)
{
    TASKS *n;
    while (taskList != (TASKS *)0) {
	n = taskList->next;
	DestroyTask(taskList);
	taskList = n;
    }
    if (taskSubst != (SUBST *)0) {
	free(taskSubst);
	taskSubst = (SUBST *)0;
    }
}

void
InitBreakList(void)
{
    int i;

    for (i = 0; i < BREAKLISTSIZE; i++) {
	breakList[i].seq = (STRING *)0;
	breakList[i].delay = 0;
	breakList[i].confirm = FLAGUNKNOWN;
    }
}

void
DestroyBreakList(void)
{
    int i;

    for (i = 0; i < BREAKLISTSIZE; i++) {
	if (breakList[i].seq != (STRING *)0) {
	    DestroyString(breakList[i].seq);
	    breakList[i].seq = (STRING *)0;
	}
    }
}

void
DestroyUserList(void)
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
FindUserList(char *id)
{
    NAMES *u;
    for (u = userList; u != (NAMES *)0; u = u->next) {
	if (strcmp(u->name, id) == 0)
	    return u;
    }
    return u;
}

NAMES *
AddUserList(char *id)
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

/* 'break' handling */
STRING *parserBreak = (STRING *)0;
int parserBreakDelay = 0;
int parserBreakNum = 0;
FLAG parserBreakConfirm = FLAGFALSE;

CONSENTUSERS *
ConsentAddUser(CONSENTUSERS **ppCU, char *id, short not)
{
    CONSENTUSERS *u = (CONSENTUSERS *)0;
    CONSENTUSERS *p = (CONSENTUSERS *)0;

    for (u = *ppCU; u != (CONSENTUSERS *)0; u = u->next) {
	if (strcmp(u->user->name, id) == 0) {
	    u->not = not;
	    /* at head of list already? */
	    if (p != (CONSENTUSERS *)0) {
		/* move it */
		p->next = u->next;
		u->next = *ppCU;
		*ppCU = u;
	    }
	    return u;
	}
	p = u;
    }

    if ((u = (CONSENTUSERS *)calloc(1, sizeof(CONSENTUSERS)))
	== (CONSENTUSERS *)0)
	OutOfMem();
    u->user = AddUserList(id);
    u->not = not;
    u->next = *ppCU;
    *ppCU = u;
    return u;
}

void
BreakBegin(char *id)
{
    CONDDEBUG((1, "BreakBegin(%s) [%s:%d]", id, file, line));
    if ((id == (char *)0) || (*id == '\000') ||
	((id[0] < '1' || id[0] > '9')
	 && (id[0] < 'a' || id[0] > 'z')) || id[1] != '\000') {
	if (isMaster)
	    Error("invalid break number `%s' [%s:%d]", id, file, line);
	parserBreakNum = 0;
    } else {
	parserBreakNum =
	    id[0] - '0' - (id[0] > '9' ? BREAKALPHAOFFSET : 0);
	if (parserBreak == (STRING *)0)
	    parserBreak = AllocString();
	else
	    BuildString((char *)0, parserBreak);
	parserBreakDelay = BREAKDELAYDEFAULT;
	parserBreakConfirm = FLAGFALSE;
    }
}

void
BreakEnd(void)
{
    CONDDEBUG((1, "BreakEnd() [%s:%d]", file, line));

    if (parserBreakNum == 0)
	return;

    BuildString((char *)0, breakList[parserBreakNum - 1].seq);
    BuildString(parserBreak->string, breakList[parserBreakNum - 1].seq);
    breakList[parserBreakNum - 1].delay = parserBreakDelay;
    breakList[parserBreakNum - 1].confirm = parserBreakConfirm;
    parserBreakNum = 0;
}

void
BreakAbort(void)
{
    CONDDEBUG((1, "BreakAbort() [%s:%d]", file, line));
    parserBreakNum = 0;
}

void
BreakDestroy(void)
{
    CONDDEBUG((1, "BreakDestroy() [%s:%d]", file, line));
    if (parserBreak != (STRING *)0) {
	DestroyString(parserBreak);
	parserBreak = (STRING *)0;
    }
#if DUMPDATA
    {
	int i;
	for (i = 0; i < BREAKLISTSIZE; i++) {
	    Msg("Break[%d] = `%s', delay=%d", i,
		breakList[i].seq ==
		(STRING *)0 ? "(null)" : (breakList[i].
					  seq->string ? breakList[i].
					  seq->string : "(null)"),
		breakList[i].delay);
	}
    }
#endif
}

void
BreakItemString(char *id)
{
    CONDDEBUG((1, "BreakItemString(%s) [%s:%d]", id, file, line));
    BuildString((char *)0, parserBreak);
    if ((id == (char *)0) || (*id == '\000'))
	return;
    BuildString(id, parserBreak);
}

void
BreakItemDelay(char *id)
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
	    Error("invalid delay number `%s' [%s:%d]", id, file, line);
	return;
    }
    parserBreakDelay = delay;
}

void
BreakItemConfirm(char *id)
{
    CONDDEBUG((1, "BreakItemConfirm(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserBreakConfirm));
}

/* 'group' handling */
typedef struct parserGroup {
    STRING *name;
    CONSENTUSERS *users;
    struct parserGroup *next;
} PARSERGROUP;

PARSERGROUP *parserGroups = (PARSERGROUP *)0;
PARSERGROUP *parserGroupTemp = (PARSERGROUP *)0;

void
DestroyParserGroup(PARSERGROUP *pg)
{
    PARSERGROUP **ppg = &parserGroups;

    if (pg == (PARSERGROUP *)0)
	return;

    CONDDEBUG((2, "DestroyParserGroup(): %s", pg->name->string));

    while (*ppg != (PARSERGROUP *)0) {
	if (*ppg == pg) {
	    break;
	} else {
	    ppg = &((*ppg)->next);
	}
    }

    if (*ppg != (PARSERGROUP *)0)
	*ppg = pg->next;

    DestroyString(pg->name);

    DestroyConsentUsers(&(pg->users));

    free(pg);
}

PARSERGROUP *
GroupFind(char *id)
{
    PARSERGROUP *pg;
    for (pg = parserGroups; pg != (PARSERGROUP *)0; pg = pg->next) {
	if (strcmp(id, pg->name->string) == 0)
	    return pg;
    }
    return pg;
}

void
GroupBegin(char *id)
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
GroupEnd(void)
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
GroupAbort(void)
{
    CONDDEBUG((1, "GroupAbort() [%s:%d]", file, line));
    DestroyParserGroup(parserGroupTemp);
    parserGroupTemp = (PARSERGROUP *)0;
}

void
GroupDestroy(void)
{
    CONDDEBUG((1, "GroupDestroy() [%s:%d]", file, line));
#if DUMPDATA
    {
	PARSERGROUP *pg;
	NAMES *u;
	for (pg = parserGroups; pg != (PARSERGROUP *)0; pg = pg->next) {
	    CONSENTUSERS *pcu;
	    Msg("Group = %s", pg->name->string);
	    for (pcu = pg->users; pcu != (CONSENTUSERS *)0;
		 pcu = pcu->next) {
		Msg("    User = %s", pcu->user->name);
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

CONSENTUSERS *
GroupAddUser(PARSERGROUP *pg, char *id, short not)
{
    return ConsentAddUser(&(pg->users), id, not);
}

void
CopyConsentUserList(CONSENTUSERS *s, CONSENTUSERS **d, short not)
{
    /* we have to add things backwards, since it's an ordered list */
    if (s == (CONSENTUSERS *)0 || d == (CONSENTUSERS **)0)
	return;

    CopyConsentUserList(s->next, d, not);

    ConsentAddUser(d, s->user->name, not ? !s->not : s->not);
}


void
GroupItemUsers(char *id)
{
    char *token = (char *)0;
    PARSERGROUP *pg = (PARSERGROUP *)0;

    CONDDEBUG((1, "GroupItemUsers(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000')) {
	DestroyConsentUsers(&(parserGroupTemp->users));
	return;
    }

    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	short not;
	if (token[0] == '!') {
	    token++;
	    not = 1;
	} else
	    not = 0;
	if ((pg = GroupFind(token)) == (PARSERGROUP *)0)
	    GroupAddUser(parserGroupTemp, token, not);
	else
	    CopyConsentUserList(pg->users, &(parserGroupTemp->users), not);
    }
}

/* 'default' handling */
CONSENT *parserDefaults = (CONSENT *)0;
CONSENT **parserDefaultsTail = &parserDefaults;
CONSENT *parserDefaultTemp = (CONSENT *)0;

void
DestroyParserDefaultOrConsole(CONSENT *c, CONSENT **ph, CONSENT ***pt)
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
    if (c->uds != (char *)0)
	free(c->uds);
    if (c->udssubst != (char *)0)
	free(c->udssubst);
    if (c->master != (char *)0)
	free(c->master);
    if (c->exec != (char *)0)
	free(c->exec);
    if (c->device != (char *)0)
	free(c->device);
    if (c->devicesubst != (char *)0)
	free(c->devicesubst);
    if (c->execsubst != (char *)0)
	free(c->execsubst);
    if (c->initsubst != (char *)0)
	free(c->initsubst);
    if (c->logfile != (char *)0)
	free(c->logfile);
    if (c->initcmd != (char *)0)
	free(c->initcmd);
    if (c->motd != (char *)0)
	free(c->motd);
    if (c->idlestring != (char *)0)
	free(c->idlestring);
    if (c->replstring != (char *)0)
	free(c->replstring);
    if (c->tasklist != (char *)0)
	free(c->tasklist);
    if (c->breaklist != (char *)0)
	free(c->breaklist);
    if (c->execSlave != (char *)0)
	free(c->execSlave);
#if HAVE_FREEIPMI
    if (c->username != (char *)0)
	free(c->username);
    if (c->password != (char *)0)
	free(c->password);
    if (c->ipmikg != (STRING *)0)
	DestroyString(c->ipmikg);
#endif
    while (c->aliases != (NAMES *)0) {
	NAMES *name;
	name = c->aliases->next;
	if (c->aliases->name != (char *)0)
	    free(c->aliases->name);
	free(c->aliases);
	c->aliases = name;
    }
    if (c->wbuf != (STRING *)0)
	DestroyString(c->wbuf);
    free(c);
}

CONSENT *
FindParserDefaultOrConsole(CONSENT *c, char *id)
{
    for (; c != (CONSENT *)0; c = c->pCEnext) {
	if (strcasecmp(id, c->server) == 0)
	    return c;
    }
    return c;
}

void
ApplyDefault(CONSENT *d, CONSENT *c)
{
    if (d->type != UNKNOWNTYPE)
	c->type = d->type;
    if (d->breakNum != 0)
	c->breakNum = d->breakNum;
    if (d->baud != (BAUD *)0)
	c->baud = d->baud;
    if (d->parity != (PARITY *)0)
	c->parity = d->parity;
    if (d->idletimeout != 0)
	c->idletimeout = d->idletimeout;
    if (d->logfilemax != 0)
	c->logfilemax = d->logfilemax;
    if (d->inituid != 0)
	c->inituid = d->inituid;
    if (d->initgid != 0)
	c->initgid = d->initgid;
    if (d->execuid != 0)
	c->execuid = d->execuid;
    if (d->execgid != 0)
	c->execgid = d->execgid;
    if (d->raw != FLAGUNKNOWN)
	c->raw = d->raw;
    if (d->port != 0)
	c->port = d->port;
    if (d->netport != 0)
	c->netport = d->netport;
    if (d->portinc != 0)
	c->portinc = d->portinc;
    if (d->portbase != 0)
	c->portbase = d->portbase;
    if (d->spinmax != 0)
	c->spinmax = d->spinmax;
    if (d->spintimer != 0)
	c->spintimer = d->spintimer;
    if (d->mark != 0)
	c->mark = d->mark;
    if (d->nextMark != 0)
	c->nextMark = d->nextMark;
    if (d->activitylog != FLAGUNKNOWN)
	c->activitylog = d->activitylog;
    if (d->breaklog != FLAGUNKNOWN)
	c->breaklog = d->breaklog;
    if (d->tasklog != FLAGUNKNOWN)
	c->tasklog = d->tasklog;
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
    if (d->login != FLAGUNKNOWN)
	c->login = d->login;
    if (d->host != (char *)0) {
	if (c->host != (char *)0)
	    free(c->host);
	if ((c->host = StrDup(d->host)) == (char *)0)
	    OutOfMem();
    }
    if (d->uds != (char *)0) {
	if (c->uds != (char *)0)
	    free(c->uds);
	if ((c->uds = StrDup(d->uds)) == (char *)0)
	    OutOfMem();
    }
    if (d->udssubst != (char *)0) {
	if (c->udssubst != (char *)0)
	    free(c->udssubst);
	if ((c->udssubst = StrDup(d->udssubst)) == (char *)0)
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
    if (d->devicesubst != (char *)0) {
	if (c->devicesubst != (char *)0)
	    free(c->devicesubst);
	if ((c->devicesubst = StrDup(d->devicesubst)) == (char *)0)
	    OutOfMem();
    }
    if (d->execsubst != (char *)0) {
	if (c->execsubst != (char *)0)
	    free(c->execsubst);
	if ((c->execsubst = StrDup(d->execsubst)) == (char *)0)
	    OutOfMem();
    }
    if (d->initsubst != (char *)0) {
	if (c->initsubst != (char *)0)
	    free(c->initsubst);
	if ((c->initsubst = StrDup(d->initsubst)) == (char *)0)
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
    if (d->idlestring != (char *)0) {
	if (c->idlestring != (char *)0)
	    free(c->idlestring);
	if ((c->idlestring = StrDup(d->idlestring)) == (char *)0)
	    OutOfMem();
    }
    if (d->replstring != (char *)0) {
	if (c->replstring != (char *)0)
	    free(c->replstring);
	if ((c->replstring = StrDup(d->replstring)) == (char *)0)
	    OutOfMem();
    }
    if (d->tasklist != (char *)0) {
	if (c->tasklist != (char *)0)
	    free(c->tasklist);
	if ((c->tasklist = StrDup(d->tasklist)) == (char *)0)
	    OutOfMem();
    }
    if (d->breaklist != (char *)0) {
	if (c->breaklist != (char *)0)
	    free(c->breaklist);
	if ((c->breaklist = StrDup(d->breaklist)) == (char *)0)
	    OutOfMem();
    }
#if HAVE_FREEIPMI
    if (d->ipmiwrkset != 0) {
	c->ipmiworkaround = d->ipmiworkaround;
	c->ipmiwrkset = d->ipmiwrkset;
    }
    if (d->ipmiciphersuite != 0)
	c->ipmiciphersuite = d->ipmiciphersuite;
    if (d->ipmiprivlevel != IPMIL_UNKNOWN)
	c->ipmiprivlevel = d->ipmiprivlevel;
    if (d->username != (char *)0) {
	if (c->username != (char *)0)
	    free(c->username);
	if ((c->username = StrDup(d->username)) == (char *)0)
	    OutOfMem();
    }
    if (d->password != (char *)0) {
	if (c->password != (char *)0)
	    free(c->password);
	if ((c->password = StrDup(d->password)) == (char *)0)
	    OutOfMem();
    }
    if (d->ipmikg != (STRING *)0) {
	if (c->ipmikg != (STRING *)0)
	    BuildString((char *)0, c->ipmikg);
	else
	    c->ipmikg = AllocString();
	BuildStringN(d->ipmikg->string, d->ipmikg->used - 1, c->ipmikg);
    }
#endif
    CopyConsentUserList(d->ro, &(c->ro), 0);
    CopyConsentUserList(d->rw, &(c->rw), 0);
}

void
DefaultBegin(char *id)
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
DefaultEnd(void)
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
DefaultAbort(void)
{
    CONDDEBUG((1, "DefaultAbort() [%s:%d]", file, line));
    DestroyParserDefaultOrConsole(parserDefaultTemp, (CONSENT **)0,
				  (CONSENT ***)0);
    parserDefaultTemp = (CONSENT *)0;
}

void
DefaultDestroy(void)
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
ProcessBaud(CONSENT *c, char *id)
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
DefaultItemBaud(char *id)
{
    CONDDEBUG((1, "DefaultItemBaud(%s) [%s:%d]", id, file, line));
    ProcessBaud(parserDefaultTemp, id);
}

void
ProcessBreak(CONSENT *c, char *id)
{
    if ((id == (char *)0) || (*id == '\000')) {
	c->breakNum = 0;
	return;
    }
    if (((id[0] >= '1' && id[0] <= '9') || (id[0] >= 'a' && id[0] <= 'z'))
	&& (id[1] == '\000')) {
	c->breakNum = id[0] - '0' - (id[0] > '9' ? BREAKALPHAOFFSET : 0);
	return;
    }
    if (isMaster)
	Error("invalid break number `%s' [%s:%d]", id, file, line);
}

void
DefaultItemBreak(char *id)
{
    CONDDEBUG((1, "DefaultItemBreak(%s) [%s:%d]", id, file, line));
    ProcessBreak(parserDefaultTemp, id);
}

void
ProcessDevice(CONSENT *c, char *id)
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
DefaultItemDevice(char *id)
{
    CONDDEBUG((1, "DefaultItemDevice(%s) [%s:%d]", id, file, line));
    ProcessDevice(parserDefaultTemp, id);
}

/* substitution support */
SUBST *substData = (SUBST *)0;
int substTokenCount[255];

int
SubstTokenCount(char c)
{
    return substTokenCount[(unsigned)c];
}

void
ZeroSubstTokenCount(void)
{
#if HAVE_MEMSET
    memset((void *)&substTokenCount, 0, sizeof(substTokenCount));
#else
    bzero((char *)&substTokenCount, sizeof(substTokenCount));
#endif
}


int
SubstValue(char c, char **s, int *i)
{
    int retval = 0;
    CONSENT *pCE;
    static char *empty = "";

    if (substData->data == (void *)0)
	return 0;
    pCE = (CONSENT *)(substData->data);

    if (s != (char **)0) {
	if (c == 'h') {
	    if (pCE->host == (char *)0) {
		(*s) = empty;
	    } else {
		(*s) = pCE->host;
	    }
	    retval = 1;
	} else if (c == 'c') {
	    if (pCE->server == (char *)0) {
		(*s) = empty;
	    } else {
		(*s) = pCE->server;
	    }
	    retval = 1;
	} else if (c == 'r') {
	    if (pCE->replstring == (char *)0) {
		(*s) = empty;
	    } else {
		(*s) = pCE->replstring;
	    }
	    retval = 1;
	}
    }

    if (i != (int *)0) {
	if (c == 'p') {
	    (*i) = pCE->port;
	    retval = 1;
	} else if (c == 'P') {
	    (*i) = pCE->netport;
	    retval = 1;
	}
    }

    return retval;
}

SUBSTTOKEN
SubstToken(char c)
{
    switch (c) {
	case 'p':
	case 'P':
	    substTokenCount[(unsigned)c]++;
	    return ISNUMBER;
	case 'h':
	case 'c':
	case 'r':
	    substTokenCount[(unsigned)c]++;
	    return ISSTRING;
	default:
	    return ISNOTHING;
    }
}

void
InitSubstCallback(void)
{
    if (substData == (SUBST *)0) {
	if ((substData = (SUBST *)calloc(1, sizeof(SUBST))) == (SUBST *)0)
	    OutOfMem();
	substData->value = &SubstValue;
	substData->token = &SubstToken;
	ZeroSubstTokenCount();
    }
}

void
DefaultItemDevicesubst(char *id)
{
    CONDDEBUG((1, "DefaultItemDevicesubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserDefaultTemp->devicesubst),
		 "devicesubst", id);
}

void
DefaultItemExecsubst(char *id)
{
    CONDDEBUG((1, "DefaultItemExecsubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserDefaultTemp->execsubst),
		 "execsubst", id);
}

void
DefaultItemUdssubst(char *id)
{
    CONDDEBUG((1, "DefaultItemUdssubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserDefaultTemp->udssubst),
		 "udssubst", id);
}

void
DefaultItemInitsubst(char *id)
{
    CONDDEBUG((1, "DefaultItemInitsubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserDefaultTemp->initsubst),
		 "initsubst", id);
}

void
ProcessUidGid(uid_t * uid, gid_t * gid, char *id)
{
    char *colon = (char *)0;
    int i;

    CONDDEBUG((1, "ProcessUidGid(%s) [%s:%d]", id, file, line));

    *uid = *gid = 0;

    if (id == (char *)0 || id[0] == '\000')
	return;

    /* hunt for colon */
    if ((colon = strchr(id, ':')) != (char *)0)
	*colon = '\000';

    if (id[0] != '\000') {
	/* Look for non-numeric characters */
	for (i = 0; id[i] != '\000'; i++)
	    if (!isdigit((int)id[i]))
		break;
	if (id[i] == '\000') {
	    *uid = (uid_t) atoi(id);
	} else {
	    struct passwd *pwd = (struct passwd *)0;
	    if ((pwd = getpwnam(id)) == (struct passwd *)0) {
		CONDDEBUG((1, "ProcessUidGid(): getpwnam(%s): %s", id,
			   strerror(errno)));
		if (isMaster)
		    Error("invalid user name `%s' [%s:%d]", id, file,
			  line);
	    } else {
		*uid = pwd->pw_uid;
	    }
	}
    }

    if (colon != (char *)0) {
	*colon = ':';
	colon++;
	if (*colon != '\000') {
	    /* Look for non-numeric characters */
	    for (i = 0; colon[i] != '\000'; i++)
		if (!isdigit((int)colon[i]))
		    break;
	    if (colon[i] == '\000') {
		*gid = (gid_t) atoi(colon);
	    } else {
		struct group *grp = (struct group *)0;
		if ((grp = getgrnam(colon)) == (struct group *)0) {
		    CONDDEBUG((1, "ProcessUidGid(): getgrnam(%s): %s",
			       colon, strerror(errno)));
		    if (isMaster)
			Error("invalid group name `%s' [%s:%d]", colon,
			      file, line);
		} else {
		    *gid = grp->gr_gid;
		}
	    }
	}
    }
}

void
ProcessInitrunas(CONSENT *c, char *id)
{
    CONDDEBUG((1, "ProcessInitrunas(%s) [%s:%d]", id, file, line));
    ProcessUidGid(&(c->inituid), &(c->initgid), id);
}

void
ProcessExecrunas(CONSENT *c, char *id)
{
    CONDDEBUG((1, "ProcessExecrunas(%s) [%s:%d]", id, file, line));
    ProcessUidGid(&(c->execuid), &(c->execgid), id);
}

void
DefaultItemInitrunas(char *id)
{
    CONDDEBUG((1, "DefaultItemInitrunas(%s) [%s:%d]", id, file, line));
    ProcessInitrunas(parserDefaultTemp, id);
}

#if HAVE_FREEIPMI
void
ProcessIpmiPrivLevel(CONSENT *c, char *id)
{
    if (!strcasecmp("user", id))
	c->ipmiprivlevel = IPMIL_USER;
    else if (!strcasecmp("operator", id))
	c->ipmiprivlevel = IPMIL_OPERATOR;
    else if (!strcasecmp("admin", id))
	c->ipmiprivlevel = IPMIL_ADMIN;
    else
	Error("invalid ipmiprivlevel `%s' [%s:%d]", id, file, line);
}

void
DefaultItemIpmiPrivLevel(char *id)
{
    CONDDEBUG((1, "DefaultItemIpmiPrivLevel(%s) [%s:%d]", id, file, line));
    ProcessIpmiPrivLevel(parserDefaultTemp, id);
}
#endif /*freeipmi */

void
DefaultItemExecrunas(char *id)
{
    CONDDEBUG((1, "DefaultItemExecrunas(%s) [%s:%d]", id, file, line));
    ProcessExecrunas(parserDefaultTemp, id);
}

void
ProcessExec(CONSENT *c, char *id)
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
DefaultItemExec(char *id)
{
    CONDDEBUG((1, "DefaultItemExec(%s) [%s:%d]", id, file, line));
    ProcessExec(parserDefaultTemp, id);
}

void
ProcessFlow(CONSENT *c, char *id)
{
    if (isMaster)
	Error("unimplemented code for `flow' [%s:%d]", file, line);
}

void
DefaultItemFlow(char *id)
{
    CONDDEBUG((1, "DefaultItemFlow(%s) [%s:%d]", id, file, line));
    ProcessFlow(parserDefaultTemp, id);
}

void
ProcessHost(CONSENT *c, char *id)
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
DefaultItemHost(char *id)
{
    CONDDEBUG((1, "DefaultItemHost(%s) [%s:%d]", id, file, line));
    ProcessHost(parserDefaultTemp, id);
}

void
ProcessUds(CONSENT *c, char *id)
{
    if (c->uds != (char *)0) {
	free(c->uds);
	c->uds = (char *)0;
    }
    if ((id == (char *)0) || (*id == '\000'))
	return;
    if ((c->uds = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
DefaultItemUds(char *id)
{
    CONDDEBUG((1, "DefaultItemUds(%s) [%s:%d]", id, file, line));
    ProcessUds(parserDefaultTemp, id);
}

#if HAVE_FREEIPMI
void
ProcessIpmiKG(CONSENT *c, char *id)
{
    char s;
    char oct = '\000';
    short octs = 0;
    short backslash = 0;
    char *i = id;
    static STRING *t = (STRING *)0;

    if (t == (STRING *)0)
	t = AllocString();

    if ((id == (char *)0) || (*id == '\000')) {
	if (c->ipmikg != (STRING *)0) {
	    DestroyString(c->ipmikg);
	    c->ipmikg = (STRING *)0;
	}
	return;
    }

    BuildString((char *)0, t);

    while ((s = (*i++)) != '\000') {
	if (octs > 0 && octs < 3 && s >= '0' && s <= '7') {
	    ++octs;
	    oct = oct * 8 + (s - '0');
	    continue;
	}
	if (octs != 0) {
	    BuildStringChar(oct, t);
	    octs = 0;
	    oct = '\000';
	}
	if (backslash) {
	    backslash = 0;
	    if (s >= '0' && s <= '7') {
		++octs;
		oct = oct * 8 + (s - '0');
		continue;
	    }
	    BuildStringChar(s, t);
	    continue;
	}
	if (s == '\\') {
	    backslash = 1;
	    continue;
	}
	BuildStringChar(s, t);
    }

    if (octs != 0)
	BuildStringChar(oct, t);

    if (backslash)
	BuildStringChar('\\', t);

    if (t->used > 21) {		/* max 20 chars */
	if (isMaster)
	    Error("ipmikg string `%s' over 20 characters [%s:%d]", id,
		  file, line);
	return;
    }
    if (!ipmiconsole_k_g_is_valid((unsigned char *)t->string, t->used - 1)) {
	if (isMaster)
	    Error("invalid ipmikg string `%s' [%s:%d]", id, file, line);
	return;
    }

    if (c->ipmikg == (STRING *)0)
	c->ipmikg = AllocString();
    BuildString((char *)0, c->ipmikg);
    BuildStringN(t->string, t->used - 1, c->ipmikg);
}

void
DefaultItemIpmiKG(char *id)
{
    CONDDEBUG((1, "DefaultItemIpmiKG(%s) [%s:%d]", id, file, line));
    ProcessIpmiKG(parserDefaultTemp, id);
}

void
ProcessUsername(CONSENT *c, char *id)
{
    if ((id == (char *)0) || (*id == '\000')) {
	c->username = (char *)0;
	return;
    }
    c->username = strdup(id);
}

void
DefaultItemUsername(char *id)
{
    CONDDEBUG((1, "DefaultItemUsername(%s) [%s:%d]", id, file, line));
    ProcessUsername(parserDefaultTemp, id);
}

void
ProcessIpmiCipherSuite(CONSENT *c, char *id)
{
    char *p;
    int i;

    if ((id == (char *)0) || (*id == '\000')) {
	c->ipmiciphersuite = 0;
	return;
    }

    /* if we have -1, allow it (we allow >= -1 now) */
    if (id[0] == '-' && id[1] == '1' && id[2] == '\000') {
	c->ipmiciphersuite = 1;
	return;
    }

    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;

    /* if it wasn't a number */
    if (*p != '\000') {
	if (isMaster)
	    Error("invalid ipmiciphersuite number `%s' [%s:%d]", id, file,
		  line);
	return;
    }

    i = atoi(id);

    if (ipmiconsole_cipher_suite_id_is_valid(i))
	c->ipmiciphersuite = i + 2;
    else {
	if (isMaster)
	    Error("invalid ipmiciphersuite number `%s' [%s:%d]", id, file,
		  line);
	return;
    }
}

void
DefaultItemIpmiCipherSuite(char *id)
{
    CONDDEBUG((1, "DefaultItemIpmiCipherSuite(%s) [%s:%d]", id, file,
	       line));
    ProcessIpmiCipherSuite(parserDefaultTemp, id);
}

void
ProcessIpmiWorkaround(CONSENT *c, char *id)
{
    unsigned int flag;
    char *token = (char *)0;
    short valid = 0;
    unsigned int wrk = 0;

    if ((id == (char *)0) || (*id == '\000')) {
	c->ipmiworkaround = 0;
	c->ipmiwrkset = 1;
	return;
    }

    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	short not;
	if (token[0] == '!') {
	    token++;
	    not = 1;
	} else
	    not = 0;
	if (!strcmp(token, "default"))
	    flag = IPMICONSOLE_WORKAROUND_DEFAULT;
# if defined(IPMICONSOLE_WORKAROUND_AUTHENTICATION_CAPABILITIES)
	else if (!strcmp(token, "auth-capabilites"))
	    flag = IPMICONSOLE_WORKAROUND_AUTHENTICATION_CAPABILITIES;
# endif
# if defined(IPMICONSOLE_WORKAROUND_INTEL_2_0_SESSION)
	else if (!strcmp(token, "intel-session"))
	    flag = IPMICONSOLE_WORKAROUND_INTEL_2_0_SESSION;
# endif
# if defined(IPMICONSOLE_WORKAROUND_SUPERMICRO_2_0_SESSION)
	else if (!strcmp(token, "supermicro-session"))
	    flag = IPMICONSOLE_WORKAROUND_SUPERMICRO_2_0_SESSION;
# endif
# if defined(IPMICONSOLE_WORKAROUND_SUN_2_0_SESSION)
	else if (!strcmp(token, "sun-session"))
	    flag = IPMICONSOLE_WORKAROUND_SUN_2_0_SESSION;
# endif
# if defined(IPMICONSOLE_WORKAROUND_OPEN_SESSION_PRIVILEGE)
	else if (!strcmp(token, "privilege"))
	    flag = IPMICONSOLE_WORKAROUND_OPEN_SESSION_PRIVILEGE;
# endif
# if defined(IPMICONSOLE_WORKAROUND_NON_EMPTY_INTEGRITY_CHECK_VALUE)
	else if (!strcmp(token, "integrity"))
	    flag = IPMICONSOLE_WORKAROUND_NON_EMPTY_INTEGRITY_CHECK_VALUE;
# endif
# if defined(IPMICONSOLE_WORKAROUND_NO_CHECKSUM_CHECK)
	else if (!strcmp(token, "checksum"))
	    flag = IPMICONSOLE_WORKAROUND_NO_CHECKSUM_CHECK;
# endif
# if defined(IPMICONSOLE_WORKAROUND_SERIAL_ALERTS_DEFERRED)
	else if (!strcmp(token, "serial-alerts"))
	    flag = IPMICONSOLE_WORKAROUND_SERIAL_ALERTS_DEFERRED;
# endif
# if defined(IPMICONSOLE_WORKAROUND_INCREMENT_SOL_PACKET_SEQUENCE)
	else if (!strcmp(token, "packet-sequence"))
	    flag = IPMICONSOLE_WORKAROUND_INCREMENT_SOL_PACKET_SEQUENCE;
# endif
# if defined(IPMICONSOLE_WORKAROUND_IGNORE_SOL_PAYLOAD_SIZE)
	else if (!strcmp(token, "ignore-payload-size"))
	    flag = IPMICONSOLE_WORKAROUND_IGNORE_SOL_PAYLOAD_SIZE;
# endif
# if defined(IPMICONSOLE_WORKAROUND_IGNORE_SOL_PORT)
	else if (!strcmp(token, "ignore-port"))
	    flag = IPMICONSOLE_WORKAROUND_IGNORE_SOL_PORT;
# endif
# if defined(IPMICONSOLE_WORKAROUND_SKIP_SOL_ACTIVATION_STATUS)
	else if (!strcmp(token, "activation-status"))
	    flag = IPMICONSOLE_WORKAROUND_SKIP_SOL_ACTIVATION_STATUS;
# endif
# if defined(IPMICONSOLE_WORKAROUND_SKIP_CHANNEL_PAYLOAD_SUPPORT)
	else if (!strcmp(token, "channel-payload"))
	    flag = IPMICONSOLE_WORKAROUND_SKIP_CHANNEL_PAYLOAD_SUPPORT;
# endif
	else {
	    if (isMaster)
		Error("invalid ipmiworkaround `%s' [%s:%d]", token, file,
		      line);
	    continue;
	}
	if (not) {
	    wrk &= ~flag;
	} else {
	    wrk |= flag;
	}
	valid = 1;
    }

    if (valid) {
	if (ipmiconsole_workaround_flags_is_valid(wrk)) {
	    c->ipmiworkaround = wrk;
	    c->ipmiwrkset = 1;
	} else {
	    if (isMaster)
		Error("invalid ipmiworkaround setting [%s:%d]", file,
		      line);
	    return;
	}
    }
}

void
DefaultItemIpmiWorkaround(char *id)
{
    CONDDEBUG((1, "DefaultItemIpmiWorkaround(%s) [%s:%d]", id, file,
	       line));
    ProcessIpmiWorkaround(parserDefaultTemp, id);
}
#endif /*freeipmi */

void
ProcessInclude(CONSENT *c, char *id)
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
DefaultItemInclude(char *id)
{
    CONDDEBUG((1, "DefaultItemInclude(%s) [%s:%d]", id, file, line));
    ProcessInclude(parserDefaultTemp, id);
}

void
ProcessLogfile(CONSENT *c, char *id)
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
ProcessInitcmd(CONSENT *c, char *id)
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
ProcessMOTD(CONSENT *c, char *id)
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
ProcessIdlestring(CONSENT *c, char *id)
{
    if (c->idlestring != (char *)0) {
	free(c->idlestring);
	c->idlestring = (char *)0;
    }
    if (id == (char *)0 || id[0] == '\000') {
	return;
    }
    if ((c->idlestring = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
DefaultItemLogfile(char *id)
{
    CONDDEBUG((1, "DefaultItemLogfile(%s) [%s:%d]", id, file, line));
    ProcessLogfile(parserDefaultTemp, id);
}

void
ProcessLogfilemax(CONSENT *c, char *id)
{
    char *p;
    off_t v = 0;

    c->logfilemax = 0;

    if (id == (char *)0 || id[0] == '\000')
	return;

    for (p = id; *p != '\000'; p++) {
	if (!isdigit((int)(*p)))
	    break;
	v = v * 10 + (*p - '0');
    }

    /* if it wasn't just numbers */
    if (*p != '\000') {
	if ((*p == 'k' || *p == 'K') && *(p + 1) == '\000') {
	    v *= 1024;
	} else if ((*p == 'm' || *p == 'M') && *(p + 1) == '\000') {
	    v *= 1024 * 1024;
	} else {
	    if (isMaster)
		Error("invalid `logfilemax' specification `%s' [%s:%d]",
		      id, file, line);
	    return;
	}
    }

    if (v < 2048) {
	if (isMaster)
	    Error
		("invalid `logfilemax' specification `%s' (must be >= 2K) [%s:%d]",
		 id, file, line);
	return;
    }

    c->logfilemax = v;
}

void
DefaultItemLogfilemax(char *id)
{
    CONDDEBUG((1, "DefaultItemLogfilemax(%s) [%s:%d]", id, file, line));
    ProcessLogfilemax(parserDefaultTemp, id);
}

void
DefaultItemInitcmd(char *id)
{
    CONDDEBUG((1, "DefaultItemInitcmd(%s) [%s:%d]", id, file, line));
    ProcessInitcmd(parserDefaultTemp, id);
}

void
DefaultItemMOTD(char *id)
{
    CONDDEBUG((1, "DefaultItemMOTD(%s) [%s:%d]", id, file, line));
    ProcessMOTD(parserDefaultTemp, id);
}

void
DefaultItemIdlestring(char *id)
{
    CONDDEBUG((1, "DefaultItemIdlestring(%s) [%s:%d]", id, file, line));
    ProcessIdlestring(parserDefaultTemp, id);
}

void
ProcessMaster(CONSENT *c, char *id)
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
DefaultItemMaster(char *id)
{
    CONDDEBUG((1, "DefaultItemMaster(%s) [%s:%d]", id, file, line));
    ProcessMaster(parserDefaultTemp, id);
}

void
ProcessOptions(CONSENT *c, char *id)
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
	c->login = FLAGUNKNOWN;
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
	else if (strcasecmp("login", token) == 0)
	    c->login = negative ? FLAGFALSE : FLAGTRUE;
	else if (isMaster)
	    Error("invalid option `%s' [%s:%d]", token, file, line);
    }
}

void
DefaultItemOptions(char *id)
{
    CONDDEBUG((1, "DefaultItemOptions(%s) [%s:%d]", id, file, line));
    ProcessOptions(parserDefaultTemp, id);
}

void
ProcessParity(CONSENT *c, char *id)
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
DefaultItemParity(char *id)
{
    CONDDEBUG((1, "DefaultItemParity(%s) [%s:%d]", id, file, line));
    ProcessParity(parserDefaultTemp, id);
}

#if HAVE_FREEIPMI
void
ProcessPassword(CONSENT *c, char *id)
{
    if ((id == (char *)0) || (*id == '\000')) {
	c->password = (char *)0;
	return;
    }
    c->password = strdup(id);
}

void
DefaultItemPassword(char *id)
{
    CONDDEBUG((1, "DefaultItemPassword(%s) [%s:%d]", id, file, line));
    ProcessPassword(parserDefaultTemp, id);
}
#endif /*freeipmi */

void
ProcessPort(CONSENT *c, char *id)
{
    char *p;

    if ((id == (char *)0) || (*id == '\000')) {
	c->port = 0;
	return;
    }
    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;

    /* if it was a number */
    if (*p == '\000') {
	c->port = (unsigned short)atoi(id) + 1;
    } else {
	/* non-numeric */
	struct servent *se;
	if ((struct servent *)0 == (se = getservbyname(id, "tcp"))) {
	    if (isMaster)
		Error
		    ("invalid port name `%s': getservbyname() failure [%s:%d]",
		     id, file, line);
	    return;
	} else {
	    c->port = ntohs((unsigned short)se->s_port) + 1;
	}
    }
}

void
ProcessPortinc(CONSENT *c, char *id)
{
    char *p;

    if ((id == (char *)0) || (*id == '\000')) {
	c->portinc = 0;
	return;
    }
    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;
    /* if it wasn't a number */
    if (*p != '\000') {
	if (isMaster)
	    Error("invalid portinc number `%s' [%s:%d]", id, file, line);
	return;
    }
    c->portinc = (unsigned short)atoi(id) + 1;
}

void
ProcessPortbase(CONSENT *c, char *id)
{
    char *p;

    if ((id == (char *)0) || (*id == '\000')) {
	c->portbase = 0;
	return;
    }

    /* if we have -1, allow it (we allow >= -1 now) */
    if (id[0] == '-' && id[1] == '1' && id[2] == '\000') {
	c->portbase = 1;
	return;
    }

    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;

    /* if it wasn't a number */
    if (*p != '\000') {
	if (isMaster)
	    Error("invalid portbase number `%s' [%s:%d]", id, file, line);
	return;
    }
    c->portbase = (unsigned short)atoi(id) + 2;
}

void
DefaultItemPort(char *id)
{
    CONDDEBUG((1, "DefaultItemPort(%s) [%s:%d]", id, file, line));
    ProcessPort(parserDefaultTemp, id);
}

void
DefaultItemPortbase(char *id)
{
    CONDDEBUG((1, "DefaultItemPortbase(%s) [%s:%d]", id, file, line));
    ProcessPortbase(parserDefaultTemp, id);
}

void
DefaultItemPortinc(char *id)
{
    CONDDEBUG((1, "DefaultItemPortinc(%s) [%s:%d]", id, file, line));
    ProcessPortinc(parserDefaultTemp, id);
}

void
ProcessInitspinmax(CONSENT *c, char *id)
{
    char *p;
    int i;

    if ((id == (char *)0) || (*id == '\000')) {
	c->spinmax = 0;
	return;
    }
    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;
    /* if it wasn't a number */
    if (*p != '\000') {
	if (isMaster)
	    Error("invalid initspinmax number `%s' [%s:%d]", id, file,
		  line);
	return;
    }
    i = atoi(id);
    if (i > 254) {
	if (isMaster)
	    Error("invalid initspinmax number `%s' [%s:%d]", id, file,
		  line);
	return;
    }
    c->spinmax = i + 1;
}

void
DefaultItemInitspinmax(char *id)
{
    CONDDEBUG((1, "DefaultItemInitspinmax(%s) [%s:%d]", id, file, line));
    ProcessInitspinmax(parserDefaultTemp, id);
}

void
ProcessInitspintimer(CONSENT *c, char *id)
{
    char *p;
    int i;

    if ((id == (char *)0) || (*id == '\000')) {
	c->spintimer = 0;
	return;
    }
    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;
    /* if it wasn't a number */
    if (*p != '\000') {
	if (isMaster)
	    Error("invalid initspintimer number `%s' [%s:%d]", id, file,
		  line);
	return;
    }
    i = atoi(id);
    if (i > 254) {
	if (isMaster)
	    Error("invalid initspintimer number `%s' [%s:%d]", id, file,
		  line);
	return;
    }
    c->spintimer = i + 1;
}

void
DefaultItemInitspintimer(char *id)
{
    CONDDEBUG((1, "DefaultItemInitspintimer(%s) [%s:%d]", id, file, line));
    ProcessInitspintimer(parserDefaultTemp, id);
}

void
ProcessProtocol(CONSENT *c, char *id)
{
    if ((id == (char *)0) || (*id == '\000')) {
	c->raw = FLAGUNKNOWN;
	return;
    }

    if (strcmp(id, "telnet") == 0) {
	c->raw = FLAGFALSE;
	return;
    }
    if (strcmp(id, "raw") == 0) {
	c->raw = FLAGTRUE;
	return;
    }
    if (isMaster)
	Error("invalid protocol name `%s' [%s:%d]", id, file, line);
}

void
DefaultItemProtocol(char *id)
{
    CONDDEBUG((1, "DefaultItemProtocol(%s) [%s:%d]", id, file, line));
    ProcessProtocol(parserDefaultTemp, id);
}

void
ProcessReplstring(CONSENT *c, char *id)
{
    if (c->replstring != (char *)0) {
	free(c->replstring);
	c->replstring = (char *)0;
    }
    if ((id == (char *)0) || (*id == '\000'))
	return;
    if ((c->replstring = StrDup(id))
	== (char *)0)
	OutOfMem();
}

void
DefaultItemReplstring(char *id)
{
    CONDDEBUG((1, "DefaultItemReplstring(%s) [%s:%d]", id, file, line));
    ProcessReplstring(parserDefaultTemp, id);
}

void
ProcessTasklist(CONSENT *c, char *id)
{
    char *token = (char *)0;
    char *list = (char *)0;

    CONDDEBUG((1, "ProcessTasklist(%s) [%s:%d]", id, file, line));

    if (c->tasklist != (char *)0) {
	free(c->tasklist);
	c->tasklist = (char *)0;
    }
    if ((id == (char *)0) || (*id == '\000'))
	return;

    list = BuildTmpString((char *)0);
    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	if (token[1] != '\000' ||
	    ((token[0] < '0' || token[0] > '9') &&
	     (token[0] < 'a' || token[0] > 'z') && token[0] != '*')) {
	    if (isMaster)
		Error("invalid tasklist reference `%s' [%s:%d]", token,
		      file, line);
	    continue;
	}
	list = BuildTmpStringChar(token[0]);
    }
    if (list == (char *)0 || *list == '\000')
	return;

    if ((c->tasklist = StrDup(list)) == (char *)0)
	OutOfMem();
}

void
DefaultItemTasklist(char *id)
{
    CONDDEBUG((1, "DefaultItemTasklist(%s) [%s:%d]", id, file, line));
    ProcessTasklist(parserDefaultTemp, id);
}

void
ProcessBreaklist(CONSENT *c, char *id)
{
    char *token = (char *)0;
    char *list = (char *)0;

    CONDDEBUG((1, "ProcessBreaklist(%s) [%s:%d]", id, file, line));

    if (c->breaklist != (char *)0) {
	free(c->breaklist);
	c->breaklist = (char *)0;
    }
    if ((id == (char *)0) || (*id == '\000'))
	return;

    list = BuildTmpString((char *)0);
    for (token = strtok(id, ALLWORDSEP); token != (char *)0;
	 token = strtok(NULL, ALLWORDSEP)) {
	if (token[1] != '\000' ||
	    (((token[0] < '0' || token[0] > '9') &&
	      (token[0] < 'a' || token[0] > 'z')) && token[0] != '*')) {
	    if (isMaster)
		Error("invalid breaklist reference `%s' [%s:%d]", token,
		      file, line);
	    continue;
	}
	list = BuildTmpStringChar(token[0]);
    }
    if (list == (char *)0 || *list == '\000')
	return;

    if ((c->breaklist = StrDup(list)) == (char *)0)
	OutOfMem();
}

void
DefaultItemBreaklist(char *id)
{
    CONDDEBUG((1, "DefaultItemBreaklist(%s) [%s:%d]", id, file, line));
    ProcessBreaklist(parserDefaultTemp, id);
}

void
ProcessIdletimeout(CONSENT *c, char *id)
{
    char *p;
    int factor = 0;

    if ((id == (char *)0) || (*id == '\000')) {
	c->idletimeout = 0;
	return;
    }
    for (p = id; factor == 0 && *p != '\000'; p++)
	if (*p == 's' || *p == 'S')
	    factor = 1;
	else if (*p == 'm' || *p == 'M')
	    factor = 60;
	else if (*p == 'h' || *p == 'H')
	    factor = 60 * 60;
	else if (!isdigit((int)(*p)))
	    break;
    /* if it wasn't a number or a qualifier wasn't at the end */
    if (*p != '\000') {
	if (isMaster)
	    Error("invalid idletimeout specification `%s' [%s:%d]", id,
		  file, line);
	return;
    }
    c->idletimeout = (time_t)atoi(id) * (factor == 0 ? 1 : factor);
}

void
DefaultItemIdletimeout(char *id)
{
    CONDDEBUG((1, "DefaultItemIdletimeout(%s) [%s:%d]", id, file, line));
    ProcessIdletimeout(parserDefaultTemp, id);
}

void
ProcessRoRw(CONSENTUSERS **ppCU, char *id)
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
	short not;
	if (token[0] == '!') {
	    token++;
	    not = 1;
	} else
	    not = 0;
	if ((pg = GroupFind(token)) == (PARSERGROUP *)0)
	    ConsentAddUser(ppCU, token, not);
	else
	    CopyConsentUserList(pg->users, ppCU, not);
    }
}

void
DefaultItemRo(char *id)
{
    CONDDEBUG((1, "DefaultItemRo(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserDefaultTemp->ro), id);
}

void
DefaultItemRw(char *id)
{
    CONDDEBUG((1, "DefaultItemRw(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserDefaultTemp->rw), id);
}

void
ProcessTimestamp(CONSENT *c, char *id)
{
    time_t tyme;
    char *p = (char *)0, *n = (char *)0;
    FLAG activity = FLAGFALSE, bactivity = FLAGFALSE, tactivity =
	FLAGFALSE;
    int factor = 0, pfactor = 0;
    int value = 0, pvalue = 0;

    if ((id == (char *)0) || (*id == '\000')) {
	c->breaklog = FLAGFALSE;
	c->tasklog = FLAGFALSE;
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
	} else if (*p == 't' || *p == 'T') {
	    if (n != (char *)0) {
		if (isMaster)
		    Error
			("invalid timestamp specification `%s': numeral before `t' (ignoring numeral) [%s:%d]",
			 id, file, line);
	    }
	    tactivity = FLAGTRUE;
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
	       "ProcessTimestamp(): mark spec of `%s' parsed: factor=%d, value=%d, activity=%d, bactivity=%d, tactivity=%d",
	       id, factor, value, activity, bactivity, tactivity));

    c->activitylog = activity;
    c->breaklog = bactivity;
    c->tasklog = tactivity;
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
DefaultItemTimestamp(char *id)
{
    CONDDEBUG((1, "DefaultItemTimestamp(%s) [%s:%d]", id, file, line));
    ProcessTimestamp(parserDefaultTemp, id);
}

void
ProcessType(CONSENT *c, char *id)
{
    CONSTYPE t = UNKNOWNTYPE;
    if ((id == (char *)0) || (*id == '\000')) {
	c->type = t;
	return;
    }
    if (strcasecmp("device", id) == 0)
	t = DEVICE;
#if HAVE_FREEIPMI
    else if (strcasecmp("ipmi", id) == 0)
	t = IPMI;
#endif
    else if (strcasecmp("exec", id) == 0)
	t = EXEC;
    else if (strcasecmp("host", id) == 0)
	t = HOST;
    else if (strcasecmp("noop", id) == 0)
	t = NOOP;
    else if (strcasecmp("uds", id) == 0)
	t = UDS;
    if (t == UNKNOWNTYPE) {
	if (isMaster)
	    Error("invalid console type `%s' [%s:%d]", id, file, line);
    } else
	c->type = t;
}

void
DefaultItemType(char *id)
{
    CONDDEBUG((1, "DefaultItemType(%s) [%s:%d]", id, file, line));
    ProcessType(parserDefaultTemp, id);
}

/* 'console' handling */
CONSENT *parserConsoles = (CONSENT *)0;
CONSENT **parserConsolesTail = &parserConsoles;
CONSENT *parserConsoleTemp = (CONSENT *)0;

void
ConsoleBegin(char *id)
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

    if ((parserConsoleTemp->breaklist = StrDup("*")) == (char *)0)
	OutOfMem();
    if ((parserConsoleTemp->tasklist = StrDup("*")) == (char *)0)
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

/* returns 1 if there's an error, otherwise 0 */
int
CheckSubst(char *label, char *subst)
{
    int invalid = 0;

    ZeroSubstTokenCount();
    ProcessSubst(substData, (char **)0, (char **)0, label, subst);

    if (SubstTokenCount('p') && parserConsoleTemp->port == 0) {
	if (isMaster)
	    Error
		("[%s] console references 'port' in '%s' without defining 'port' attribute (ignoring %s) [%s:%d]",
		 parserConsoleTemp->server, label, label, file, line);
	invalid = 1;
    }

    if (SubstTokenCount('h') && parserConsoleTemp->host == (char *)0) {
	if (isMaster)
	    Error
		("[%s] console references 'host' in '%s' without defining 'host' attribute (ignoring %s) [%s:%d]",
		 parserConsoleTemp->server, label, label, file, line);
	invalid = 1;
    }

    return invalid;
}

void
ConsoleEnd(void)
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
	    if (parserConsoleTemp->execsubst != (char *)0) {
		if (CheckSubst("execsubst", parserConsoleTemp->execsubst)) {
		    free(parserConsoleTemp->execsubst);
		    parserConsoleTemp->execsubst = (char *)0;
		}
	    }
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
	    if (parserConsoleTemp->devicesubst != (char *)0) {
		if (CheckSubst
		    ("devicesubst", parserConsoleTemp->devicesubst)) {
		    free(parserConsoleTemp->devicesubst);
		    parserConsoleTemp->devicesubst = (char *)0;
		}
	    }
	    break;
#if HAVE_FREEIPMI
	case IPMI:
	    if (parserConsoleTemp->host == (char *)0) {
		if (isMaster)
		    Error("[%s] console missing 'host' attribute [%s:%d]",
			  parserConsoleTemp->server, file, line);
		invalid = 1;
	    }
	    break;
#endif
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
	case NOOP:
	    break;
	case UDS:
	    if (parserConsoleTemp->uds == (char *)0) {
		if (isMaster)
		    Error("[%s] console missing 'uds' attribute [%s:%d]",
			  parserConsoleTemp->server, file, line);
		invalid = 1;
	    }
	    if (parserConsoleTemp->udssubst != (char *)0) {
		if (CheckSubst("udssubst", parserConsoleTemp->udssubst)) {
		    free(parserConsoleTemp->udssubst);
		    parserConsoleTemp->udssubst = (char *)0;
		}
	    }
	    break;
	case UNKNOWNTYPE:
	    if (isMaster)
		Error("[%s] console type unknown %d [%s:%d]",
		      parserConsoleTemp->server, parserConsoleTemp->type,
		      file, line);
	    invalid = 1;
	    break;
    }
    if (parserConsoleTemp->initsubst != (char *)0 &&
	parserConsoleTemp->initcmd != (char *)0) {
	if (CheckSubst("initsubst", parserConsoleTemp->initsubst)) {
	    free(parserConsoleTemp->initsubst);
	    parserConsoleTemp->initsubst = (char *)0;
	}
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
ConsoleAbort(void)
{
    CONDDEBUG((1, "ConsoleAbort() [%s:%d]", file, line));
    DestroyParserDefaultOrConsole(parserConsoleTemp, (CONSENT **)0,
				  (CONSENT ***)0);
    parserConsoleTemp = (CONSENT *)0;
}

void
SwapStr(char **s1, char **s2)
{
    char *s;
    s = *s1;
    *s1 = *s2;
    *s2 = s;
}

void
ExpandLogfile(CONSENT *c, char *id)
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
ConsoleAdd(CONSENT *c)
{
    CONSENT *pCEmatch = (CONSENT *)0;
    GRPENT *pGEmatch = (GRPENT *)0, *pGEtmp = (GRPENT *)0;
    CONSCLIENT *pCLtmp = (CONSCLIENT *)0;

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
	if (pCEmatch->taskfile != (CONSFILE *)0) {
	    int taskfile = FileFDNum(pCEmatch->taskfile);
	    FD_SET(taskfile, &rinit);
	    if (maxfd < taskfile + 1)
		maxfd = taskfile + 1;
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
		SwapStr(&pCEmatch->logfile, &c->logfile);
		closeMatch = 0;
	    }
	} else if (pCEmatch->logfile != (char *)0 ||
		   c->logfile != (char *)0) {
	    SwapStr(&pCEmatch->logfile, &c->logfile);
	    closeMatch = 0;
	}
	if (pCEmatch->initcmd != (char *)0 && c->initcmd != (char *)0) {
	    if (strcmp(pCEmatch->initcmd, c->initcmd) != 0) {
		SwapStr(&pCEmatch->initcmd, &c->initcmd);
		/* only trigger reinit if we're running the old command */
		if (pCEmatch->initpid != 0)
		    closeMatch = 0;
	    }
	} else if (pCEmatch->initcmd != (char *)0 ||
		   c->initcmd != (char *)0) {
	    SwapStr(&pCEmatch->initcmd, &c->initcmd);
	    /* only trigger reinit if we're running the old command */
	    if (pCEmatch->initpid != 0)
		closeMatch = 0;
	}

	switch (pCEmatch->type) {
	    case EXEC:
		if (pCEmatch->exec != (char *)0 && c->exec != (char *)0) {
		    if (strcmp(pCEmatch->exec, c->exec) != 0) {
			SwapStr(&pCEmatch->exec, &c->exec);
			closeMatch = 0;
		    }
		} else if (pCEmatch->exec != (char *)0 ||
			   c->exec != (char *)0) {
		    SwapStr(&pCEmatch->exec, &c->exec);
		    closeMatch = 0;
		}
		if (pCEmatch->execuid != c->execuid) {
		    pCEmatch->execuid = c->execuid;
		    closeMatch = 0;
		}
		if (pCEmatch->execgid != c->execgid) {
		    pCEmatch->execgid = c->execgid;
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
			SwapStr(&pCEmatch->device, &c->device);
			closeMatch = 0;
		    }
		} else if (pCEmatch->device != (char *)0 ||
			   c->device != (char *)0) {
		    SwapStr(&pCEmatch->device, &c->device);
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
#if HAVE_FREEIPMI
	    case IPMI:
		if (pCEmatch->host != (char *)0 && c->host != (char *)0) {
		    if (strcasecmp(pCEmatch->host, c->host) != 0) {
			SwapStr(&pCEmatch->host, &c->host);
			closeMatch = 0;
		    }
		} else if (pCEmatch->host != (char *)0 ||
			   c->host != (char *)0) {
		    SwapStr(&pCEmatch->host, &c->host);
		    closeMatch = 0;
		}
		if (pCEmatch->username != (char *)0 &&
		    c->username != (char *)0) {
		    if (strcmp(pCEmatch->username, c->username) != 0) {
			SwapStr(&pCEmatch->username, &c->username);
			closeMatch = 0;
		    }
		} else if (pCEmatch->username != (char *)0 ||
			   c->username != (char *)0) {
		    SwapStr(&pCEmatch->username, &c->username);
		    closeMatch = 0;
		}
		if (pCEmatch->password != (char *)0 &&
		    c->password != (char *)0) {
		    if (strcmp(pCEmatch->password, c->password) != 0) {
			SwapStr(&pCEmatch->password, &c->password);
			closeMatch = 0;
		    }
		} else if (pCEmatch->password != (char *)0 ||
			   c->password != (char *)0) {
		    SwapStr(&pCEmatch->password, &c->password);
		    closeMatch = 0;
		}
		if (pCEmatch->ipmiprivlevel != c->ipmiprivlevel) {
		    pCEmatch->ipmiprivlevel = c->ipmiprivlevel;
		    closeMatch = 0;
		}
		if (pCEmatch->ipmiworkaround != c->ipmiworkaround) {
		    pCEmatch->ipmiworkaround = c->ipmiworkaround;
		    closeMatch = 0;
		}
		if (pCEmatch->ipmiciphersuite != c->ipmiciphersuite) {
		    pCEmatch->ipmiciphersuite = c->ipmiciphersuite;
		    closeMatch = 0;
		}
		if (pCEmatch->ipmikg->used != 0 &&
		    c->ipmikg->used == pCEmatch->ipmikg->used) {
		    if (
# if HAVE_MEMCMP
			   memcmp(pCEmatch->ipmikg->string, c->ipmikg,
				  c->ipmikg->used) != 0
# else
			   bcmp(pCEmatch->ipmikg->string, c->ipmikg,
				c->ipmikg->used) != 0
# endif
			) {
			BuildString((char *)0, pCEmatch->ipmikg);
			BuildStringN(c->ipmikg->string,
				     c->ipmikg->used - 1,
				     pCEmatch->ipmikg);
			closeMatch = 0;
		    }
		} else if (pCEmatch->ipmikg->used != 0 ||
			   c->ipmikg->used != 0) {
		    BuildString((char *)0, pCEmatch->ipmikg);
		    BuildStringN(c->ipmikg->string, c->ipmikg->used - 1,
				 pCEmatch->ipmikg);
		    closeMatch = 0;
		}
		break;
#endif /* freeipmi */
	    case HOST:
		if (pCEmatch->host != (char *)0 && c->host != (char *)0) {
		    if (strcasecmp(pCEmatch->host, c->host) != 0) {
			SwapStr(&pCEmatch->host, &c->host);
			closeMatch = 0;
		    }
		} else if (pCEmatch->host != (char *)0 ||
			   c->host != (char *)0) {
		    SwapStr(&pCEmatch->host, &c->host);
		    closeMatch = 0;
		}
		if (pCEmatch->netport != c->netport) {
		    pCEmatch->netport = c->netport;
		    closeMatch = 0;
		}
		break;
	    case NOOP:
		break;
	    case UDS:
		if (pCEmatch->uds != (char *)0 && c->uds != (char *)0) {
		    if (strcasecmp(pCEmatch->uds, c->uds) != 0) {
			SwapStr(&pCEmatch->uds, &c->uds);
			closeMatch = 0;
		    }
		} else if (pCEmatch->uds != (char *)0 ||
			   c->uds != (char *)0) {
		    SwapStr(&pCEmatch->uds, &c->uds);
		    closeMatch = 0;
		}
		break;
	    case UNKNOWNTYPE:
		break;
	}

	/* and now the rest (minus the "runtime" members - see below) */
	pCEmatch->idletimeout = c->idletimeout;
	if (pCEmatch->idletimeout != (time_t)0 &&
	    (timers[T_CIDLE] == (time_t)0 ||
	     timers[T_CIDLE] >
	     pCEmatch->lastWrite + pCEmatch->idletimeout))
	    timers[T_CIDLE] = pCEmatch->lastWrite + pCEmatch->idletimeout;

	pCEmatch->logfilemax = c->logfilemax;
	if (pCEmatch->logfilemax != (off_t) 0 &&
	    timers[T_ROLL] == (time_t)0)
	    timers[T_ROLL] = time((time_t *)0);

	SwapStr(&pCEmatch->motd, &c->motd);
	SwapStr(&pCEmatch->idlestring, &c->idlestring);
	SwapStr(&pCEmatch->replstring, &c->breaklist);
	SwapStr(&pCEmatch->tasklist, &c->tasklist);
	SwapStr(&pCEmatch->breaklist, &c->tasklist);
	pCEmatch->portinc = c->portinc;
	pCEmatch->portbase = c->portbase;
	pCEmatch->spinmax = c->spinmax;
	pCEmatch->spintimer = c->spintimer;
	pCEmatch->activitylog = c->activitylog;
	pCEmatch->breaklog = c->breaklog;
	pCEmatch->tasklog = c->tasklog;
	pCEmatch->raw = c->raw;
	pCEmatch->mark = c->mark;
	pCEmatch->nextMark = c->nextMark;
	pCEmatch->breakNum = c->breakNum;
	pCEmatch->ondemand = c->ondemand;
	pCEmatch->striphigh = c->striphigh;
	pCEmatch->reinitoncc = c->reinitoncc;
	pCEmatch->autoreinit = c->autoreinit;
	pCEmatch->unloved = c->unloved;
	pCEmatch->login = c->login;
	pCEmatch->inituid = c->inituid;
	pCEmatch->initgid = c->initgid;
	while (pCEmatch->aliases != (NAMES *)0) {
	    NAMES *name;
	    name = pCEmatch->aliases->next;
	    if (pCEmatch->aliases->name != (char *)0)
		free(pCEmatch->aliases->name);
	    free(pCEmatch->aliases);
	    pCEmatch->aliases = name;
	}
	pCEmatch->aliases = c->aliases;
	c->aliases = (NAMES *)0;

	/* we have to override the ro/rw lists... */
	/* so first destroy the existing (which point to freed space anyway) */
	DestroyConsentUsers(&(pCEmatch->ro));
	DestroyConsentUsers(&(pCEmatch->rw));
	/* now copy over the new stuff */
	CopyConsentUserList(c->ro, &(pCEmatch->ro), 0);
	CopyConsentUserList(c->rw, &(pCEmatch->rw), 0);

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
ConsoleDestroy(void)
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

#if HAVE_FREEIPMI
	if (c->ipmiprivlevel == 0)
	    c->ipmiprivlevel = IPMIL_ADMIN;
	c->ipmiprivlevel--;

	if (c->ipmiciphersuite == 0)
	    c->ipmiciphersuite = 1;
	c->ipmiciphersuite -= 2;

	if (c->ipmikg == (STRING *)0)
	    c->ipmikg = AllocString();

	if (c->ipmiwrkset == 0) {
	    c->ipmiworkaround = IPMICONSOLE_WORKAROUND_DEFAULT;
	    c->ipmiwrkset = 1;
	}
#endif

	/* default break number */
	if (c->breakNum == 0)
	    c->breakNum = 1;

	/* initspin* values are +1, so adjust (since we don't
	 * compare on a reread)
	 */
	if (c->spinmax == 0)
	    c->spinmax = 5;
	else
	    c->spinmax--;
	if (c->spintimer == 0)
	    c->spintimer = 1;
	else
	    c->spintimer--;

	/* portbase, portinc, and port values are +2, +1, +1, so a zero can
	 * show that no value was given.  defaults: portbase=0, portinc=1
	 */
	if (c->portbase != 0)
	    c->portbase -= 2;
	if (c->portinc != 0)
	    c->portinc--;
	else
	    c->portinc = 1;

	/* if this is ever false, we don't actually use the port value, so
	 * doesn't matter if we "default" to zero...it's all enforced in
	 * ConsoleEnd()
	 */
	if (c->port != 0)
	    c->port--;

	/* now calculate the "real" port number */

	/* this formula could give -1 because
	 * portbase >= -1, portinc >= 0, and port >= 0
	 * since it's an unsigned type, it'll wrap back around
	 * look very, very, bizarre.  but, oh well.  yeah, a
	 * user can shoot himself in the foot with a bad config
	 * file, but it won't hurt too much.
	 */
	c->netport = c->portbase + c->portinc * c->port;

	/* prepare for substitutions */
	substData->data = (void *)c;

	/* check for substitutions */
	if (c->type == DEVICE && c->devicesubst != (char *)0)
	    ProcessSubst(substData, &(c->device), (char **)0, (char *)0,
			 c->devicesubst);

	if (c->type == EXEC && c->execsubst != (char *)0)
	    ProcessSubst(substData, &(c->exec), (char **)0, (char *)0,
			 c->execsubst);

	if (c->type == UDS && c->udssubst != (char *)0)
	    ProcessSubst(substData, &(c->uds), (char **)0, (char *)0,
			 c->udssubst);

	if (c->initcmd != (char *)0 && c->initsubst != (char *)0)
	    ProcessSubst(substData, &(c->initcmd), (char **)0, (char *)0,
			 c->initsubst);

	/* go ahead and do the '&' substitution */
	if (c->logfile != (char *)0) {
	    char *lf;
	    lf = c->logfile;
	    ExpandLogfile(c, lf);
	    free(lf);
	}

	/* set the idlestring default, if needed */
	if (c->idlestring == (char *)0 &&
	    (c->idlestring = StrDup("\\n")) == (char *)0)
	    OutOfMem();

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
	if (c->raw == FLAGUNKNOWN)
	    c->raw = FLAGFALSE;
	if (c->breaklog == FLAGUNKNOWN)
	    c->breaklog = FLAGFALSE;
	if (c->tasklog == FLAGUNKNOWN)
	    c->tasklog = FLAGFALSE;
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
	if (c->login == FLAGUNKNOWN)
	    c->login = FLAGTRUE;

	/* set some forced options, based on situations */
	if (c->type == NOOP) {
	    c->login = FLAGFALSE;
	    ProcessLogfile(c, (char *)0);
	}

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

	/* perform all post-processing checks */
	if (c->type == UDS) {
	    struct sockaddr_un port;
	    int limit, len;

	    limit = sizeof(port.sun_path);
	    len = strlen(c->uds);

	    if (len >= limit) {
		if (isMaster)
		    Error("[%s] 'uds' path too large (%d >= %d) [%s:%d]",
			  c->server, len, limit, file, line);
		continue;
	    }
	}

	if (fSyntaxOnly > 1) {
	    static STRING *s = (STRING *)0;

	    if (s == (STRING *)0)
		s = AllocString();

	    BuildString((char *)0, s);
	    BuildString(BuildTmpStringPrint
			("{%s:%s:", c->server, c->master), s);
	    if (c->aliases != (NAMES *)0) {
		NAMES *n;
		for (n = c->aliases; n != (NAMES *)0; n = n->next) {
		    if (n == c->aliases)
			BuildStringChar(',', s);
		    BuildString(n->name, s);
		}
	    }
	    BuildStringChar(':', s);
	    switch (c->type) {
		case EXEC:
		    BuildString(BuildTmpStringPrint
				("|:%s",
				 (c->exec !=
				  (char *)0 ? c->exec : "/bin/sh")), s);
		    break;
		case HOST:
		    BuildString(BuildTmpStringPrint
				("!:%s,%hu", c->host, c->netport), s);
		    break;
		case NOOP:
		    BuildString("#:", s);
		    break;
		case UDS:
		    BuildString(BuildTmpStringPrint("%%:%s", c->uds), s);
		    break;
		case DEVICE:
		    BuildString(BuildTmpStringPrint
				("/:%s,%s%c", c->device,
				 (c->baud ? c->baud->acrate : ""),
				 (c->parity ? c->parity->key[0] : ' ')),
				s);
		    break;
#if HAVE_FREEIPMI
		case IPMI:
		    BuildString(BuildTmpStringPrint("@:%s", c->host), s);
#endif
		case UNKNOWNTYPE:	/* shut up gcc */
		    break;
	    }
	    BuildStringChar('}', s);
	    Msg("%s", s->string);
	}
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
    if (!isMaster && pGroups != (GRPENT *)0) {
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
			BumpClient(pCE, (char *)0);
			TagLogfileAct(pCE, "%s detached",
				      pCL->acid->string);
			if (pCE->nolog) {
			    pCE->nolog = 0;
			    TagLogfile(pCE,
				       "Console logging restored (bumped)");
			}
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
FindConsoleName(CONSENT *c, char *id)
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
ConsoleItemAliases(char *id)
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
ConsoleItemBaud(char *id)
{
    CONDDEBUG((1, "ConsoleItemBaud(%s) [%s:%d]", id, file, line));
    ProcessBaud(parserConsoleTemp, id);
}

void
ConsoleItemBreak(char *id)
{
    CONDDEBUG((1, "ConsoleItemBreak(%s) [%s:%d]", id, file, line));
    ProcessBreak(parserConsoleTemp, id);
}

void
ConsoleItemDevice(char *id)
{
    CONDDEBUG((1, "ConsoleItemDevice(%s) [%s:%d]", id, file, line));
    ProcessDevice(parserConsoleTemp, id);
}

void
ConsoleItemDevicesubst(char *id)
{
    CONDDEBUG((1, "ConsoleItemDevicesubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserConsoleTemp->devicesubst),
		 "devicesubst", id);
}

void
ConsoleItemExecsubst(char *id)
{
    CONDDEBUG((1, "ConsoleItemExecsubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserConsoleTemp->execsubst),
		 "execsubst", id);
}

void
ConsoleItemUdssubst(char *id)
{
    CONDDEBUG((1, "ConsoleItemUdssubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserConsoleTemp->udssubst),
		 "udssubst", id);
}

void
ConsoleItemInitsubst(char *id)
{
    CONDDEBUG((1, "ConsoleItemInitsubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserConsoleTemp->initsubst),
		 "initsubst", id);
}

void
ConsoleItemInitrunas(char *id)
{
    CONDDEBUG((1, "ConsoleItemInitrunas(%s) [%s:%d]", id, file, line));
    ProcessInitrunas(parserConsoleTemp, id);
}

void
ConsoleItemExecrunas(char *id)
{
    CONDDEBUG((1, "ConsoleItemExecrunas(%s) [%s:%d]", id, file, line));
    ProcessExecrunas(parserConsoleTemp, id);
}

void
ConsoleItemExec(char *id)
{
    CONDDEBUG((1, "ConsoleItemExec(%s) [%s:%d]", id, file, line));
    ProcessExec(parserConsoleTemp, id);
}

void
ConsoleItemFlow(char *id)
{
    CONDDEBUG((1, "ConsoleItemFlow(%s) [%s:%d]", id, file, line));
    ProcessFlow(parserConsoleTemp, id);
}

void
ConsoleItemHost(char *id)
{
    CONDDEBUG((1, "ConsoleItemHost(%s) [%s:%d]", id, file, line));
    ProcessHost(parserConsoleTemp, id);
}

void
ConsoleItemUds(char *id)
{
    CONDDEBUG((1, "ConsoleItemUds(%s) [%s:%d]", id, file, line));
    ProcessUds(parserConsoleTemp, id);
}

#if HAVE_FREEIPMI
void
ConsoleItemIpmiKG(char *id)
{
    CONDDEBUG((1, "ConsoleItemIpmiKG(%s) [%s:%d]", id, file, line));
    ProcessIpmiKG(parserConsoleTemp, id);
}

void
ConsoleItemUsername(char *id)
{
    CONDDEBUG((1, "ConsoleItemUsername(%s) [%s:%d]", id, file, line));
    ProcessUsername(parserConsoleTemp, id);
}

void
ConsoleItemIpmiCipherSuite(char *id)
{
    CONDDEBUG((1, "ConsoleItemIpmiCipherSuite(%s) [%s:%d]", id, file,
	       line));
    ProcessIpmiCipherSuite(parserConsoleTemp, id);
}

void
ConsoleItemIpmiWorkaround(char *id)
{
    CONDDEBUG((1, "ConsoleItemIpmiWorkaround(%s) [%s:%d]", id, file,
	       line));
    ProcessIpmiWorkaround(parserConsoleTemp, id);
}
#endif /*freeipmi */

void
ConsoleItemInclude(char *id)
{
    CONDDEBUG((1, "ConsoleItemInclude(%s) [%s:%d]", id, file, line));
    ProcessInclude(parserConsoleTemp, id);
}

void
ConsoleItemLogfile(char *id)
{
    CONDDEBUG((1, "ConsoleItemLogfile(%s) [%s:%d]", id, file, line));
    ProcessLogfile(parserConsoleTemp, id);
}

void
ConsoleItemLogfilemax(char *id)
{
    CONDDEBUG((1, "ConsoleItemLogfilemax(%s) [%s:%d]", id, file, line));
    ProcessLogfilemax(parserConsoleTemp, id);
}

void
ConsoleItemInitcmd(char *id)
{
    CONDDEBUG((1, "ConsoleItemInitcmd(%s) [%s:%d]", id, file, line));
    ProcessInitcmd(parserConsoleTemp, id);
}

void
ConsoleItemMOTD(char *id)
{
    CONDDEBUG((1, "ConsoleItemMOTD(%s) [%s:%d]", id, file, line));
    ProcessMOTD(parserConsoleTemp, id);
}

void
ConsoleItemIdlestring(char *id)
{
    CONDDEBUG((1, "ConsoleItemIdlestring(%s) [%s:%d]", id, file, line));
    ProcessIdlestring(parserConsoleTemp, id);
}

void
ConsoleItemMaster(char *id)
{
    CONDDEBUG((1, "ConsoleItemMaster(%s) [%s:%d]", id, file, line));
    ProcessMaster(parserConsoleTemp, id);
}

void
ConsoleItemOptions(char *id)
{
    CONDDEBUG((1, "ConsoleItemOptions(%s) [%s:%d]", id, file, line));
    ProcessOptions(parserConsoleTemp, id);
}

void
ConsoleItemParity(char *id)
{
    CONDDEBUG((1, "ConsoleItemParity(%s) [%s:%d]", id, file, line));
    ProcessParity(parserConsoleTemp, id);
}

#if HAVE_FREEIPMI
void
ConsoleItemPassword(char *id)
{
    CONDDEBUG((1, "ConsoleItemPassword(%s) [%s:%d]", id, file, line));
    ProcessPassword(parserConsoleTemp, id);
}
#endif /*freeipmi */

void
ConsoleItemPort(char *id)
{
    CONDDEBUG((1, "ConsoleItemPort(%s) [%s:%d]", id, file, line));
    ProcessPort(parserConsoleTemp, id);
}

void
ConsoleItemPortbase(char *id)
{
    CONDDEBUG((1, "ConsoleItemPortbase(%s) [%s:%d]", id, file, line));
    ProcessPortbase(parserConsoleTemp, id);
}

void
ConsoleItemPortinc(char *id)
{
    CONDDEBUG((1, "ConsoleItemPortinc(%s) [%s:%d]", id, file, line));
    ProcessPortinc(parserConsoleTemp, id);
}

void
ConsoleItemInitspinmax(char *id)
{
    CONDDEBUG((1, "ConsoleItemInitspinmax(%s) [%s:%d]", id, file, line));
    ProcessInitspinmax(parserConsoleTemp, id);
}

void
ConsoleItemInitspintimer(char *id)
{
    CONDDEBUG((1, "ConsoleItemInitspintimer(%s) [%s:%d]", id, file, line));
    ProcessInitspintimer(parserConsoleTemp, id);
}

void
ConsoleItemProtocol(char *id)
{
    CONDDEBUG((1, "ConsoleItemProtocol(%s) [%s:%d]", id, file, line));
    ProcessProtocol(parserConsoleTemp, id);
}

void
ConsoleItemReplstring(char *id)
{
    CONDDEBUG((1, "ConsoleItemReplstring(%s) [%s:%d]", id, file, line));
    ProcessReplstring(parserConsoleTemp, id);
}

void
ConsoleItemTasklist(char *id)
{
    CONDDEBUG((1, "ConsoleItemTasklist(%s) [%s:%d]", id, file, line));
    ProcessTasklist(parserConsoleTemp, id);
}

void
ConsoleItemBreaklist(char *id)
{
    CONDDEBUG((1, "ConsoleItemBreaklist(%s) [%s:%d]", id, file, line));
    ProcessBreaklist(parserConsoleTemp, id);
}

void
ConsoleItemIdletimeout(char *id)
{
    CONDDEBUG((1, "ConsoleItemIdletimeout(%s) [%s:%d]", id, file, line));
    ProcessIdletimeout(parserConsoleTemp, id);
}

void
ConsoleItemRo(char *id)
{
    CONDDEBUG((1, "ConsoleItemRo(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserConsoleTemp->ro), id);
}

void
ConsoleItemRw(char *id)
{
    CONDDEBUG((1, "ConsoleItemRw(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserConsoleTemp->rw), id);
}

void
ConsoleItemTimestamp(char *id)
{
    CONDDEBUG((1, "ConsoleItemTimestamp(%s) [%s:%d]", id, file, line));
    ProcessTimestamp(parserConsoleTemp, id);
}

void
ConsoleItemType(char *id)
{
    CONDDEBUG((1, "ConsoleItemType(%s) [%s:%d]", id, file, line));
    ProcessType(parserConsoleTemp, id);
}

/* 'access' handling */
typedef struct parserAccess {
    STRING *name;
    ACCESS *access;
    CONSENTUSERS *admin;
    CONSENTUSERS *limited;
    struct parserAccess *next;
} PARSERACCESS;

PARSERACCESS *parserAccesses = (PARSERACCESS *)0;
PARSERACCESS **parserAccessesTail = &parserAccesses;
PARSERACCESS *parserAccessTemp = (PARSERACCESS *)0;

void
DestroyParserAccess(PARSERACCESS *pa)
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
    DestroyConsentUsers(&(pa->limited));
    free(pa);
    CONDDEBUG((2, "DestroyParserAccess(): %s", m));
}

PARSERACCESS *
AccessFind(char *id)
{
    PARSERACCESS *pa;
    for (pa = parserAccesses; pa != (PARSERACCESS *)0; pa = pa->next) {
	if (strcasecmp(id, pa->name->string) == 0)
	    return pa;
    }
    return pa;
}

void
AccessAddACL(PARSERACCESS *pa, ACCESS *access)
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
AccessBegin(char *id)
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
AccessEnd(void)
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
AccessAbort(void)
{
    CONDDEBUG((1, "AccessAbort() [%s:%d]", file, line));
    DestroyParserAccess(parserAccessTemp);
    parserAccessTemp = (PARSERACCESS *)0;
}

void
AccessDestroy(void)
{
    ACCESS *a;
    PARSERACCESS *p;
    ACCESS **ppa;
    CONSENTUSERS **pad;
    CONSENTUSERS **plu;

    CONDDEBUG((1, "AccessDestroy() [%s:%d]", file, line));

    /* clean out the access restrictions */
    while (pACList != (ACCESS *)0) {
	a = pACList->pACnext;
	DestroyAccessList(pACList);
	pACList = a;
    }
    pACList = (ACCESS *)0;

    DestroyConsentUsers(&(pADList));
    DestroyConsentUsers(&(pLUList));
    pADList = (CONSENTUSERS *)0;
    pLUList = (CONSENTUSERS *)0;

    ppa = &(pACList);
    pad = &(pADList);
    plu = &(pLUList);

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
	    for (u = p->limited; u != (CONSENTUSERS *)0; u = u->next) {
		Msg("    Limited = %s", u->user->name);
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
	    /* add any limited users to the list */
	    if (p->limited != (CONSENTUSERS *)0) {
		*plu = p->limited;
		p->limited = (CONSENTUSERS *)0;
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
	    while (*plu != (CONSENTUSERS *)0) {
		plu = &((*plu)->next);
	    }
	}
    }

    while (parserAccesses != (PARSERACCESS *)0)
	DestroyParserAccess(parserAccesses);
    DestroyParserAccess(parserAccessTemp);
    parserAccesses = parserAccessTemp = (PARSERACCESS *)0;
}

void
AccessItemAdmin(char *id)
{
    CONDDEBUG((1, "AccessItemAdmin(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserAccessTemp->admin), id);
}

void
AccessItemLimited(char *id)
{
    CONDDEBUG((1, "AccessItemLimited(%s) [%s:%d]", id, file, line));
    ProcessRoRw(&(parserAccessTemp->limited), id);
}

void
AccessItemInclude(char *id)
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
	    if (pa->admin != (CONSENTUSERS *)0)
		CopyConsentUserList(pa->admin, &(parserAccessTemp->admin),
				    0);
	    if (pa->limited != (CONSENTUSERS *)0)
		CopyConsentUserList(pa->limited,
				    &(parserAccessTemp->limited), 0);
	}
    }
}

void
AccessProcessACL(char trust, char *acl)
{
    char *token = (char *)0;
    ACCESS **ppa = (ACCESS **)0;
    ACCESS *pa = (ACCESS *)0;
#if HAVE_INET_ATON
    struct in_addr inetaddr;
#else
    in_addr_t addr;
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
		break;
	    }
	}
	if (*ppa == (ACCESS *)0)
	    *ppa = pa;		/* add to end of list */
    }
}

void
AccessItemAllowed(char *id)
{
    CONDDEBUG((1, "AccessItemAllowed(%s) [%s:%d]", id, file, line));
    AccessProcessACL('a', id);
}

void
AccessItemRejected(char *id)
{
    CONDDEBUG((1, "AccessItemRejected(%s) [%s:%d]", id, file, line));
    AccessProcessACL('r', id);
}

void
AccessItemTrusted(char *id)
{
    CONDDEBUG((1, "AccessItemTrusted(%s) [%s:%d]", id, file, line));
    AccessProcessACL('t', id);
}

/* 'config' handling */
CONFIG *parserConfigTemp = (CONFIG *)0;

void
DestroyConfig(CONFIG *c)
{
    if (c == (CONFIG *)0)
	return;
    if (c->logfile != (char *)0)
	free(c->logfile);
    if (c->passwdfile != (char *)0)
	free(c->passwdfile);
    if (c->primaryport != (char *)0)
	free(c->primaryport);
    if (c->secondaryport != (char *)0)
	free(c->secondaryport);
    if (c->unifiedlog != (char *)0)
	free(c->unifiedlog);
#if HAVE_OPENSSL
    if (c->sslcredentials != (char *)0)
	free(c->sslcredentials);
    if (c->sslcacertificatefile != (char *)0)
	free(c->sslcacertificatefile);
#endif
    free(c);
}

void
ConfigBegin(char *id)
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
ConfigEnd(void)
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
	    if (parserConfigTemp->passwdfile != (char *)0) {
		if (pConfig->passwdfile != (char *)0)
		    free(pConfig->passwdfile);
		pConfig->passwdfile = parserConfigTemp->passwdfile;
		parserConfigTemp->passwdfile = (char *)0;
	    }
	    if (parserConfigTemp->unifiedlog != (char *)0) {
		if (pConfig->unifiedlog != (char *)0)
		    free(pConfig->unifiedlog);
		pConfig->unifiedlog = parserConfigTemp->unifiedlog;
		parserConfigTemp->unifiedlog = (char *)0;
	    }
	    if (parserConfigTemp->primaryport != (char *)0) {
		if (pConfig->primaryport != (char *)0)
		    free(pConfig->primaryport);
		pConfig->primaryport = parserConfigTemp->primaryport;
		parserConfigTemp->primaryport = (char *)0;
	    }
	    if (parserConfigTemp->defaultaccess != '\000')
		pConfig->defaultaccess = parserConfigTemp->defaultaccess;
	    if (parserConfigTemp->autocomplete != FLAGUNKNOWN)
		pConfig->autocomplete = parserConfigTemp->autocomplete;
	    if (parserConfigTemp->daemonmode != FLAGUNKNOWN)
		pConfig->daemonmode = parserConfigTemp->daemonmode;
	    if (parserConfigTemp->redirect != FLAGUNKNOWN)
		pConfig->redirect = parserConfigTemp->redirect;
	    if (parserConfigTemp->loghostnames != FLAGUNKNOWN)
		pConfig->loghostnames = parserConfigTemp->loghostnames;
	    if (parserConfigTemp->reinitcheck != 0)
		pConfig->reinitcheck = parserConfigTemp->reinitcheck;
	    if (parserConfigTemp->initdelay != 0)
		pConfig->initdelay = parserConfigTemp->initdelay;
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
	    if (parserConfigTemp->sslcacertificatefile != (char *)0) {
		if (pConfig->sslcacertificatefile != (char *)0)
		    free(pConfig->sslcacertificatefile);
		pConfig->sslcacertificatefile =
		    parserConfigTemp->sslcacertificatefile;
		parserConfigTemp->sslcacertificatefile = (char *)0;
	    }
	    if (parserConfigTemp->sslrequired != FLAGUNKNOWN)
		pConfig->sslrequired = parserConfigTemp->sslrequired;
	    if (parserConfigTemp->sslreqclientcert != FLAGUNKNOWN)
		pConfig->sslreqclientcert =
		    parserConfigTemp->sslreqclientcert;
#endif
#if HAVE_SETPROCTITLE
	    if (parserConfigTemp->setproctitle != FLAGUNKNOWN)
		pConfig->setproctitle = parserConfigTemp->setproctitle;
#endif
	}
    }

    DestroyConfig(parserConfigTemp);
    parserConfigTemp = (CONFIG *)0;
}

void
ConfigAbort(void)
{
    CONDDEBUG((1, "ConfigAbort() [%s:%d]", file, line));
    if (parserConfigTemp == (CONFIG *)0)
	return;

    DestroyConfig(parserConfigTemp);
    parserConfigTemp = (CONFIG *)0;
}

void
ConfigDestroy(void)
{
    CONDDEBUG((1, "ConfigDestroy() [%s:%d]", file, line));
    if (parserConfigTemp == (CONFIG *)0)
	return;

    DestroyConfig(parserConfigTemp);
    parserConfigTemp = (CONFIG *)0;
}

void
ConfigItemDefaultaccess(char *id)
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

#if HAVE_FREEIPMI
void
ConsoleItemIpmiPrivLevel(char *id)
{
    CONDDEBUG((1, "ConsoleItemIpmiPrivLevel(%s) [%s:%d]", id, file, line));
    ProcessIpmiPrivLevel(parserConsoleTemp, id);
}
#endif /*freeipmi */

void
ConfigItemAutocomplete(char *id)
{
    CONDDEBUG((1, "ConfigItemAutocomplete(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserConfigTemp->autocomplete));
}

void
ConfigItemDaemonmode(char *id)
{
    CONDDEBUG((1, "ConfigItemDaemonmode(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserConfigTemp->daemonmode));
}

void
ConfigItemLogfile(char *id)
{
    CONDDEBUG((1, "ConfigItemLogfile(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->logfile != (char *)0)
	free(parserConfigTemp->logfile);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->logfile = (char *)0;
	return;
    }
    if ((parserConfigTemp->logfile = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
ConfigItemPasswordfile(char *id)
{
    CONDDEBUG((1, "ConfigItemPasswordfile(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->passwdfile != (char *)0)
	free(parserConfigTemp->passwdfile);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->passwdfile = (char *)0;
	return;
    }
    if ((parserConfigTemp->passwdfile = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
ConfigItemUnifiedlog(char *id)
{
    CONDDEBUG((1, "ConfigItemUnifiedlog(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->unifiedlog != (char *)0)
	free(parserConfigTemp->unifiedlog);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->unifiedlog = (char *)0;
	return;
    }

    if ((parserConfigTemp->unifiedlog = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
ConfigItemPrimaryport(char *id)
{
    CONDDEBUG((1, "ConfigItemPrimaryport(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->primaryport != (char *)0)
	free(parserConfigTemp->primaryport);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->primaryport = (char *)0;
	return;
    }
    if ((parserConfigTemp->primaryport = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
ConfigItemRedirect(char *id)
{
    CONDDEBUG((1, "ConfigItemRedirect(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserConfigTemp->redirect));
}

void
ConfigItemLoghostnames(char *id)
{
    CONDDEBUG((1, "ConfigItemLoghostnames(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserConfigTemp->loghostnames));
}

void
ConfigItemReinitcheck(char *id)
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

    /* if it wasn't a number */
    if (*p != '\000') {
	if (isMaster)
	    Error("invalid reinitcheck value `%s' [%s:%d]", id, file,
		  line);
	return;
    }
    parserConfigTemp->reinitcheck = atoi(id);
}

void
ConfigItemInitdelay(char *id)
{
    char *p;

    CONDDEBUG((1, "ConfigItemInitdelay(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->initdelay = 0;
	return;
    }

    for (p = id; *p != '\000'; p++)
	if (!isdigit((int)(*p)))
	    break;

    /* if it wasn't a number */
    if (*p != '\000') {
	if (isMaster)
	    Error("invalid initdelay value `%s' [%s:%d]", id, file, line);
	return;
    }
    parserConfigTemp->initdelay = atoi(id);
}

void
ConfigItemSecondaryport(char *id)
{
    CONDDEBUG((1, "ConfigItemSecondaryport(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->secondaryport != (char *)0)
	free(parserConfigTemp->secondaryport);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->secondaryport = (char *)0;
	return;
    }
    if ((parserConfigTemp->secondaryport = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
ConfigItemSslcredentials(char *id)
{
    CONDDEBUG((1, "ConfigItemSslcredentials(%s) [%s:%d]", id, file, line));
#if HAVE_OPENSSL
    if (parserConfigTemp->sslcredentials != (char *)0)
	free(parserConfigTemp->sslcredentials);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->sslcredentials = (char *)0;
	return;
    }
    if ((parserConfigTemp->sslcredentials = StrDup(id)) == (char *)0)
	OutOfMem();
#else
    if (isMaster)
	Error
	    ("sslcredentials ignored - encryption not compiled into code [%s:%d]",
	     file, line);
#endif
}

void
ConfigItemSslcacertificatefile(char *id)
{
    CONDDEBUG((1, "ConfigItemSslcacertificatefile(%s) [%s:%d]", id, file,
	       line));
#if HAVE_OPENSSL
    if (parserConfigTemp->sslcacertificatefile != (char *)0)
	free(parserConfigTemp->sslcacertificatefile);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->sslcacertificatefile = (char *)0;
	return;
    }
    if ((parserConfigTemp->sslcacertificatefile = StrDup(id)) == (char *)0)
	OutOfMem();
#else
    if (isMaster)
	Error
	    ("sslcacertificatefile ignored - encryption not compiled into code [%s:%d]",
	     file, line);
#endif
}

void
ConfigItemSslrequired(char *id)
{
    CONDDEBUG((1, "ConfigItemSslrequired(%s) [%s:%d]", id, file, line));
#if HAVE_OPENSSL
    ProcessYesNo(id, &(parserConfigTemp->sslrequired));
#else
    if (isMaster)
	Error
	    ("sslrequired ignored - encryption not compiled into code [%s:%d]",
	     file, line);
#endif
}

void
ConfigItemSslreqclientcert(char *id)
{
    CONDDEBUG((1, "ConfigItemSslreqclientcert(%s) [%s:%d]", id, file,
	       line));
#if HAVE_OPENSSL
    ProcessYesNo(id, &(parserConfigTemp->sslreqclientcert));
#else
    if (isMaster)
	Error
	    ("sslreqclientcert ignored - encryption not compiled into code [%s:%d]",
	     file, line);
#endif
}

void
ConfigItemSetproctitle(char *id)
{
    CONDDEBUG((1, "ConfigItemSetproctitle(%s) [%s:%d]", id, file, line));
#if HAVE_SETPROCTITLE
    ProcessYesNo(id, &(parserConfigTemp->setproctitle));
#else
    if (isMaster)
	Error
	    ("setproctitle ignored - operating system support does not exist [%s:%d]",
	     file, line);
#endif
}

/* task parsing */
TASKS *parserTask;

void
TaskBegin(char *id)
{
    CONDDEBUG((1, "TaskBegin(%s) [%s:%d]", id, file, line));
    if (id == (char *)0 || id[0] == '\000' || id[1] != '\000' ||
	((id[0] < '0' || id[0] > '9') && (id[0] < 'a' || id[0] > 'z'))) {
	if (isMaster)
	    Error("invalid task id `%s' [%s:%d]", id, file, line);
    } else {
	if (parserTask == (TASKS *)0) {
	    if ((parserTask =
		 (TASKS *)calloc(1, sizeof(TASKS))) == (TASKS *)0)
		OutOfMem();
	    parserTask->cmd = AllocString();
	    parserTask->descr = AllocString();
	}
	if (taskSubst == (SUBST *)0) {
	    if ((taskSubst =
		 (SUBST *)calloc(1, sizeof(SUBST))) == (SUBST *)0)
		OutOfMem();
	    taskSubst->value = &SubstValue;
	    taskSubst->token = &SubstToken;
	}

	BuildString((char *)0, parserTask->cmd);
	BuildString((char *)0, parserTask->descr);
	parserTask->confirm = FLAGFALSE;
	parserTask->id = id[0];
    }
}

void
TaskEnd(void)
{
    TASKS *t;
    TASKS **prev;
    CONDDEBUG((1, "TaskEnd() [%s:%d]", file, line));

    /* skip this if we've marked it that way or if there is no command to run */
    if (parserTask == (TASKS *)0 || parserTask->id == ' ' ||
	parserTask->cmd->used <= 1)
	return;

    /* create an ordered list */
    prev = &taskList;
    t = taskList;
    while (t != (TASKS *)0 && t->id < parserTask->id) {
	prev = &(t->next);
	t = t->next;
    }
    *prev = parserTask;
    if (t != (TASKS *)0 && parserTask->id == t->id) {
	parserTask->next = t->next;
	DestroyTask(t);
    } else {
	parserTask->next = t;
    }
    parserTask = (TASKS *)0;
}

void
TaskAbort(void)
{
    CONDDEBUG((1, "TaskAbort() [%s:%d]", file, line));
    if (parserTask == (TASKS *)0 || parserTask->id == ' ')
	return;

    parserTask->id = ' ';
}

void
TaskDestroy(void)
{
    CONDDEBUG((1, "TaskDestroy() [%s:%d]", file, line));
    if (parserTask != (TASKS *)0) {
	DestroyTask(parserTask);
	parserTask = (TASKS *)0;
    }
}

void
TaskItemRunas(char *id)
{
    CONDDEBUG((1, "TaskItemRunas(%s) [%s:%d]", id, file, line));
    if (parserTask == (TASKS *)0 || parserTask->id == ' ')
	return;
    ProcessUidGid(&(parserTask->uid), &(parserTask->gid), id);
}

void
TaskItemSubst(char *id)
{
    CONDDEBUG((1, "TaskItemSubst(%s) [%s:%d]", id, file, line));
    if (parserTask == (TASKS *)0 || parserTask->id == ' ')
	return;
    ProcessSubst(taskSubst, (char **)0, &(parserTask->subst), "subst", id);
}

void
TaskItemCmd(char *id)
{
    CONDDEBUG((1, "TaskItemCmd(%s) [%s:%d]", id, file, line));
    if (parserTask == (TASKS *)0 || parserTask->id == ' ')
	return;
    BuildString((char *)0, parserTask->cmd);
    if ((id == (char *)0) || (*id == '\000'))
	return;
    BuildString(id, parserTask->cmd);
}

void
TaskItemDescr(char *id)
{
    CONDDEBUG((1, "TaskItemDescr(%s) [%s:%d]", id, file, line));
    if (parserTask == (TASKS *)0 || parserTask->id == ' ')
	return;
    BuildString((char *)0, parserTask->descr);
    if ((id == (char *)0) || (*id == '\000'))
	return;
    BuildString(id, parserTask->descr);
}

void
TaskItemConfirm(char *id)
{
    CONDDEBUG((1, "TaskItemConfirm(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserTask->confirm));
}

/* now all the real nitty-gritty bits for making things work */
ITEM keyTask[] = {
    {"cmd", TaskItemCmd},
    {"confirm", TaskItemConfirm},
    {"description", TaskItemDescr},
    {"runas", TaskItemRunas},
    {"subst", TaskItemSubst},
    {(char *)0, (void *)0}
};

ITEM keyBreak[] = {
    {"confirm", BreakItemConfirm},
    {"delay", BreakItemDelay},
    {"string", BreakItemString},
    {(char *)0, (void *)0}
};

ITEM keyGroup[] = {
    {"users", GroupItemUsers},
    {(char *)0, (void *)0}
};

ITEM keyDefault[] = {
    {"baud", DefaultItemBaud},
    {"break", DefaultItemBreak},
    {"breaklist", DefaultItemBreaklist},
    {"device", DefaultItemDevice},
    {"devicesubst", DefaultItemDevicesubst},
    {"exec", DefaultItemExec},
    {"execrunas", DefaultItemExecrunas},
    {"execsubst", DefaultItemExecsubst},
/*  {"flow", DefaultItemFlow}, */
    {"host", DefaultItemHost},
    {"idlestring", DefaultItemIdlestring},
    {"idletimeout", DefaultItemIdletimeout},
    {"include", DefaultItemInclude},
    {"initcmd", DefaultItemInitcmd},
    {"initrunas", DefaultItemInitrunas},
    {"initspinmax", DefaultItemInitspinmax},
    {"initspintimer", DefaultItemInitspintimer},
    {"initsubst", DefaultItemInitsubst},
    {"logfile", DefaultItemLogfile},
    {"logfilemax", DefaultItemLogfilemax},
    {"master", DefaultItemMaster},
    {"motd", DefaultItemMOTD},
    {"options", DefaultItemOptions},
    {"parity", DefaultItemParity},
    {"port", DefaultItemPort},
    {"portbase", DefaultItemPortbase},
    {"portinc", DefaultItemPortinc},
    {"protocol", DefaultItemProtocol},
    {"replstring", DefaultItemReplstring},
    {"ro", DefaultItemRo},
    {"rw", DefaultItemRw},
    {"tasklist", DefaultItemTasklist},
    {"timestamp", DefaultItemTimestamp},
    {"type", DefaultItemType},
    {"uds", DefaultItemUds},
    {"udssubst", DefaultItemUdssubst},
#if HAVE_FREEIPMI
    {"ipmiciphersuite", DefaultItemIpmiCipherSuite},
    {"ipmikg", DefaultItemIpmiKG},
    {"ipmiprivlevel", DefaultItemIpmiPrivLevel},
    {"ipmiworkaround", DefaultItemIpmiWorkaround},
    {"password", DefaultItemPassword},
    {"username", DefaultItemUsername},
#endif
    {(char *)0, (void *)0}
};

ITEM keyConsole[] = {
    {"aliases", ConsoleItemAliases},
    {"baud", ConsoleItemBaud},
    {"break", ConsoleItemBreak},
    {"breaklist", ConsoleItemBreaklist},
    {"device", ConsoleItemDevice},
    {"devicesubst", ConsoleItemDevicesubst},
    {"exec", ConsoleItemExec},
    {"execrunas", ConsoleItemExecrunas},
    {"execsubst", ConsoleItemExecsubst},
/*  {"flow", ConsoleItemFlow}, */
    {"host", ConsoleItemHost},
    {"idlestring", ConsoleItemIdlestring},
    {"idletimeout", ConsoleItemIdletimeout},
    {"include", ConsoleItemInclude},
    {"initcmd", ConsoleItemInitcmd},
    {"initrunas", ConsoleItemInitrunas},
    {"initspinmax", ConsoleItemInitspinmax},
    {"initspintimer", ConsoleItemInitspintimer},
    {"initsubst", ConsoleItemInitsubst},
    {"logfile", ConsoleItemLogfile},
    {"logfilemax", ConsoleItemLogfilemax},
    {"master", ConsoleItemMaster},
    {"motd", ConsoleItemMOTD},
    {"options", ConsoleItemOptions},
    {"parity", ConsoleItemParity},
    {"port", ConsoleItemPort},
    {"portbase", ConsoleItemPortbase},
    {"portinc", ConsoleItemPortinc},
    {"protocol", ConsoleItemProtocol},
    {"replstring", ConsoleItemReplstring},
    {"ro", ConsoleItemRo},
    {"rw", ConsoleItemRw},
    {"tasklist", ConsoleItemTasklist},
    {"timestamp", ConsoleItemTimestamp},
    {"type", ConsoleItemType},
    {"uds", ConsoleItemUds},
    {"udssubst", ConsoleItemUdssubst},
#if HAVE_FREEIPMI
    {"ipmiciphersuite", ConsoleItemIpmiCipherSuite},
    {"ipmikg", ConsoleItemIpmiKG},
    {"ipmiprivlevel", ConsoleItemIpmiPrivLevel},
    {"ipmiworkaround", ConsoleItemIpmiWorkaround},
    {"password", ConsoleItemPassword},
    {"username", ConsoleItemUsername},
#endif
    {(char *)0, (void *)0}
};

ITEM keyAccess[] = {
    {"admin", AccessItemAdmin},
    {"allowed", AccessItemAllowed},
    {"include", AccessItemInclude},
    {"limited", AccessItemLimited},
    {"rejected", AccessItemRejected},
    {"trusted", AccessItemTrusted},
    {(char *)0, (void *)0}
};

ITEM keyConfig[] = {
    {"autocomplete", ConfigItemAutocomplete},
    {"defaultaccess", ConfigItemDefaultaccess},
    {"daemonmode", ConfigItemDaemonmode},
    {"initdelay", ConfigItemInitdelay},
    {"logfile", ConfigItemLogfile},
    {"loghostnames", ConfigItemLoghostnames},
    {"passwdfile", ConfigItemPasswordfile},
    {"primaryport", ConfigItemPrimaryport},
    {"redirect", ConfigItemRedirect},
    {"reinitcheck", ConfigItemReinitcheck},
    {"secondaryport", ConfigItemSecondaryport},
    {"setproctitle", ConfigItemSetproctitle},
    {"sslcredentials", ConfigItemSslcredentials},
    {"sslcacertificatefile", ConfigItemSslcacertificatefile},
    {"sslrequired", ConfigItemSslrequired},
    {"sslreqclientcert", ConfigItemSslreqclientcert},
    {"unifiedlog", ConfigItemUnifiedlog},
    {(char *)0, (void *)0}
};

SECTION sections[] = {
    {"task", TaskBegin, TaskEnd, TaskAbort, TaskDestroy, keyTask},
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

void
ReadCfg(char *filename, FILE *fp)
{
    int i;
#if HAVE_DMALLOC && DMALLOC_MARK_READCFG
    unsigned long dmallocMarkReadCfg = 0;
#endif

#if HAVE_DMALLOC && DMALLOC_MARK_READCFG
    dmallocMarkReadCfg = dmalloc_mark();
#endif
    isStartup = (pGroups == (GRPENT *)0 && pRCList == (REMOTE *)0);

    /* initialize the break lists */
    for (i = 0; i < BREAKLISTSIZE; i++) {
	if (breakList[i].seq == (STRING *)0) {
	    breakList[i].seq = AllocString();
	} else {
	    BuildString((char *)0, breakList[i].seq);
	}
	breakList[i].delay = BREAKDELAYDEFAULT;
	breakList[i].confirm = FLAGFALSE;
    }
    BuildString("\\z", breakList[0].seq);
    BuildString("\\r~^b", breakList[1].seq);
    BuildString("#.", breakList[2].seq);
    BuildString("\\r\\d~\\d^b", breakList[3].seq);
    breakList[3].delay = 600;

    /* initialize the user list */
    DestroyUserList();

    /* initialize the task list */
    DestroyTaskList();

    /* initialize the config set */
    if (pConfig != (CONFIG *)0) {
	DestroyConfig(pConfig);
	pConfig = (CONFIG *)0;
    }
    if ((pConfig = (CONFIG *)calloc(1, sizeof(CONFIG))) == (CONFIG *)0)
	OutOfMem();

    /* initialize the substition bits */
    InitSubstCallback();

    /* ready to read in the data */
    ParseFile(filename, fp, 0);

#if HAVE_DMALLOC && DMALLOC_MARK_READCFG
    CONDDEBUG((1, "ReadCfg(): dmalloc / MarkReadCfg"));
    dmalloc_log_changed(dmallocMarkReadCfg, 1, 0, 1);
#endif
}

void
ReReadCfg(int fd, int msfd)
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
	    Msg("no consoles to manage in child process after reconfiguration - child exiting");
	    DeUtmp((GRPENT *)0, fd);
	}
    }

    /* check for changes to master & child values */
    if (optConf->logfile == (char *)0) {
	char *p;
	if (pConfig->logfile == (char *)0)
	    p = defConfig.logfile;
	else
	    p = pConfig->logfile;
	if (config->logfile == (char *)0 ||
	    strcmp(p, config->logfile) != 0) {
	    if (config->logfile != (char *)0)
		free(config->logfile);
	    if ((config->logfile = StrDup(p))
		== (char *)0)
		OutOfMem();
	    ReopenLogfile();
	}
    }

    /* check for changes to unifiedlog...this might (and does) have
     * a default of (char *)0, so it's slightly different than the
     * other code that does similar stuff (like logfile)
     */
    if (optConf->unifiedlog == (char *)0) {
	char *p;
	if (pConfig->unifiedlog == (char *)0)
	    p = defConfig.unifiedlog;
	else
	    p = pConfig->unifiedlog;
	if (config->unifiedlog == (char *)0 || p == (char *)0 ||
	    strcmp(p, config->unifiedlog) != 0) {
	    if (config->unifiedlog != (char *)0)
		free(config->unifiedlog);
	    if (p == (char *)0)
		config->unifiedlog = p;
	    else if ((config->unifiedlog = StrDup(p))
		     == (char *)0)
		OutOfMem();
	    ReopenUnifiedlog();
	}
    }

    if (optConf->defaultaccess == '\000') {
	if (pConfig->defaultaccess == '\000')
	    config->defaultaccess = defConfig.defaultaccess;
	else if (pConfig->defaultaccess != config->defaultaccess)
	    config->defaultaccess = pConfig->defaultaccess;
	/* gets used below by SetDefAccess() */
    }

    if (optConf->passwdfile == (char *)0) {
	char *p;
	if (pConfig->passwdfile == (char *)0)
	    p = defConfig.passwdfile;
	else
	    p = pConfig->passwdfile;
	if (config->passwdfile == (char *)0 ||
	    strcmp(p, config->passwdfile) != 0) {
	    if (config->passwdfile != (char *)0)
		free(config->passwdfile);
	    if ((config->passwdfile = StrDup(p))
		== (char *)0)
		OutOfMem();
	    /* gets used on-the-fly */
	}
    }

    if (optConf->redirect == FLAGUNKNOWN) {
	if (pConfig->redirect == FLAGUNKNOWN)
	    config->redirect = defConfig.redirect;
	else if (pConfig->redirect != config->redirect)
	    config->redirect = pConfig->redirect;
	/* gets used on-the-fly */
    }

    if (optConf->autocomplete == FLAGUNKNOWN) {
	if (pConfig->autocomplete == FLAGUNKNOWN)
	    config->autocomplete = defConfig.autocomplete;
	else if (pConfig->autocomplete != config->autocomplete)
	    config->autocomplete = pConfig->autocomplete;
	/* gets used on-the-fly */
    }

    if (optConf->loghostnames == FLAGUNKNOWN) {
	if (pConfig->loghostnames == FLAGUNKNOWN)
	    config->loghostnames = defConfig.loghostnames;
	else if (pConfig->loghostnames != config->loghostnames)
	    config->loghostnames = pConfig->loghostnames;
	/* gets used on-the-fly */
    }

    if (optConf->reinitcheck == 0) {
	if (pConfig->reinitcheck == 0)
	    config->reinitcheck = defConfig.reinitcheck;
	else if (pConfig->reinitcheck != config->reinitcheck)
	    config->reinitcheck = pConfig->reinitcheck;
	/* gets used on-the-fly */
    }

    if (optConf->initdelay == 0) {
	if (pConfig->initdelay == 0)
	    config->initdelay = defConfig.initdelay;
	else if (pConfig->initdelay != config->initdelay)
	    config->initdelay = pConfig->initdelay;
	/* gets used on-the-fly */
    }
#if HAVE_OPENSSL
    if (optConf->sslrequired == FLAGUNKNOWN) {
	if (pConfig->sslrequired == FLAGUNKNOWN)
	    config->sslrequired = defConfig.sslrequired;
	else if (pConfig->sslrequired != config->sslrequired)
	    config->sslrequired = pConfig->sslrequired;
	/* gets used on-the-fly */
    }
#endif

    /* if no one can use us we need to come up with a default
     */
    if (pACList == (ACCESS *)0)
#if USE_IPV6
	SetDefAccess();
#else
	SetDefAccess(myAddrs, myHostname);
#endif

    if (isMaster) {
	GRPENT *pGE;

	/* process any new options (command-line flags might have
	 * overridden things, so just need to check on new pConfig
	 * values for changes).
	 * the checks here produce warnings, and are inside the
	 * isMaster check so it only pops out once.
	 */
	if (optConf->daemonmode == FLAGUNKNOWN) {
	    if (pConfig->daemonmode == FLAGUNKNOWN)
		pConfig->daemonmode = defConfig.daemonmode;
	    if (pConfig->daemonmode != config->daemonmode) {
		config->daemonmode = pConfig->daemonmode;
		Msg("warning: `daemonmode' config option changed - you must restart for it to take effect");
	    }
	}
#if !USE_UNIX_DOMAIN_SOCKETS
	if (optConf->primaryport == (char *)0) {
	    char *p;
	    if (pConfig->primaryport == (char *)0)
		p = defConfig.primaryport;
	    else
		p = pConfig->primaryport;
	    if (config->primaryport == (char *)0 ||
		strcmp(p, config->primaryport) != 0) {
		if (config->primaryport != (char *)0)
		    free(config->primaryport);
		if ((config->primaryport = StrDup(p))
		    == (char *)0)
		    OutOfMem();
		Msg("warning: `primaryport' config option changed - you must restart for it to take effect");
	    }
	}
	if (optConf->secondaryport == (char *)0) {
	    char *p;
	    if (pConfig->secondaryport == (char *)0)
		p = defConfig.secondaryport;
	    else
		p = pConfig->secondaryport;
	    if (config->secondaryport == (char *)0 ||
		strcmp(p, config->secondaryport) != 0) {
		if (config->secondaryport != (char *)0)
		    free(config->secondaryport);
		if ((config->secondaryport = StrDup(p))
		    == (char *)0)
		    OutOfMem();
		Msg("warning: `secondaryport' config option changed - you must restart for it to take effect");
	    }
	}
#endif
#if HAVE_OPENSSL
	if (optConf->sslcredentials == (char *)0) {
	    if (pConfig->sslcredentials == (char *)0) {
		if (config->sslcredentials != (char *)0) {
		    free(config->sslcredentials);
		    config->sslcredentials = (char *)0;
		    Msg("warning: `sslcredentials' config option changed - you must restart for it to take effect");
		}
	    } else {
		if (config->sslcredentials == (char *)0 ||
		    strcmp(pConfig->sslcredentials,
			   config->sslcredentials) != 0) {
		    if (config->sslcredentials != (char *)0)
			free(config->sslcredentials);
		    if ((config->sslcredentials =
			 StrDup(pConfig->sslcredentials))
			== (char *)0)
			OutOfMem();
		    Msg("warning: `sslcredentials' config option changed - you must restart for it to take effect");
		}
	    }
	}
	if (optConf->sslcacertificatefile == (char *)0) {
	    if (pConfig->sslcacertificatefile == (char *)0) {
		if (config->sslcacertificatefile != (char *)0) {
		    free(config->sslcacertificatefile);
		    config->sslcacertificatefile = (char *)0;
		    Msg("warning: `sslcacertificatefile' config option changed - you must restart for it to take effect");
		}
	    } else {
		if (config->sslcacertificatefile == (char *)0 ||
		    strcmp(pConfig->sslcacertificatefile,
			   config->sslcacertificatefile) != 0) {
		    if (config->sslcacertificatefile != (char *)0)
			free(config->sslcacertificatefile);
		    if ((config->sslcacertificatefile =
			 StrDup(pConfig->sslcacertificatefile))
			== (char *)0)
			OutOfMem();
		    Msg("warning: `sslcacertificatefile' config option changed - you must restart for it to take effect");
		}
	    }
	}
	if (optConf->sslreqclientcert == FLAGUNKNOWN) {
	    if (pConfig->sslreqclientcert == FLAGUNKNOWN) {
		if (config->sslreqclientcert != defConfig.sslreqclientcert) {
		    Msg("warning: `sslreqclientcert' config option changed - you must restart for it to take effect");
		    config->sslreqclientcert = defConfig.sslreqclientcert;
		}
	    } else if (config->sslreqclientcert !=
		       pConfig->sslreqclientcert) {
		Msg("warning: `sslreqclientcert' config option changed - you must restart for it to take effect");
		config->sslreqclientcert = pConfig->sslreqclientcert;
	    }
	}
#endif
#if HAVE_SETPROCTITLE
	if (optConf->setproctitle == FLAGUNKNOWN) {
	    if (pConfig->setproctitle == FLAGUNKNOWN)
		pConfig->setproctitle = defConfig.setproctitle;
	    if (pConfig->setproctitle != config->setproctitle) {
		config->setproctitle = pConfig->setproctitle;
		Msg("warning: `setproctitle' config option changed - you must restart for it to take effect");
	    }
	}
#endif

	/* spawn all the children, so fix kids has an initial pid */
	for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
	    if (pGE->imembers == 0 || pGE->pid != -1)
		continue;

	    Spawn(pGE, msfd);

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
#if HAVE_SETPROCTITLE
    if (config->setproctitle == FLAGTRUE) {
	if (isMaster) {
	    REMOTE *pRC;
	    GRPENT *pGE;
	    int local = 0, remote = 0;
	    for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext)
		local += pGE->imembers;
	    for (pRC = pRCList; (REMOTE *)0 != pRC; pRC = pRC->pRCnext)
		remote++;
	    setproctitle("master: port %hu, %d local, %d remote", bindPort,
			 local, remote);
	} else
	    setproctitle("group %u: port %hu, %d %s", pGroups->id,
			 pGroups->port, pGroups->imembers,
			 pGroups->imembers == 1 ? "console" : "consoles");
    }
#endif
}
