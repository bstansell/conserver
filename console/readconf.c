/*
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#include <compat.h>

#include "cutil.h"
#include "readconf.h"

CONFIG *parserConfigTemp = (CONFIG *)0;
CONFIG *parserConfigDefault = (CONFIG *)0;
CONFIG *pConfig = (CONFIG *)0;
TERM *parserTermTemp = (TERM *)0;
TERM *parserTermDefault = (TERM *)0;
TERM *pTerm = (TERM *)0;

void
DestroyConfig(CONFIG *c)
{
    if (c == (CONFIG *)0)
	return;
    if (c->username != (char *)0)
	free(c->username);
    if (c->master != (char *)0)
	free(c->master);
    if (c->port != (char *)0)
	free(c->port);
    if (c->escape != (char *)0)
	free(c->escape);
#if HAVE_OPENSSL
    if (c->sslcredentials != (char *)0)
	free(c->sslcredentials);
    if (c->sslcacertificatefile != (char *)0)
	free(c->sslcacertificatefile);
    if (c->sslcacertificatepath != (char *)0)
	free(c->sslcacertificatepath);
#endif
    free(c);
}

void
ApplyConfigDefault(CONFIG *c)
{
    if (parserConfigDefault == (CONFIG *)0)
	return;

    if (parserConfigDefault->username != (char *)0) {
	if (c->username != (char *)0)
	    free(c->username);
	if ((c->username =
	     StrDup(parserConfigDefault->username)) == (char *)0)
	    OutOfMem();
    }
    if (parserConfigDefault->master != (char *)0) {
	if (c->master != (char *)0)
	    free(c->master);
	if ((c->master = StrDup(parserConfigDefault->master)) == (char *)0)
	    OutOfMem();
    }
    if (parserConfigDefault->port != (char *)0) {
	if (c->port != (char *)0)
	    free(c->port);
	if ((c->port = StrDup(parserConfigDefault->port)) == (char *)0)
	    OutOfMem();
    }
    if (parserConfigDefault->escape != (char *)0) {
	if (c->escape != (char *)0)
	    free(c->escape);
	if ((c->escape = StrDup(parserConfigDefault->escape)) == (char *)0)
	    OutOfMem();
    }
    if (parserConfigDefault->striphigh != FLAGUNKNOWN)
	c->striphigh = parserConfigDefault->striphigh;
    if (parserConfigDefault->replay != FLAGUNKNOWN)
	c->replay = parserConfigDefault->replay;
    if (parserConfigDefault->playback != FLAGUNKNOWN)
	c->playback = parserConfigDefault->playback;
#if HAVE_OPENSSL
    if (parserConfigDefault->sslcredentials != (char *)0) {
	if (c->sslcredentials != (char *)0)
	    free(c->sslcredentials);
	if ((c->sslcredentials =
	     StrDup(parserConfigDefault->sslcredentials)) == (char *)0)
	    OutOfMem();
    }
    if (parserConfigDefault->sslcacertificatefile != (char *)0) {
	if (c->sslcacertificatefile != (char *)0)
	    free(c->sslcacertificatefile);
	if ((c->sslcacertificatefile =
	     StrDup(parserConfigDefault->sslcacertificatefile)) ==
	    (char *)0)
	    OutOfMem();
    }
    if (parserConfigDefault->sslcacertificatepath != (char *)0) {
	if (c->sslcacertificatepath != (char *)0)
	    free(c->sslcacertificatepath);
	if ((c->sslcacertificatepath =
	     StrDup(parserConfigDefault->sslcacertificatepath)) ==
	    (char *)0)
	    OutOfMem();
    }
    if (parserConfigDefault->sslrequired != FLAGUNKNOWN)
	c->sslrequired = parserConfigDefault->sslrequired;
    if (parserConfigDefault->sslenabled != FLAGUNKNOWN)
	c->sslenabled = parserConfigDefault->sslenabled;
#endif
}

void
ConfigBegin(char *id)
{
    CONDDEBUG((1, "ConfigBegin(%s) [%s:%d]", id, file, line));
    if (id == (char *)0 || id[0] == '\000') {
	Error("empty config name [%s:%d]", file, line);
	return;
    }
    if (parserConfigTemp != (CONFIG *)0)
	DestroyConfig(parserConfigTemp);
    if ((parserConfigTemp = (CONFIG *)calloc(1, sizeof(CONFIG)))
	== (CONFIG *)0)
	OutOfMem();
    ApplyConfigDefault(parserConfigTemp);
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
	    DestroyConfig(parserConfigDefault);
	    parserConfigDefault = parserConfigTemp;
	    parserConfigTemp = (CONFIG *)0;
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

    if (parserConfigTemp != (CONFIG *)0) {
	DestroyConfig(parserConfigTemp);
	parserConfigTemp = (CONFIG *)0;
    }

    if (parserConfigDefault != (CONFIG *)0) {
	DestroyConfig(pConfig);
	pConfig = parserConfigDefault;
	parserConfigDefault = (CONFIG *)0;
    }
}

void
DestroyTerminal(TERM *t)
{
    if (t == (TERM *)0)
	return;
    if (t->attach != (char *)0)
	free(t->attach);
    if (t->attachsubst != (char *)0)
	free(t->attachsubst);
    if (t->detach != (char *)0)
	free(t->detach);
    if (t->detachsubst != (char *)0)
	free(t->detachsubst);
    free(t);
}

void
ApplyTermDefault(TERM *t)
{
    if (parserTermDefault == (TERM *)0)
	return;

    if (parserTermDefault->attach != (char *)0) {
	if (t->attach != (char *)0)
	    free(t->attach);
	if ((t->attach = StrDup(parserTermDefault->attach)) == (char *)0)
	    OutOfMem();
    }
    if (parserTermDefault->attachsubst != (char *)0) {
	if (t->attachsubst != (char *)0)
	    free(t->attachsubst);
	if ((t->attachsubst =
	     StrDup(parserTermDefault->attachsubst)) == (char *)0)
	    OutOfMem();
    }
    if (parserTermDefault->detach != (char *)0) {
	if (t->detach != (char *)0)
	    free(t->detach);
	if ((t->detach = StrDup(parserTermDefault->detach)) == (char *)0)
	    OutOfMem();
    }
    if (parserTermDefault->detachsubst != (char *)0) {
	if (t->detachsubst != (char *)0)
	    free(t->detachsubst);
	if ((t->detachsubst =
	     StrDup(parserTermDefault->detachsubst)) == (char *)0)
	    OutOfMem();
    }
}

void
TerminalBegin(char *id)
{
    CONDDEBUG((1, "TerminalBegin(%s) [%s:%d]", id, file, line));
    if (id == (char *)0 || id[0] == '\000') {
	Error("empty terminal name [%s:%d]", file, line);
	return;
    }
    if (parserTermTemp != (TERM *)0)
	DestroyTerminal(parserTermTemp);
    if ((parserTermTemp = (TERM *)calloc(1, sizeof(TERM)))
	== (TERM *)0)
	OutOfMem();
    ApplyTermDefault(parserTermTemp);
    parserTermTemp->name = AllocString();
    BuildString(id, parserTermTemp->name);
}

void
TerminalEnd(void)
{
    static char *term = (char *)0;

    CONDDEBUG((1, "TerminalEnd() [%s:%d]", file, line));

    if (parserTermTemp == (TERM *)0)
	return;

    if (term == (char *)0) {
	if ((term = getenv("TERM")) == (char *)0) {
	    term = "";
	}
    }

    if (parserTermTemp->name->used > 1) {
	if ((parserTermTemp->name->string[0] == '*' &&
	     parserTermTemp->name->string[1] == '\000') ||
	    strcmp(parserTermTemp->name->string, term) == 0) {
	    DestroyTerminal(parserTermDefault);
	    parserTermDefault = parserTermTemp;
	    parserTermTemp = (TERM *)0;
	}
    }

    DestroyTerminal(parserTermTemp);
    parserTermTemp = (TERM *)0;
}

void
TerminalAbort(void)
{
    CONDDEBUG((1, "TerminalAbort() [%s:%d]", file, line));
    if (parserTermTemp == (TERM *)0)
	return;

    DestroyTerminal(parserTermTemp);
    parserTermTemp = (TERM *)0;
}

void
TerminalDestroy(void)
{
    CONDDEBUG((1, "TerminalDestroy() [%s:%d]", file, line));

    if (parserTermTemp != (TERM *)0) {
	DestroyTerminal(parserTermTemp);
	parserTermTemp = (TERM *)0;
    }

    if (parserTermDefault != (TERM *)0) {
	DestroyTerminal(pTerm);
	pTerm = parserTermDefault;
	parserTermDefault = (TERM *)0;
    }
}

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
}

void
ConfigItemEscape(char *id)
{
    CONDDEBUG((1, "ConfigItemEscape(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->escape != (char *)0)
	free(parserConfigTemp->escape);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->escape = (char *)0;
	return;
    }
    if ((parserConfigTemp->escape = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
ConfigItemMaster(char *id)
{
    CONDDEBUG((1, "ConfigItemMaster(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->master != (char *)0)
	free(parserConfigTemp->master);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->master = (char *)0;
	return;
    }
    if ((parserConfigTemp->master = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
ConfigItemPlayback(char *id)
{
    int i;

    CONDDEBUG((1, "ConfigItemPlayback(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->playback = 0;
	return;
    }
    for (i = 0; id[i] != '\000'; i++) {
	if (!isdigit((int)id[i])) {
	    Error("invalid playback value [%s:%d]", file, line);
	    return;
	}
    }
    if (i > 4) {
	Error("playback value too large [%s:%d]", file, line);
	return;
    }
    parserConfigTemp->playback = (unsigned short)atoi(id) + 1;
}

void
ConfigItemPort(char *id)
{
    CONDDEBUG((1, "ConfigItemPort(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->port != (char *)0)
	free(parserConfigTemp->port);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->port = (char *)0;
	return;
    }
    if ((parserConfigTemp->port = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
ConfigItemReplay(char *id)
{
    int i;

    CONDDEBUG((1, "ConfigItemReplay(%s) [%s:%d]", id, file, line));

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->replay = 0;
	return;
    }
    for (i = 0; id[i] != '\000'; i++) {
	if (!isdigit((int)id[i])) {
	    Error("invalid replay value [%s:%d]", file, line);
	    return;
	}
    }
    if (i > 4) {
	Error("replay value too large [%s:%d]", file, line);
	return;
    }
    parserConfigTemp->replay = (unsigned short)atoi(id) + 1;
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
    Error
	("sslcacertificatefile ignored - encryption not compiled into code [%s:%d]",
	 file, line);
#endif
}

void
ConfigItemSslcacertificatepath(char *id)
{
    CONDDEBUG((1, "ConfigItemSslcacertificatepath(%s) [%s:%d]", id, file,
	       line));
#if HAVE_OPENSSL
    if (parserConfigTemp->sslcacertificatepath != (char *)0)
	free(parserConfigTemp->sslcacertificatepath);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->sslcacertificatepath = (char *)0;
	return;
    }
    if ((parserConfigTemp->sslcacertificatepath = StrDup(id)) == (char *)0)
	OutOfMem();
#else
    Error
	("sslcacertificatepath ignored - encryption not compiled into code [%s:%d]",
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
    Error
	("sslrequired ignored - encryption not compiled into code [%s:%d]",
	 file, line);
#endif
}

void
ConfigItemSslenabled(char *id)
{
    CONDDEBUG((1, "ConfigItemSslenabled(%s) [%s:%d]", id, file, line));
#if HAVE_OPENSSL
    ProcessYesNo(id, &(parserConfigTemp->sslenabled));
#else
    Error("sslenabled ignored - encryption not compiled into code [%s:%d]",
	  file, line);
#endif
}

void
ConfigItemStriphigh(char *id)
{
    CONDDEBUG((1, "ConfigItemStriphigh(%s) [%s:%d]", id, file, line));
    ProcessYesNo(id, &(parserConfigTemp->striphigh));
}

void
ConfigItemUsername(char *id)
{
    CONDDEBUG((1, "ConfigItemUsername(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->username != (char *)0)
	free(parserConfigTemp->username);

    if ((id == (char *)0) || (*id == '\000')) {
	parserConfigTemp->username = (char *)0;
	return;
    }
    if ((parserConfigTemp->username = StrDup(id)) == (char *)0)
	OutOfMem();
}

SUBST *substData = (SUBST *)0;

SUBSTTOKEN
SubstToken(char c)
{
    switch (c) {
	case 'u':
	case 'c':
	    return ISSTRING;
	default:
	    return ISNOTHING;
    }
}

int
SubstValue(char c, char **s, int *i)
{
    int retval = 0;

    if (s != (char **)0) {
	CONFIG *pc;
	if (substData->data == (void *)0)
	    return 0;

	pc = (CONFIG *)(substData->data);
	if (c == 'u') {
	    (*s) = pc->username;
	    retval = 1;
	} else if (c == 'c') {
	    (*s) = pc->console;
	    retval = 1;
	}
    }

    return retval;
}

void
InitSubstCallback(void)
{
    if (substData == (SUBST *)0) {
	if ((substData = (SUBST *)calloc(1, sizeof(SUBST))) == (SUBST *)0)
	    OutOfMem();
	substData->value = &SubstValue;
	substData->token = &SubstToken;
    }
}


void
TerminalItemAttach(char *id)
{
    CONDDEBUG((1, "TerminalItemAttach(%s) [%s:%d]", id, file, line));

    if (parserTermTemp->attach != (char *)0)
	free(parserTermTemp->attach);

    if ((id == (char *)0) || (*id == '\000')) {
	parserTermTemp->attach = (char *)0;
	return;
    }
    if ((parserTermTemp->attach = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
TerminalItemAttachsubst(char *id)
{
    CONDDEBUG((1, "TerminalItemAttachsubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserTermTemp->attachsubst),
		 "attachsubst", id);
}

void
TerminalItemDetach(char *id)
{
    CONDDEBUG((1, "TerminalItemDetach(%s) [%s:%d]", id, file, line));

    if (parserTermTemp->detach != (char *)0)
	free(parserTermTemp->detach);

    if ((id == (char *)0) || (*id == '\000')) {
	parserTermTemp->detach = (char *)0;
	return;
    }
    if ((parserTermTemp->detach = StrDup(id)) == (char *)0)
	OutOfMem();
}

void
TerminalItemDetachsubst(char *id)
{
    CONDDEBUG((1, "TerminalItemDetachsubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, (char **)0, &(parserTermTemp->detachsubst),
		 "detachsubst", id);
}

ITEM keyConfig[] = {
    {"escape", ConfigItemEscape},
    {"master", ConfigItemMaster},
    {"playback", ConfigItemPlayback},
    {"port", ConfigItemPort},
    {"replay", ConfigItemReplay},
    {"sslcredentials", ConfigItemSslcredentials},
    {"sslcacertificatefile", ConfigItemSslcacertificatefile},
    {"sslcacertificatepath", ConfigItemSslcacertificatepath},
    {"sslrequired", ConfigItemSslrequired},
    {"sslenabled", ConfigItemSslenabled},
    {"striphigh", ConfigItemStriphigh},
    {"username", ConfigItemUsername},
    {(char *)0, (void *)0}
};

ITEM keyTerminal[] = {
    {"attach", TerminalItemAttach},
    {"attachsubst", TerminalItemAttachsubst},
    {"detach", TerminalItemDetach},
    {"detachsubst", TerminalItemDetachsubst},
    {(char *)0, (void *)0}
};

SECTION sections[] = {
    {"config", ConfigBegin, ConfigEnd, ConfigAbort, ConfigDestroy,
     keyConfig},
    {"terminal", TerminalBegin, TerminalEnd, TerminalAbort,
     TerminalDestroy, keyTerminal},
    {(char *)0, (void *)0, (void *)0, (void *)0, (void *)0}
};

void
ReadConf(char *filename, FLAG verbose)
{
    FILE *fp;

    if ((FILE *)0 == (fp = fopen(filename, "r"))) {
	if (verbose == FLAGTRUE)
	    Error("could not open `%s'", filename);
	return;
    }

    /* initialize the substition bits */
    InitSubstCallback();

    parserConfigDefault = pConfig;
    pConfig = (CONFIG *)0;

    parserTermDefault = pTerm;
    pTerm = (TERM *)0;

    ParseFile(filename, fp, 0);

    /* shouldn't really happen, but in case i screw up the stuff
     * ParseFile calls...
     */
    if (pConfig == (CONFIG *)0) {
	if ((pConfig = (CONFIG *)calloc(1, sizeof(CONFIG)))
	    == (CONFIG *)0)
	    OutOfMem();
    }

    if (pTerm == (TERM *)0) {
	if ((pTerm = (TERM *)calloc(1, sizeof(TERM)))
	    == (TERM *)0)
	    OutOfMem();
    }

    if (fDebug) {
#define EMPTYSTR(x) x == (char *)0 ? "(null)" : x
#define FLAGSTR(x) x == FLAGTRUE ? "true" : (x == FLAGFALSE ? "false" : "unset")
	CONDDEBUG((1, "pConfig->username = %s",
		   EMPTYSTR(pConfig->username)));
	CONDDEBUG((1, "pConfig->master = %s", EMPTYSTR(pConfig->master)));
	CONDDEBUG((1, "pConfig->port = %s", EMPTYSTR(pConfig->port)));
	CONDDEBUG((1, "pConfig->escape = %s", EMPTYSTR(pConfig->escape)));
	CONDDEBUG((1, "pConfig->striphigh = %s",
		   FLAGSTR(pConfig->striphigh)));
	CONDDEBUG((1, "pConfig->replay = %hu", pConfig->replay));
	CONDDEBUG((1, "pConfig->playback = %hu", pConfig->playback));
#if HAVE_OPENSSL
	CONDDEBUG((1, "pConfig->sslcredentials = %s",
		   EMPTYSTR(pConfig->sslcredentials)));
	CONDDEBUG((1, "pConfig->sslcacertificatefile = %s",
		   EMPTYSTR(pConfig->sslcacertificatefile)));
	CONDDEBUG((1, "pConfig->sslcacertificatepath = %s",
		   EMPTYSTR(pConfig->sslcacertificatepath)));
	CONDDEBUG((1, "pConfig->sslrequired = %s",
		   FLAGSTR(pConfig->sslrequired)));
	CONDDEBUG((1, "pConfig->sslenabled = %s",
		   FLAGSTR(pConfig->sslenabled)));
#endif
	CONDDEBUG((1, "pTerm->attach = %s", EMPTYSTR(pTerm->attach)));
	CONDDEBUG((1, "pTerm->attachsubst = %s",
		   EMPTYSTR(pTerm->attachsubst)));
	CONDDEBUG((1, "pTerm->detach = %s", EMPTYSTR(pTerm->detach)));
	CONDDEBUG((1, "pTerm->detachsubst = %s",
		   EMPTYSTR(pTerm->detachsubst)));
    }

    fclose(fp);
}
