/*
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#include <compat.h>

#include "cutil.h"
#include "readconf.h"

CONFIG *parserConfigTemp = NULL;
CONFIG *parserConfigDefault = NULL;
CONFIG *pConfig = NULL;
TERM *parserTermTemp = NULL;
TERM *parserTermDefault = NULL;
TERM *pTerm = NULL;

void
DestroyConfig(CONFIG *c)
{
    if (c == NULL)
	return;
    if (c->username != NULL)
	free(c->username);
    if (c->master != NULL)
	free(c->master);
    if (c->port != NULL)
	free(c->port);
    if (c->escape != NULL)
	free(c->escape);
#if HAVE_OPENSSL
    if (c->sslcredentials != NULL)
	free(c->sslcredentials);
    if (c->sslcacertificatefile != NULL)
	free(c->sslcacertificatefile);
    if (c->sslcacertificatepath != NULL)
	free(c->sslcacertificatepath);
#endif
    free(c);
}

void
ApplyConfigDefault(CONFIG *c)
{
    if (parserConfigDefault == NULL)
	return;

    if (parserConfigDefault->username != NULL) {
	if (c->username != NULL)
	    free(c->username);
	if ((c->username =
	     StrDup(parserConfigDefault->username)) == NULL)
	    OutOfMem();
    }
    if (parserConfigDefault->master != NULL) {
	if (c->master != NULL)
	    free(c->master);
	if ((c->master = StrDup(parserConfigDefault->master)) == NULL)
	    OutOfMem();
    }
    if (parserConfigDefault->port != NULL) {
	if (c->port != NULL)
	    free(c->port);
	if ((c->port = StrDup(parserConfigDefault->port)) == NULL)
	    OutOfMem();
    }
    if (parserConfigDefault->escape != NULL) {
	if (c->escape != NULL)
	    free(c->escape);
	if ((c->escape = StrDup(parserConfigDefault->escape)) == NULL)
	    OutOfMem();
    }
    if (parserConfigDefault->striphigh != FLAGUNKNOWN)
	c->striphigh = parserConfigDefault->striphigh;
    if (parserConfigDefault->replay != FLAGUNKNOWN)
	c->replay = parserConfigDefault->replay;
    if (parserConfigDefault->playback != FLAGUNKNOWN)
	c->playback = parserConfigDefault->playback;
#if HAVE_OPENSSL
    if (parserConfigDefault->sslcredentials != NULL) {
	if (c->sslcredentials != NULL)
	    free(c->sslcredentials);
	if ((c->sslcredentials =
	     StrDup(parserConfigDefault->sslcredentials)) == NULL)
	    OutOfMem();
    }
    if (parserConfigDefault->sslcacertificatefile != NULL) {
	if (c->sslcacertificatefile != NULL)
	    free(c->sslcacertificatefile);
	if ((c->sslcacertificatefile =
	     StrDup(parserConfigDefault->sslcacertificatefile)) ==
	    NULL)
	    OutOfMem();
    }
    if (parserConfigDefault->sslcacertificatepath != NULL) {
	if (c->sslcacertificatepath != NULL)
	    free(c->sslcacertificatepath);
	if ((c->sslcacertificatepath =
	     StrDup(parserConfigDefault->sslcacertificatepath)) ==
	    NULL)
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
    if (id == NULL || id[0] == '\000') {
	Error("empty config name [%s:%d]", file, line);
	return;
    }
    if (parserConfigTemp != NULL)
	DestroyConfig(parserConfigTemp);
    if ((parserConfigTemp = (CONFIG *)calloc(1, sizeof(CONFIG)))
	== NULL)
	OutOfMem();
    ApplyConfigDefault(parserConfigTemp);
    parserConfigTemp->name = AllocString();
    BuildString(id, parserConfigTemp->name);
}

void
ConfigEnd(void)
{
    CONDDEBUG((1, "ConfigEnd() [%s:%d]", file, line));

    if (parserConfigTemp == NULL)
	return;

    if (parserConfigTemp->name->used > 1) {
	if ((parserConfigTemp->name->string[0] == '*' &&
	     parserConfigTemp->name->string[1] == '\000') ||
	    IsMe(parserConfigTemp->name->string)) {
	    DestroyConfig(parserConfigDefault);
	    parserConfigDefault = parserConfigTemp;
	    parserConfigTemp = NULL;
	}
    }

    DestroyConfig(parserConfigTemp);
    parserConfigTemp = NULL;
}

void
ConfigAbort(void)
{
    CONDDEBUG((1, "ConfigAbort() [%s:%d]", file, line));
    if (parserConfigTemp == NULL)
	return;

    DestroyConfig(parserConfigTemp);
    parserConfigTemp = NULL;
}

void
ConfigDestroy(void)
{
    CONDDEBUG((1, "ConfigDestroy() [%s:%d]", file, line));

    if (parserConfigTemp != NULL) {
	DestroyConfig(parserConfigTemp);
	parserConfigTemp = NULL;
    }

    if (parserConfigDefault != NULL) {
	DestroyConfig(pConfig);
	pConfig = parserConfigDefault;
	parserConfigDefault = NULL;
    }
}

void
DestroyTerminal(TERM *t)
{
    if (t == NULL)
	return;
    if (t->attach != NULL)
	free(t->attach);
    if (t->attachsubst != NULL)
	free(t->attachsubst);
    if (t->detach != NULL)
	free(t->detach);
    if (t->detachsubst != NULL)
	free(t->detachsubst);
    free(t);
}

void
ApplyTermDefault(TERM *t)
{
    if (parserTermDefault == NULL)
	return;

    if (parserTermDefault->attach != NULL) {
	if (t->attach != NULL)
	    free(t->attach);
	if ((t->attach = StrDup(parserTermDefault->attach)) == NULL)
	    OutOfMem();
    }
    if (parserTermDefault->attachsubst != NULL) {
	if (t->attachsubst != NULL)
	    free(t->attachsubst);
	if ((t->attachsubst =
	     StrDup(parserTermDefault->attachsubst)) == NULL)
	    OutOfMem();
    }
    if (parserTermDefault->detach != NULL) {
	if (t->detach != NULL)
	    free(t->detach);
	if ((t->detach = StrDup(parserTermDefault->detach)) == NULL)
	    OutOfMem();
    }
    if (parserTermDefault->detachsubst != NULL) {
	if (t->detachsubst != NULL)
	    free(t->detachsubst);
	if ((t->detachsubst =
	     StrDup(parserTermDefault->detachsubst)) == NULL)
	    OutOfMem();
    }
}

void
TerminalBegin(char *id)
{
    CONDDEBUG((1, "TerminalBegin(%s) [%s:%d]", id, file, line));
    if (id == NULL || id[0] == '\000') {
	Error("empty terminal name [%s:%d]", file, line);
	return;
    }
    if (parserTermTemp != NULL)
	DestroyTerminal(parserTermTemp);
    if ((parserTermTemp = (TERM *)calloc(1, sizeof(TERM)))
	== NULL)
	OutOfMem();
    ApplyTermDefault(parserTermTemp);
    parserTermTemp->name = AllocString();
    BuildString(id, parserTermTemp->name);
}

void
TerminalEnd(void)
{
    static char *term = NULL;

    CONDDEBUG((1, "TerminalEnd() [%s:%d]", file, line));

    if (parserTermTemp == NULL)
	return;

    if (term == NULL) {
	if ((term = getenv("TERM")) == NULL) {
	    term = "";
	}
    }

    if (parserTermTemp->name->used > 1) {
	if ((parserTermTemp->name->string[0] == '*' &&
	     parserTermTemp->name->string[1] == '\000') ||
	    strcmp(parserTermTemp->name->string, term) == 0) {
	    DestroyTerminal(parserTermDefault);
	    parserTermDefault = parserTermTemp;
	    parserTermTemp = NULL;
	}
    }

    DestroyTerminal(parserTermTemp);
    parserTermTemp = NULL;
}

void
TerminalAbort(void)
{
    CONDDEBUG((1, "TerminalAbort() [%s:%d]", file, line));
    if (parserTermTemp == NULL)
	return;

    DestroyTerminal(parserTermTemp);
    parserTermTemp = NULL;
}

void
TerminalDestroy(void)
{
    CONDDEBUG((1, "TerminalDestroy() [%s:%d]", file, line));

    if (parserTermTemp != NULL) {
	DestroyTerminal(parserTermTemp);
	parserTermTemp = NULL;
    }

    if (parserTermDefault != NULL) {
	DestroyTerminal(pTerm);
	pTerm = parserTermDefault;
	parserTermDefault = NULL;
    }
}

void
ProcessYesNo(char *id, FLAG *flag)
{
    if (id == NULL || id[0] == '\000')
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

    if (parserConfigTemp->escape != NULL)
	free(parserConfigTemp->escape);

    if ((id == NULL) || (*id == '\000')) {
	parserConfigTemp->escape = NULL;
	return;
    }
    if ((parserConfigTemp->escape = StrDup(id)) == NULL)
	OutOfMem();
}

void
ConfigItemMaster(char *id)
{
    CONDDEBUG((1, "ConfigItemMaster(%s) [%s:%d]", id, file, line));

    if (parserConfigTemp->master != NULL)
	free(parserConfigTemp->master);

    if ((id == NULL) || (*id == '\000')) {
	parserConfigTemp->master = NULL;
	return;
    }
    if ((parserConfigTemp->master = StrDup(id)) == NULL)
	OutOfMem();
}

void
ConfigItemPlayback(char *id)
{
    int i;

    CONDDEBUG((1, "ConfigItemPlayback(%s) [%s:%d]", id, file, line));

    if ((id == NULL) || (*id == '\000')) {
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

    if (parserConfigTemp->port != NULL)
	free(parserConfigTemp->port);

    if ((id == NULL) || (*id == '\000')) {
	parserConfigTemp->port = NULL;
	return;
    }
    if ((parserConfigTemp->port = StrDup(id)) == NULL)
	OutOfMem();
}

void
ConfigItemReplay(char *id)
{
    int i;

    CONDDEBUG((1, "ConfigItemReplay(%s) [%s:%d]", id, file, line));

    if ((id == NULL) || (*id == '\000')) {
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
    if (parserConfigTemp->sslcredentials != NULL)
	free(parserConfigTemp->sslcredentials);

    if ((id == NULL) || (*id == '\000')) {
	parserConfigTemp->sslcredentials = NULL;
	return;
    }
    if ((parserConfigTemp->sslcredentials = StrDup(id)) == NULL)
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
    if (parserConfigTemp->sslcacertificatefile != NULL)
	free(parserConfigTemp->sslcacertificatefile);

    if ((id == NULL) || (*id == '\000')) {
	parserConfigTemp->sslcacertificatefile = NULL;
	return;
    }
    if ((parserConfigTemp->sslcacertificatefile = StrDup(id)) == NULL)
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
    if (parserConfigTemp->sslcacertificatepath != NULL)
	free(parserConfigTemp->sslcacertificatepath);

    if ((id == NULL) || (*id == '\000')) {
	parserConfigTemp->sslcacertificatepath = NULL;
	return;
    }
    if ((parserConfigTemp->sslcacertificatepath = StrDup(id)) == NULL)
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

    if (parserConfigTemp->username != NULL)
	free(parserConfigTemp->username);

    if ((id == NULL) || (*id == '\000')) {
	parserConfigTemp->username = NULL;
	return;
    }
    if ((parserConfigTemp->username = StrDup(id)) == NULL)
	OutOfMem();
}

SUBST *substData = NULL;

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

    if (s != NULL) {
	CONFIG *pc;
	if (substData->data == NULL)
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
    if (substData == NULL) {
	if ((substData = (SUBST *)calloc(1, sizeof(SUBST))) == NULL)
	    OutOfMem();
	substData->value = &SubstValue;
	substData->token = &SubstToken;
    }
}


void
TerminalItemAttach(char *id)
{
    CONDDEBUG((1, "TerminalItemAttach(%s) [%s:%d]", id, file, line));

    if (parserTermTemp->attach != NULL)
	free(parserTermTemp->attach);

    if ((id == NULL) || (*id == '\000')) {
	parserTermTemp->attach = NULL;
	return;
    }
    if ((parserTermTemp->attach = StrDup(id)) == NULL)
	OutOfMem();
}

void
TerminalItemAttachsubst(char *id)
{
    CONDDEBUG((1, "TerminalItemAttachsubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, NULL, &(parserTermTemp->attachsubst),
		 "attachsubst", id);
}

void
TerminalItemDetach(char *id)
{
    CONDDEBUG((1, "TerminalItemDetach(%s) [%s:%d]", id, file, line));

    if (parserTermTemp->detach != NULL)
	free(parserTermTemp->detach);

    if ((id == NULL) || (*id == '\000')) {
	parserTermTemp->detach = NULL;
	return;
    }
    if ((parserTermTemp->detach = StrDup(id)) == NULL)
	OutOfMem();
}

void
TerminalItemDetachsubst(char *id)
{
    CONDDEBUG((1, "TerminalItemDetachsubst(%s) [%s:%d]", id, file, line));
    ProcessSubst(substData, NULL, &(parserTermTemp->detachsubst),
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
    {NULL, NULL}
};

ITEM keyTerminal[] = {
    {"attach", TerminalItemAttach},
    {"attachsubst", TerminalItemAttachsubst},
    {"detach", TerminalItemDetach},
    {"detachsubst", TerminalItemDetachsubst},
    {NULL, NULL}
};

SECTION sections[] = {
    {"config", ConfigBegin, ConfigEnd, ConfigAbort, ConfigDestroy,
     keyConfig},
    {"terminal", TerminalBegin, TerminalEnd, TerminalAbort,
     TerminalDestroy, keyTerminal},
    {NULL, NULL, NULL, NULL, NULL}
};

void
ReadConf(char *filename, FLAG verbose)
{
    FILE *fp;

    if (NULL == (fp = fopen(filename, "r"))) {
	if (verbose == FLAGTRUE)
	    Error("could not open `%s'", filename);
	return;
    }

    /* initialize the substition bits */
    InitSubstCallback();

    parserConfigDefault = pConfig;
    pConfig = NULL;

    parserTermDefault = pTerm;
    pTerm = NULL;

    ParseFile(filename, fp, 0);

    /* shouldn't really happen, but in case i screw up the stuff
     * ParseFile calls...
     */
    if (pConfig == NULL) {
	if ((pConfig = (CONFIG *)calloc(1, sizeof(CONFIG)))
	    == NULL)
	    OutOfMem();
    }

    if (pTerm == NULL) {
	if ((pTerm = (TERM *)calloc(1, sizeof(TERM)))
	    == NULL)
	    OutOfMem();
    }

    if (fDebug) {
#define EMPTYSTR(x) x == NULL ? "(null)" : x
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
