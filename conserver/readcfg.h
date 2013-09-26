/*
 *  $Id: readcfg.h,v 5.49 2013/09/23 22:58:21 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#define BREAKDELAYDEFAULT 250

typedef struct config {
    STRING *name;
    FLAG autocomplete;
    char defaultaccess;
    FLAG daemonmode;
    char *logfile;
    char *passwdfile;
    char *primaryport;
    FLAG redirect;
    FLAG loghostnames;
    int reinitcheck;
    char *secondaryport;
    char *unifiedlog;
    int initdelay;
#if HAVE_SETPROCTITLE
    FLAG setproctitle;
#endif
#if HAVE_OPENSSL
    char *sslcredentials;
    FLAG sslrequired;
    FLAG sslreqclientcert;
    char *sslcacertificatefile;
#endif
} CONFIG;

typedef struct breaks {
    STRING *seq;
    int delay;
    FLAG confirm;
} BREAKS;

typedef struct tasks {
    char id;
    STRING *cmd;
    STRING *descr;
    uid_t uid;
    gid_t gid;
    char *subst;
    FLAG confirm;
    struct tasks *next;
} TASKS;

extern NAMES *userList;		/* user list */
extern GRPENT *pGroups;		/* group info */
extern REMOTE *pRCList;		/* list of remote consoles we know about */
extern REMOTE *pRCUniq;		/* list of uniq console servers */
extern ACCESS *pACList;		/* `who do you love' (or trust) */
extern CONSENTUSERS *pADList;	/* list of admin users */
extern CONSENTUSERS *pLUList;	/* list of limited users */
extern BREAKS breakList[9];	/* list of break sequences */
extern TASKS *taskList;		/* list of tasks */
extern SUBST *taskSubst;	/* substitution function data for tasks */
extern CONFIG *pConfig;		/* settings seen by config parser */
extern SUBST *substData;	/* substitution function data */

extern void ReadCfg PARAMS((char *, FILE *));
extern void ReReadCfg PARAMS((int, int));
extern void DestroyBreakList PARAMS((void));
extern void DestroyTaskList PARAMS((void));
extern void DestroyUserList PARAMS((void));
extern void DestroyConfig PARAMS((CONFIG *));
extern NAMES *FindUserList PARAMS((char *));
extern NAMES *AddUserList PARAMS((char *));
extern CONSENT *FindConsoleName PARAMS((CONSENT *, char *));
