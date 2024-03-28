/*
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#define BREAKDELAYDEFAULT 250
#define BREAKLISTSIZE 35	/* ('z'-('a'-1))+('9'-('1'-1)) */
#define BREAKALPHAOFFSET 39	/* ('a'-('9'+1)) */

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
    int reinitcheck; /* stored in sec, configured in min or sec */
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
extern BREAKS breakList[BREAKLISTSIZE];	/* list of break sequences */
extern TASKS *taskList;		/* list of tasks */
extern SUBST *taskSubst;	/* substitution function data for tasks */
extern CONFIG *pConfig;		/* settings seen by config parser */
extern SUBST *substData;	/* substitution function data */

extern void ReadCfg(char *, FILE *);
extern void ReReadCfg(int, int);
extern void DestroyBreakList(void);
extern void InitBreakList(void);
extern void DestroyTaskList(void);
extern void DestroyUserList(void);
extern void DestroyConfig(CONFIG *);
extern NAMES *FindUserList(char *);
extern NAMES *AddUserList(char *);
extern CONSENT *FindConsoleName(CONSENT *, char *);
