/*
 *  $Id: readcfg.h,v 5.34 2003-10-10 08:57:17-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

typedef struct config {
    STRING *name;
    char defaultaccess;
    FLAG daemonmode;
    char *logfile;
    char *initcmd;
    char *passwdfile;
    char *primaryport;
    FLAG redirect;
    int reinitcheck;
    char *secondaryport;
#if HAVE_OPENSSL
    char *sslcredentials;
    FLAG sslrequired;
#endif
} CONFIG;

typedef struct breaks {
    STRING *seq;
    int delay;
} BREAKS;

extern NAMES *userList;		/* user list */
extern GRPENT *pGroups;		/* group info */
extern REMOTE *pRCList;		/* list of remote consoles we know about */
extern REMOTE *pRCUniq;		/* list of uniq console servers */
extern ACCESS *pACList;		/* `who do you love' (or trust) */
extern CONSENTUSERS *pADList;	/* list of admin users */
extern BREAKS breakList[9];	/* list of break sequences */
extern CONFIG *pConfig;		/* settings seen by config parser */

extern void ReadCfg PARAMS((char *, FILE *));
extern void ReReadCfg PARAMS((int));
extern void DestroyBreakList PARAMS((void));
extern void DestroyUserList PARAMS((void));
extern void DestroyConfig PARAMS((CONFIG *));
extern NAMES *FindUserList PARAMS((char *));
extern NAMES *AddUserList PARAMS((char *));
extern CONSENT *FindConsoleName PARAMS((CONSENT *, char *));
