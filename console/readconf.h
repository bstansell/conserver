/*
 *  $Id: readconf.h,v 5.3 2004/05/25 23:03:25 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

typedef struct config {
    STRING *name;
    char *console;
    char *username;
    char *master;
    char *port;
    char *escape;
    FLAG striphigh;
#if HAVE_OPENSSL
    char *sslcredentials;
    FLAG sslrequired;
    FLAG sslenabled;
#endif
} CONFIG;

typedef struct term {
    STRING *name;
    char *attach;
    char *attachsubst;
    char *detach;
    char *detachsubst;
} TERM;

extern CONFIG *pConfig;
extern TERM *pTerm;
extern SUBST *substData;

extern void ReadConf PARAMS((char *, FLAG));
extern void DestroyConfig PARAMS((CONFIG *));
extern void DestroyTerminal PARAMS((TERM *));
