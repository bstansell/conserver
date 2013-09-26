/*
 *  $Id: readconf.h,v 5.6 2013/09/18 14:31:39 bryan Exp $
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
    unsigned short replay;
    unsigned short playback;
#if HAVE_OPENSSL
    char *sslcredentials;
    char *sslcacertificatefile;
    char *sslcacertificatepath;
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
