/*
 *  $Id: readconf.h,v 5.7 2014/04/20 06:45:07 bryan Exp $
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

extern void ReadConf(char *, FLAG);
extern void DestroyConfig(CONFIG *);
extern void DestroyTerminal(TERM *);
