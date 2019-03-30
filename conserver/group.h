/*
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
 */

/*
 * Copyright 1992 Purdue Research Foundation, West Lafayette, Indiana
 * 47907.  All rights reserved.
 *
 * Written by Kevin S Braunsdorf, ksb@cc.purdue.edu, purdue!ksb
 *
 * This software is not subject to any license of the American Telephone
 * and Telegraph Company or the Regents of the University of California.
 *
 * Permission is granted to anyone to use this software for any purpose on
 * any computer system, and to alter it and redistribute it freely, subject
 * to the following restrictions:
 *
 * 1. Neither the authors nor Purdue University are responsible for any
 *    consequences of the use of this software.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Credit to the authors and Purdue
 *    University must appear in documentation and sources.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 *
 * 4. This notice may not be removed or altered.
 */

/* timers used to have various things happen */
#define T_STATE		0
#define T_CIDLE		1
#define T_MARK		2
#define T_REINIT	3
#define T_AUTOUP	4
#define T_ROLL		5
#define T_INITDELAY	6
#define T_MAX		7	/* T_MAX *must* be last */

/* return values used by CheckPass()
 */
#define AUTH_SUCCESS	0	/* ok                                   */
#define AUTH_NOUSER	1	/* no user                              */
#define AUTH_INVALID	2	/* invalid password                     */

typedef struct grpent {		/* group info                           */
    unsigned int id;		/* uniqueue group id                    */
    unsigned short port;	/* port group listens on                */
    pid_t pid;			/* pid of server for group              */
    int imembers;		/* number of consoles in this group     */
    CONSENT *pCElist;		/* list of consoles in this group       */
    CONSENT *pCEctl;		/* our control `console'                */
    CONSCLIENT *pCLall;		/* all clients to scan after select     */
    CONSCLIENT *pCLfree;	/* head of free list                    */
    struct grpent *pGEnext;	/* next group entry                     */
} GRPENT;

extern time_t timers[];

extern void Spawn(GRPENT *, int);
extern int CheckPass(char *, char *, FLAG);
extern void TagLogfile(const CONSENT *, char *, ...);
extern void TagLogfileAct(const CONSENT *, char *, ...);
extern void DestroyGroup(GRPENT *);
extern void DestroyConsent(GRPENT *, CONSENT *);
extern void SendClientsMsg(CONSENT *, char *);
extern void ResetMark(void);
extern void DestroyConsentUsers(CONSENTUSERS **);
extern CONSENTUSERS *ConsentFindUser(CONSENTUSERS *, char *);
extern int ConsentUserOk(CONSENTUSERS *, char *);
extern void DisconnectClient(GRPENT *, CONSCLIENT *, char *, FLAG);
extern int ClientAccess(CONSENT *, char *);
extern void DestroyClient(CONSCLIENT *);
extern int CheckPasswd(CONSCLIENT *, char *, FLAG);
extern void DeUtmp(GRPENT *, int);
extern void ClientWantsWrite(CONSCLIENT *);
extern void SendIWaitClientsMsg(CONSENT *, char *);
#if HAVE_OPENSSL
extern int AttemptSSL(CONSCLIENT *);
#endif
#if HAVE_GSSAPI
extern int AttemptGSSAPI(CONSCLIENT *);
#endif
