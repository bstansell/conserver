/*
 *  $Id: group.h,v 5.31 2003-03-17 08:43:20-08 bryan Exp $
 *
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
    fd_set rinit;		/* descriptor list                      */
    CONSENT *pCElist;		/* list of consoles in this group       */
    CONSENT *pCEctl;		/* our control `console'                */
    CONSCLIENT *pCLall;		/* all clients to scan after select     */
    CONSCLIENT *pCLfree;	/* head of free list                    */
    struct grpent *pGEnext;	/* next group entry                     */
} GRPENT;

extern void Spawn PARAMS((GRPENT *));
extern int CheckPass PARAMS((char *, char *));
extern void TagLogfile PARAMS((const CONSENT *, const char *, ...));
extern void TagLogfileAct PARAMS((const CONSENT *, const char *, ...));
extern void CleanupBreak PARAMS((short));
extern void DestroyGroup PARAMS((GRPENT *));
extern void DestroyConsent PARAMS((GRPENT *, CONSENT *));
extern void SendClientsMsg PARAMS((CONSENT *, char *));
extern void ResetMark PARAMS((void));
