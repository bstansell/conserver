/*
 *  $Id: access.h,v 5.17 2002-02-25 14:00:38-08 bryan Exp $
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
/*
 * keep track of network access and peer console servers		(ksb)
 */

typedef struct access {
    char ctrust;		/* how much do we trust the host        */
    int ilen;			/* length (strlen) of pcwho             */
    char *pcwho;		/* what is the hosts name/ip number     */
    int isCIDR;			/* is this a CIDR addr (or hostname?)   */
    struct access *pACnext;	/* next access list                     */
} ACCESS;

typedef struct remote {		/* console at another host              */
    struct remote *pRCnext;	/* next remote console we know about    */
    struct remote *pRCuniq;	/* list of uniq remote servers          */
    STRING rserver;		/* remote server name                   */
    STRING rhost;		/* remote host to call to get it        */
} REMOTE;

#if USE_ANSI_PROTO
extern REMOTE *FindUniq(REMOTE *);
extern char AccType(struct in_addr *, char *);
extern void SetDefAccess(struct in_addr *pAddr, char *pHost);
#else
extern REMOTE *FindUniq();
extern char AccType();
extern void SetDefAccess();
#endif
