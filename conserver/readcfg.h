/*
 *  $Id: readcfg.h,v 5.20 2002-09-29 19:05:12-07 bryan Exp $
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

/* we read in which hosts to trust and which ones we proxy for
 * from a file, into these structures
 */

extern GRPENT *pGroups;		/* group info                   */
extern REMOTE *pRCList;		/* list of remote consoles we know about */
extern REMOTE *pRCUniq;		/* list of uniq console servers */
extern ACCESS *pACList;		/* `who do you love' (or trust)         */
extern STRING *breakList;	/* list of break sequences              */

#if USE_ANSI_PROTO
extern void ReadCfg(char *, FILE *);
extern char *pruneSpace(char *);
extern void ReReadCfg(void);
#else
extern void ReadCfg();
extern char *pruneSpace();
extern void ReReadCfg();
#endif
