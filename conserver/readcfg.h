/*
 * $Id: readcfg.h,v 5.6 1993-02-09 03:59:25-08 ldv Exp $
 *
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

extern GRPENT
	aGroups[MAXGRP];		/* group info			*/
extern CONSENT
	aConsoles[MAXGRP*MAXMEMB];	/* console list			*/
extern REMOTE
	*pRCList;		/* list of remote consoles we know about */
extern ACCESS
	*pACList;		/* `who do you love' (or trust)		*/

extern int
	iAccess;		/* how many access restrictions we have	*/
extern int
	iLocal;			/* how many local consoles we have	*/

extern void ReadCfg();
