/*
 *  $Id: access.c,v 5.12 1999-01-26 20:35:17-08 bryan Exp $
 *
 *  Copyright GNAC, Inc., 1998
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@gnac.com)
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
#ifndef lint
static char copyright[] =
"@(#) Copyright 1992 Purdue Research Foundation.\nAll rights reserved.\n";
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>

#include "cons.h"
#include "port.h"
#include "access.h"
#include "consent.h"
#include "client.h"
#include "group.h"
#include "readcfg.h"
#include "main.h"

#if USE_STRINGS
#include <strings.h>
#else
#include <string.h>
#endif


/* in the routines below (the init code) we can bomb if malloc fails	(ksb)
 */
void
OutOfMem()
{
	static char acNoMem[] = ": out of memory\n";

	write(2, progname, strlen(progname));
	write(2, acNoMem, sizeof(acNoMem)-1);
	exit(45);
}


/* return the access type for a given host entry			(ksb)
 */
char
AccType(hp)
struct hostent *hp;
{
	register int i;
	register unsigned char *puc;
	register char *pcName;
	auto char acAddr[4*3+2];
	register int len;

	puc = (unsigned char *)hp->h_addr;
	sprintf(acAddr, "%d.%d.%d.%d", puc[0], puc[1], puc[2], puc[3]);
	for (i = 0; i < iAccess; ++i) {
		if (isdigit(pACList[i].pcwho[0])) {
			/* we could allow 128.210.7 to match all on that subnet
			 * here...
			 */
			if (0 == strcmp(acAddr, pACList[i].pcwho)) {
				return pACList[i].ctrust;
			}
			continue;
		}
		pcName = hp->h_name;
		len = strlen(pcName);
		while (len >= pACList[i].ilen) {
			if (0 == strcmp(pcName, pACList[i].pcwho)) {
				return pACList[i].ctrust;
			}
			pcName = strchr(pcName, '.');
			if ((char *)0 == pcName) {
				break;
			}
			++pcName;
			len = strlen(pcName);
		}
	}
	return chDefAcc;
}

/* we know iAccess == 0, we want to setup a nice default access list	(ksb)
 */
void
SetDefAccess(hpLocal)
struct hostent *hpLocal;
{
	register char *pcWho, *pcDomain;
	register unsigned char *puc;
	register int iLen;

	pACList = (ACCESS *)calloc(3, sizeof(ACCESS));
	if ((ACCESS *)0 == pACList) {
		OutOfMem();
	}
	if ((char *)0 == (pcWho = malloc(4*3+1))) {
		OutOfMem();
	}
	puc = (unsigned char *)hpLocal->h_addr;
	sprintf(pcWho, "%d.%d.%d.%d", puc[0], puc[1], puc[2], puc[3]);
	pACList[iAccess].ctrust = 'a';
	pACList[iAccess].ilen = strlen(pcWho);
	pACList[iAccess++].pcwho = pcWho;

	if ((char *)0 == (pcDomain = strchr(hpLocal->h_name, '.'))) {
		return;
	}
	++pcDomain;
	iLen = strlen(pcDomain);
	pcWho = malloc(iLen+1);
	pACList[iAccess].ctrust = 'a';
	pACList[iAccess].ilen = iLen;
	pACList[iAccess++].pcwho = strcpy(pcWho, pcDomain);
}

/* thread ther list of uniq console server machines, aliases for	(ksb)
 * machines will screw us up
 */
REMOTE *
FindUniq(pRCAll)
register REMOTE *pRCAll;
{
	register REMOTE *pRC;

	/* INV: tail of the list we are building always contains only
	 * uniq hosts, or the empty list.
	 */
	if ((REMOTE *)0 == pRCAll) {
		return (REMOTE *)0;
	}

	pRCAll->pRCuniq = FindUniq(pRCAll->pRCnext);

	/* if it is in the returned list of uniq hosts, return that list
	 * else add us by returning our node
	 */
	for (pRC = pRCAll->pRCuniq; (REMOTE *)0 != pRC; pRC = pRC->pRCuniq) {
		if (0 == strcmp(pRC->rhost, pRCAll->rhost)) {
			return pRCAll->pRCuniq;
		}
	}
	return pRCAll;
}

