/*
 *  $Id: readcfg.c,v 5.23 1999-01-13 11:48:11-08 bryan Exp $
 *
 *  GNAC, Inc., 1998
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@gnac.com)
 */

/*
 * Copyright (c) 1990 The Ohio State University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by The Ohio State University and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
/*
 * Network console modifications by Robert Olson, olson@mcs.anl.gov.
 */
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
#include "consent.h"
#include "client.h"
#include "group.h"
#include "access.h"
#include "readcfg.h"
#include "master.h"
#include "main.h"

#if USE_STRINGS
#include <strings.h>
#else
#include <string.h>
#endif


GRPENT
	aGroups[MAXGRP];		/* even spread is OK		*/
CONSENT
	aConsoles[MAXGRP*MAXMEMB];	/* gross over allocation        */
REMOTE
	*pRCList;		/* list of remote consoles we know about */
int
	iLocal;			/* number of local consoles		*/

ACCESS
	*pACList;		/* `who do you love' (or trust)		*/
int
	iAccess;		/* how many access restrictions we have	*/

/* read in the configuration file, fill in all the structs we use	(ksb)
 * to manage the consoles
 */
void
ReadCfg(pcFile, fp)
char *pcFile;
register FILE *fp;
{
	register GRPENT *pGE;
	register int iG, minG;
	auto int iLine;
	auto char acIn[BUFSIZ];
	register GRPENT *pGEAll;
	register CONSENT *pCE;
	register REMOTE **ppRC;
	char LogDirectory[MAXLOGLEN];
	long tyme;

	tyme = time((long *)0);
	LogDirectory[0] = '\000';
	pGEAll = aGroups;		/* fill in these structs	*/
	pCE = aConsoles;
	ppRC = & pRCList;
	iLocal = 0;

	iG = minG = 0;
	iLine = 0;
	while (fgets(acIn, sizeof(acIn)-1, fp) != NULL) {
		register char *pcLine, *pcMode, *pcLog, *pcRem, *pcStart, *pcMark;

		++iLine;
		for (pcRem = acIn+strlen(acIn)-1; pcRem >= acIn; --pcRem) {
			if (!isspace(*pcRem))
				break;
			*pcRem = '\000';
			if (pcRem == acIn)
				break;
		}
		if ('#' == acIn[0] || '\000' == acIn[0]) {
			continue;
		}
		if ('%' == acIn[0] && '%' == acIn[1] && '\000' == acIn[2]) {
			break;
		}
		if ( (char *)0 == strchr(acIn, ':') &&
		     (char *)0 != (pcLine = strchr(acIn, '=')) ) {
			*pcLine = '\000';
			if ( 0 == strcmp(acIn, "LOGDIR") ) {
			    (void)strcpy(LogDirectory, ++pcLine);
			} else if ( 0 == strcmp(acIn, "DOMAINHACK") ) {
			    domainHack = 1;
			} else {
			    *pcLine = '=';
			    fprintf(stderr, "%s: %s(%d) bad variable line `%s'\n", progname, pcFile, iLine, acIn);
			}
			continue;
		}
		if ( (char *)0 == (pcLine = strchr(acIn, ':')) ||
		     (char *)0 == (pcMode = strchr(pcLine+1, ':')) ||
		     (char *)0 == (pcLog  = strchr(pcMode+1, ':'))) {
			fprintf(stderr, "%s: %s(%d) bad config line `%s'\n", progname, pcFile, iLine, acIn);
			continue;
		}
		*pcLine++ = '\000';
		*pcMode++ = '\000';
		*pcLog++ = '\000';

		if ((char *)0 != (pcMark = strchr(pcLog, ':'))) {
			*pcMark++ = '\000';
			/* Skip null intervals */
			if ( pcMark[0] == '\000' ) pcMark = (char *)0;
		}

		/* if this server remote?
		 * (contains an '@host' where host is not us)
		 * if so just add it to a linked list of remote hosts
		 * I'm sure most sites will never use this code (ksb)
		 */
		if ((char *)0 != (pcRem = strchr(pcLine, '@')) &&
		   ((*pcRem++ = '\000'), 0 != strcmp(acMyHost, pcRem))) {
			register REMOTE *pRCTemp;
			pRCTemp = (REMOTE *)calloc(1, sizeof(REMOTE));
			if ((REMOTE *)0 == pRCTemp) {
				CSTROUT(2, "out of memory!\n");
				exit(32);
			}
			(void)strcpy(pRCTemp->rhost, pcRem);
			(void)strcpy(pRCTemp->rserver, acIn);
			*ppRC = pRCTemp;
			ppRC = & pRCTemp->pRCnext;
			if (fVerbose) {
				printf("%s: %s remote on %s\n", progname, acIn, pcRem);
			}
			continue;
		}

		/* take the same group as the last line, by default
		 */
		if (MAXMEMB == pGEAll[iG].imembers) {
			++iG;
		}
		if (iG < minG || iG >= MAXGRP) {
			fprintf(stderr, "%s: %s(%d) group number out of bounds %d <= %d < %d\n", progname, pcFile, iLine, minG, iG, MAXGRP);
			exit(1);
		}
		minG = iG;
		pGE = pGEAll+iG;
		if (0 == pGE->imembers++) {
			pGE->pCElist = pCE;
		}
		if (pGE->imembers > MAXMEMB) {
			fprintf(stderr, "%s: %s(%d) group %d has more than %d members -- but we'll give it a spin\n", progname, pcFile, iLine, iG, MAXMEMB);
		}

		/* fill in the console entry
		 */
		if (sizeof(aConsoles)/sizeof(CONSENT) == iLocal) {
			fprintf(stderr, "%s: %s(%d) %d is too many consoles for hard coded tables, adjust MAXGRP or MAXMEMB\n", progname, pcFile, iLine, iLocal);
			exit(1);
		}
		(void)strcpy(pCE->server, acIn);

/*
 *  Here we substitute the console name for any '&' character in the
 *  logfile name.  That way you can just have something like
 *  "/var/console/&" for each of the conserver.cf entries.
 */
		*(pCE->lfile) = '\000';
		pcStart = pcLog;
		while ((char *)0 != (pcRem = strchr(pcStart, '&'))) {
		    *pcRem = '\000';
		    (void)strcat(pCE->lfile, pcStart);
		    (void)strcat(pCE->lfile, acIn);
		    pcStart = pcRem + 1;
		}
		(void)strcat(pCE->lfile, pcStart);
		if ( LogDirectory[0] && (pCE->lfile)[0] != '/' ) {
		    char lfile[MAXLOGLEN];
		    strcpy( lfile, pCE->lfile );
		    strcpy( pCE->lfile, LogDirectory );
		    strcat( pCE->lfile, "/" );
		    strcat( pCE->lfile, lfile );
		}

		if ( pcMark ) {
		    int factor;
		    char *p;
		    p = pcMark + strlen(pcMark) - 1;
		    if ( *p == 'm' ) {
			factor = 60;
		    } else if ( *p == 'h' ) {
			factor = 60 * 60;
		    } else if ( *p == 'd' ) {
			factor = 60 * 60 * 24;
		    } else {
			fprintf(stderr, "%s: %s(%d) bad mark specification `%s'\n", progname, pcFile, iLine, pcMark);
			pcMark = 0;
			factor = 0;
		    }
		    if ( factor ) {
			*p = '\000';
			pCE->mark = atoi(pcMark) * factor;
			pCE->nextMark = tyme + pCE->mark;
			if ( pCE->mark < 0 ) {
			    fprintf(stderr, "%s: %s(%d) negative mark specification `%s'\n", progname, pcFile, iLine, pcMark);
			    pcMark = 0;
			}
		    }
		}
		if ( !pcMark ) {
		    pCE->nextMark = pCE->mark = 0;
		}

#if DO_VIRTUAL
		if (pcLine[0] == '!')
		{
		    pCE->isNetworkConsole = 1;
		    strcpy(pCE->networkConsoleHost, pcLine + 1);
		    pCE->networkConsolePort = atoi(pcMode);
		    
		    if (fVerbose) {
			printf("%s: %d: %s is network on %s/%d logged to %s\n",
			       progname, iG, acIn, pCE->networkConsoleHost,
			       pCE->networkConsolePort, pCE->lfile);
		    }
		    pCE->fvirtual = 0;
		    sprintf( pCE->dfile, "%s/%d", pCE->networkConsoleHost, pCE->networkConsolePort );
		    pCE->pbaud = FindBaud("Netwk");
		    pCE->pparity = FindParity(" ");
		}
		else if ('|' == pcLine[0]) {
		    pCE->isNetworkConsole = 0;
			pCE->fvirtual = 1;
			if ((char *)0 == (pCE->pccmd = malloc((strlen(pcLine)|7)+1))) {
				OutOfMem();
			}
			(void)strcpy(pCE->pccmd, pcLine+1);
			(void)strcpy(pCE->dfile, "/dev/null");
		} else {
		    pCE->isNetworkConsole = 0;
			pCE->fvirtual = 0;
			(void)strcpy(pCE->dfile, pcLine);
		}
		pCE->ipid = -1;
#else
		if ('|' == pcLine[0]) {
			fprintf(stderr, "%s: %s(%d) this server doesn't provide any virtual console support\n", progname, pcFile, iLine);
			exit(9);
		}
		(void)strcpy(pCE->dfile, pcLine);
#endif

		if (!pCE->isNetworkConsole)
		{
		/* find user baud and parity
		 * default to first table entry for baud and parity
		 */
		pCE->pbaud = FindBaud(pcMode);
		pCE->pparity = FindParity(pcMode);
		if (fVerbose) {
#if DO_VIRTUAL
			if (pCE->fvirtual)
				printf("%s: %d: %s with command `%s' logged to %s\n", progname, iG, acIn, pCE->pccmd, pCE->lfile);
			else
#endif
				printf("%s: %d: %s is on %s (%s%c) logged to %s\n", progname, iG, acIn, pCE->dfile, pCE->pbaud->acrate, pCE->pparity->ckey, pCE->lfile);
		    }
		}
		++pCE, ++iLocal;
	}
	*ppRC = (REMOTE *)0;

	/* make a vector of access restructions
	 */
	iG = iAccess = 0;
	pACList = (ACCESS *)0;
	while (fgets(acIn, sizeof(acIn)-1, fp) != NULL) {
		register char *pcRem, *pcMach, *pcNext, *pcMem;
		auto char cType;
		auto int iLen;

		++iLine;
		for (pcRem = acIn+strlen(acIn); pcRem >= acIn; --pcRem) {
			if (!isspace(*pcRem))
				break;
			*pcRem = '\000';
			if (pcRem == acIn)
				break;
		}
		if ('#' == acIn[0] || '\000' == acIn[0]) {
			continue;
		}
		if ('%' == acIn[0] && '%' == acIn[1] && '\000' == acIn[2]) {
			break;
		}
		if ((char *)0 == (pcNext = strchr(acIn, ':'))) {
			fprintf(stderr, "%s: %s(%d) missing colon?\n", progname, pcFile, iLine);
			exit(3);
		}
		do {
			*pcNext++ = '\000';
		} while (isspace(*pcNext));
		switch (acIn[0]) {
		case 'a':		/* allowed, allow, allows	*/
		case 'A':
			cType = 'a';
			break;
		case 'r':		/* rejected, refused, refuse	*/
		case 'R':
			cType = 'r';
			break;
		case 't':		/* trust, trusted, trusts	*/
		case 'T':
			cType = 't';
			break;
		default:
			fprintf(stderr, "%s: %s(%d) unknown access key `%s\'\n", progname, pcFile, iLine, acIn);
			exit(3);
		}
		while ('\000' != *(pcMach = pcNext)) {
			while (!isspace(*pcNext)) {
				++pcNext;
			}
			while ('\000' != *pcNext && isspace(*pcNext)) {
				*pcNext++ = '\000';
			}
			if (iAccess < iG) {
				/* still have room */;
			} else if (0 != iG) {
				iG += 8;
				pACList = (ACCESS *)realloc((char *)pACList, iG * sizeof(ACCESS));
			} else {
				iG = MAXGRP;
				pACList = (ACCESS *)malloc(iG * sizeof(ACCESS));
			}
			if ((ACCESS *)0 == pACList) {
				OutOfMem();
			}
			/* use loopback interface for local connections
			if (0 == strcmp(pcMach, acMyHost)) {
				pcMach = "127.0.0.1";
			}
			 */
			iLen = strlen(pcMach);
			if ((char *)0 == (pcMem = malloc(iLen+1))) {
				OutOfMem();
			}
			pACList[iAccess].ctrust = cType;
			pACList[iAccess].ilen = iLen;
			pACList[iAccess].pcwho = strcpy(pcMem, pcMach);
			++iAccess;
		}
	}
}
