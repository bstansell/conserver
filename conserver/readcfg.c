/*
 *  $Id: readcfg.c,v 5.61 2001-07-23 00:45:49-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000-2001
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
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

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>

#include <compat.h>
#include <port.h>
#include <util.h>

#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <readcfg.h>
#include <master.h>
#include <main.h>

GRPENT aGroups[MAXGRP];		/* even spread is OK            */
CONSENT aConsoles[MAXGRP * MAXMEMB];	/* gross over allocation        */
REMOTE *pRCList;		/* list of remote consoles we know about */
int
  iLocal;			/* number of local consoles             */

ACCESS *pACList;		/* `who do you love' (or trust)         */
int
  iAccess;			/* how many access restrictions we have */

/* Parse the [number(m|h|d|l)[a]] spec
 * return 0 on invalid spec, non-zero on valid spec
 */
int
parseMark(pcFile, iLine, pcMark, tyme, pCE)
    const char *pcFile;
    const int iLine;
    const char *pcMark;
    CONSENT *pCE;
{
    char mark[BUFSIZ];
    char *p, *n = (char *)0;
    int activity = 0;
    int factor = 0, pfactor = 0;
    int value = 0, pvalue = 0;

    if ((pcMark == (char *)0) || (*pcMark == '\000'))
	return 0;
    (void)strcpy(mark, pcMark);

    for (p = mark; *p != '\000'; p++) {
	if (*p == 'a' || *p == 'A') {
	    if (n != (char *)0) {
		Error
		    ("%s(%d) bad timestamp specification `%s': numeral before `a' (ignoring numeral)",
		     pcFile, iLine, pcMark);
	    }
	    activity = 1;
	} else if (*p == 'm' || *p == 'M') {
	    pfactor = 60;
	} else if (*p == 'h' || *p == 'H') {
	    pfactor = 60 * 60;
	} else if (*p == 'd' || *p == 'D') {
	    pfactor = 60 * 60 * 24;
	} else if (*p == 'l' || *p == 'L') {
	    pfactor = -1;
	} else if (isdigit((int)*p)) {
	    if (n == (char *)0)
		n = p;
	} else if (isspace((int)*p)) {
	    if (n != (char *)0) {
		pfactor = 60;
	    }
	} else {
	    Error
		("%s(%d) bad timestamp specification `%s': unknown character `%c'",
		 pcFile, iLine, pcMark, *p);
	    return 0;
	}
	if (pfactor) {
	    if (n == (char *)0) {
		Error
		    ("%s(%d) bad timestamp specification `%s': missing numeric prefix for `%c'",
		     pcFile, iLine, pcMark, *p);
		return 0;
	    } else {
		*p = '\000';
		pvalue = atoi(n);
		if (pvalue < 0) {
		    Error("%s(%d) negative timestamp specification `%s'",
			  pcFile, iLine, pcMark);
		    return 0;
		}
		n = (char *)0;
		factor = pfactor;
		value = pvalue * pfactor;
		pvalue = pfactor = 0;
	    }
	}
    }

    if (n != (char *)0) {
	pvalue = atoi(n);
	if (pvalue < 0) {
	    Error("%s(%d) negative timestamp specification `%s'", pcFile,
		  iLine, pcMark);
	    return 0;
	}
	factor = 60;
	value = pvalue * factor;
    }

    Debug("Mark spec of `%s' parsed: factor=%d, value=%d, activity=%d",
	  pcMark, factor, value, activity);

    if (pCE != (CONSENT *) 0) {
	pCE->activitylog = activity;
	if (factor && value) {
	    pCE->mark = value;
	    if (factor > 0) {
		pCE->nextMark = tyme + value;
	    } else {
		pCE->nextMark = value;
	    }
	} else {
	    pCE->nextMark = pCE->mark = 0;
	}
    }

    return factor;
}

/* replace trailing space with '\000' in a string and return
 * a pointer to the start of the non-space part
 */
char *
pruneSpace(string)
    char *string;
{
    char *p;
    char *head = (char *)0;
    char *tail = (char *)0;

    /* Don't do much if it's crap */
    if (string == (char *)0 || *string == '\000')
	return string;

    /* Now for the tricky part - search the string */
    for (p = string; *p != '\000'; p++) {
	if (isspace((int)(*p))) {
	    if (tail == (char *)0)
		tail = p;	/* possible end of string */
	} else {
	    if (head == (char *)0)
		head = p;	/* found the start */
	    tail = (char *)0;	/* reset tail */
	}
    }

    if (tail != (char *)0)
	*tail = '\000';

    if (head != (char *)0)
	return head;
    else
	return string;
}

/* read in the configuration file, fill in all the structs we use	(ksb)
 * to manage the consoles
 */
void
ReadCfg(pcFile, fp)
    char *pcFile;
    FILE *fp;
{
    GRPENT *pGE;
    int iG, minG;
    int iLine;
    unsigned char acIn[BUFSIZ];
    char *acStart;
    GRPENT *pGEAll;
    CONSENT *pCE;
    REMOTE **ppRC;
    char LogDirectory[MAXLOGLEN];
    time_t tyme;
    char defMark[BUFSIZ];

    tyme = time((time_t *) 0);
    LogDirectory[0] = '\000';
    defMark[0] = '\000';
    pGEAll = aGroups;		/* fill in these structs        */
    pCE = aConsoles;
    ppRC = &pRCList;
    iLocal = 0;

    iG = minG = 0;
    iLine = 0;
    while (fgets(acIn, sizeof(acIn) - 1, fp) != NULL) {
	char *pcLine, *pcMode, *pcLog, *pcRem, *pcStart, *pcMark;

	++iLine;

	acStart = pruneSpace(acIn);

	if ('#' == acStart[0] || '\000' == acStart[0]) {
	    continue;
	}
	if ('%' == acStart[0] && '%' == acStart[1] && '\000' == acStart[2]) {
	    break;
	}
	if ((char *)0 == strchr(acStart, ':') &&
	    (char *)0 != (pcLine = strchr(acStart, '='))) {
	    *pcLine++ = '\000';
	    acStart = pruneSpace(acStart);
	    pcLine = pruneSpace(pcLine);
	    if (0 == strcmp(acStart, "LOGDIR")) {
		(void)strcpy(LogDirectory, pcLine);
	    } else if (0 == strcmp(acStart, "TIMESTAMP")) {
		if (parseMark(pcFile, iLine, pcLine, tyme, NULL))
		    (void)strcpy(defMark, pcLine);
		else
		    defMark[0] = '\000';
	    } else if (0 == strcmp(acStart, "DOMAINHACK")) {
		domainHack = 1;
	    } else {
		Error("%s(%d) unknown variable `%s'", pcFile, iLine,
		      acStart);
	    }
	    continue;
	}
	if ((char *)0 == (pcLine = strchr(acStart, ':')) ||
	    (char *)0 == (pcMode = strchr(pcLine + 1, ':')) ||
	    (char *)0 == (pcLog = strchr(pcMode + 1, ':'))) {
	    Error("%s(%d) bad config line `%s'", pcFile, iLine, acIn);
	    continue;
	}
	*pcLine++ = '\000';
	*pcMode++ = '\000';
	*pcLog++ = '\000';

	acStart = pruneSpace(acStart);
	pcLine = pruneSpace(pcLine);
	pcMode = pruneSpace(pcMode);
	pcLog = pruneSpace(pcLog);

	if ((char *)0 != (pcMark = strchr(pcLog, ':'))) {
	    *pcMark++ = '\000';
	    pcLog = pruneSpace(pcLog);
	    pcMark = pruneSpace(pcMark);
	    /* Skip null intervals */
	    if (pcMark[0] == '\000')
		pcMark = (char *)0;
	}

	/* if this server remote?
	 * (contains an '@host' where host is not us)
	 * if so just add it to a linked list of remote hosts
	 * I'm sure most sites will never use this code (ksb)
	 */
	if ((char *)0 != (pcRem = strchr(pcLine, '@'))) {
	    struct hostent *hpMe;

	    *pcRem++ = '\000';
	    pcLine = pruneSpace(pcLine);
	    pcRem = pruneSpace(pcRem);

	    if ((struct hostent *)0 == (hpMe = gethostbyname(pcRem))) {
		Error("gethostbyname(%s): %s", pcRem, hstrerror(h_errno));
		exit(EX_UNAVAILABLE);
	    }
	    if (4 != hpMe->h_length || AF_INET != hpMe->h_addrtype) {
		Error
		    ("wrong address size (4 != %d) or address family (%d != %d)",
		     hpMe->h_length, AF_INET, hpMe->h_addrtype);
		exit(EX_UNAVAILABLE);
	    }

	    if (0 !=
#if HAVE_MEMCMP
		memcmp(&acMyAddr.s_addr, hpMe->h_addr, hpMe->h_length)
#else
		bcmp(&acMyAddr.s_addr, hpMe->h_addr, hpMe->h_length)
#endif
		) {

		REMOTE *pRCTemp;
		pRCTemp = (REMOTE *) calloc(1, sizeof(REMOTE));
		if ((REMOTE *) 0 == pRCTemp) {
		    OutOfMem();
		}
		(void)strcpy(pRCTemp->rhost, pcRem);
		(void)strcpy(pRCTemp->rserver, acStart);
		*ppRC = pRCTemp;
		ppRC = &pRCTemp->pRCnext;
		if (fVerbose) {
		    Info("%s remote on %s", acStart, pcRem);
		}
		continue;
	    }
	}

	/* take the same group as the last line, by default
	 */
	if (MAXMEMB == pGEAll[iG].imembers) {
	    ++iG;
	}
	if (iG < minG || iG >= MAXGRP) {
	    Error("%s(%d) group number out of bounds %d <= %d < %d",
		  pcFile, iLine, minG, iG, MAXGRP);
	    exit(EX_UNAVAILABLE);
	}
	minG = iG;
	pGE = pGEAll + iG;
	if (0 == pGE->imembers++) {
	    pGE->pCElist = pCE;
	}
	if (pGE->imembers > MAXMEMB) {
	    Error
		("%s(%d) group %d has more than %d members -- but we'll give it a spin",
		 pcFile, iLine, iG, MAXMEMB);
	}

	/* fill in the console entry
	 */
	if (sizeof(aConsoles) / sizeof(CONSENT) == iLocal) {
	    Error
		("%s(%d) %d is too many consoles for hard coded tables, adjust MAXGRP or MAXMEMB",
		 pcFile, iLine, iLocal);
	    exit(EX_UNAVAILABLE);
	}
	(void)strcpy(pCE->server, acStart);

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
	    (void)strcat(pCE->lfile, acStart);
	    pcStart = pcRem + 1;
	}
	(void)strcat(pCE->lfile, pcStart);
	if (LogDirectory[0] && (pCE->lfile)[0] != '/') {
	    char lfile[MAXLOGLEN];
	    strcpy(lfile, pCE->lfile);
	    strcpy(pCE->lfile, LogDirectory);
	    strcat(pCE->lfile, "/");
	    strcat(pCE->lfile, lfile);
	}

	if (pcMark) {
	    (void)parseMark(pcFile, iLine, pcMark, tyme, pCE);
	} else {
	    (void)parseMark(pcFile, iLine, defMark, tyme, pCE);
	}

	if (pcLine[0] == '!') {
	    pcLine = pruneSpace(pcLine + 1);
	    pCE->isNetworkConsole = 1;
	    pCE->telnetState = 0;
	    strcpy(pCE->networkConsoleHost, pcLine);
	    pCE->networkConsolePort = atoi(pcMode);

	    if (fVerbose) {
		Info("%s is network on %s/%d logged to %s", acStart,
		     pCE->networkConsoleHost, pCE->networkConsolePort,
		     pCE->lfile);
	    }
	    pCE->fvirtual = 0;
	    sprintf(pCE->dfile, "%s/%d", pCE->networkConsoleHost,
		    pCE->networkConsolePort);
	    pCE->pbaud = FindBaud("Netwk");
	    pCE->pparity = FindParity(" ");
	} else if ('|' == pcLine[0]) {
	    pcLine = pruneSpace(pcLine + 1);
	    pCE->isNetworkConsole = 0;
	    pCE->telnetState = 0;
	    pCE->fvirtual = 1;
	    if ((char *)0 ==
		(pCE->pccmd = malloc((strlen(pcLine) | 7) + 1))) {
		OutOfMem();
	    }
	    (void)strcpy(pCE->pccmd, pcLine);
	    (void)strcpy(pCE->dfile, "/dev/null");
	    (void)strcpy(pCE->acslave, "/dev/null");
	} else {
	    pCE->isNetworkConsole = 0;
	    pCE->telnetState = 0;
	    pCE->fvirtual = 0;
	    (void)strcpy(pCE->dfile, pcLine);
	}
	pCE->ipid = -1;

	if (!pCE->isNetworkConsole) {
	    /* find user baud and parity
	     * default to first table entry for baud and parity
	     */
	    pCE->pbaud = FindBaud(pcMode);
	    pCE->pparity = FindParity(pcMode);
	    if (fVerbose) {
		if (pCE->fvirtual)
		    Info("%s with command `%s' logged to %s", acStart,
			 pCE->pccmd, pCE->lfile);
		else
		    Info("%s is on %s (%s%c) logged to %s", acStart,
			 pCE->dfile, pCE->pbaud->acrate,
			 pCE->pparity->ckey, pCE->lfile);
	    }
	}
	++pCE, ++iLocal;
    }
    *ppRC = (REMOTE *) 0;

    /* make a vector of access restructions
     */
    iG = iAccess = 0;
    pACList = (ACCESS *) 0;
    while (fgets(acIn, sizeof(acIn) - 1, fp) != NULL) {
	char *pcMach, *pcNext, *pcMem;
	char cType;
	int iLen;

	++iLine;

	acStart = pruneSpace(acIn);

	if ('#' == acStart[0] || '\000' == acStart[0]) {
	    continue;
	}
	if ('%' == acStart[0] && '%' == acStart[1] && '\000' == acStart[2]) {
	    break;
	}
	if ((char *)0 == (pcNext = strchr(acStart, ':'))) {
	    Error("%s(%d) missing colon?", pcFile, iLine);
	    exit(EX_UNAVAILABLE);
	}

	do {
	    *pcNext++ = '\000';
	} while (isspace((int)(*pcNext)));

	switch (acStart[0]) {
	    case 'a':		/* allowed, allow, allows       */
	    case 'A':
		cType = 'a';
		break;
	    case 'r':		/* rejected, refused, refuse    */
	    case 'R':
		cType = 'r';
		break;
	    case 't':		/* trust, trusted, trusts       */
	    case 'T':
		cType = 't';
		break;
	    default:
		Error("%s(%d) unknown access key `%s\'", pcFile, iLine,
		      acStart);
		exit(EX_UNAVAILABLE);
	}
	while ('\000' != *(pcMach = pcNext)) {
	    int j, isCIDR = 0;
	    while ('\000' != *pcNext &&
		   !(isspace((int)(*pcNext)) || ',' == *pcNext)) {
		++pcNext;
	    }
	    while ('\000' != *pcNext &&
		   (isspace((int)(*pcNext)) || ',' == *pcNext)) {
		*pcNext++ = '\000';
	    }

	    /* Scan for [0-9./], and stop if you find something else */
	    for (j = 0; pcMach[j] != '\000'; j++) {
		if (!isdigit((int)(pcMach[j])) && pcMach[j] != '/' &&
		    pcMach[j] != '.') {
		    break;
		}
	    }
	    /* Did we see just [0-9./]?  If so, CIDR notation */
	    if (pcMach[j] == '\000') {
		/* Do a little checking on the input */
		int nCount = 0, sCount = 0, dCount = 0;
		char *sPtr = (char *)0, *nPtr = (char *)0;
		char cidr[BUFSIZ];

		(void)strcpy(cidr, pcMach);
		/* Scan for [0-9./], and stop if you find something else */
		for (j = 0; cidr[j] != '\000'; j++) {
		    if (isdigit((int)(cidr[j]))) {
			if (nPtr == (char *)0) {
			    nCount++;
			    nPtr = cidr + j;
			}
		    } else if (cidr[j] == '/') {
			sCount++;
			sPtr = cidr + j;
		    } else if (cidr[j] == '.') {
			int num;
			dCount++;
			if (nPtr == (char *)0) {
			    Error
				("%s(%d) bad access list specification `%s': missing numeral before `.'",
				 pcFile, iLine, pcMach);
			    break;
			}
			cidr[j] = '\000';
			num = atoi(nPtr);
			if (num < 0 || num > 255) {
			    Error
				("%s(%d) bad access list specification `%s': invalid IP octet `%s'",
				 pcFile, iLine, pcMach, nPtr);
			    break;
			}
			nPtr = (char *)0;
		    }
		}
		/* If we got through the whole string, then...
		 * Gotta check against pcMach 'cause we stompped on stuff in cidr above, so can't
		 * judge what happened correctly with it.
		 */
		if (pcMach[j] == '\000') {
		    if (dCount != 3 || sCount > 1) {
			Error
			    ("%s(%d) bad access list specification `%s': must be in a.b.c.d[/n] form",
			     pcFile, iLine, pcMach);
			continue;
		    }
		    if (sCount == 1) {
			int mask;
			mask = atoi(sPtr + 1);
			if (mask < 0 || mask > 32) {
			    Error
				("%s(%d) bad access list specification `%s': netmask not from 0 to 32",
				 pcFile, iLine, pcMach);
			    continue;
			}
		    }
		    isCIDR = 1;
		} else {
		    continue;
		}
	    }

	    if (iAccess < iG) {
		/* still have room */ ;
	    } else if (0 != iG) {
		iG += 8;
		pACList =
		    (ACCESS *) realloc((char *)pACList,
				       iG * sizeof(ACCESS));
	    } else {
		iG = MAXGRP;
		pACList = (ACCESS *) malloc(iG * sizeof(ACCESS));
	    }
	    if ((ACCESS *) 0 == pACList) {
		OutOfMem();
	    }
	    /* use loopback interface for local connections
	       if (0 == strcmp(pcMach, acMyHost)) {
	       pcMach = "127.0.0.1";
	       }
	     */
	    iLen = strlen(pcMach);
	    if ((char *)0 == (pcMem = malloc(iLen + 1))) {
		OutOfMem();
	    }
	    pACList[iAccess].ctrust = cType;
	    pACList[iAccess].ilen = iLen;
	    pACList[iAccess].pcwho = strcpy(pcMem, pcMach);
	    pACList[iAccess].isCIDR = isCIDR;
	    ++iAccess;
	}
    }
}
