/*
 *  $Id: readcfg.c,v 5.89 2002-10-12 20:07:43-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000
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
#include <util.h>

#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <readcfg.h>
#include <master.h>
#include <main.h>

GRPENT *pGroups = (GRPENT *) 0;
REMOTE *pRCList = (REMOTE *) 0;	/* list of remote consoles we know about */
ACCESS *pACList = (ACCESS *) 0;	/* `who do you love' (or trust)         */
STRING *breakList = (STRING *) 0;	/* list of break sequences */
REMOTE *pRCUniq = (REMOTE *) 0;	/* list of uniq console servers         */

static unsigned int groupID = 0;

/* Parse the [number(m|h|d|l)[a]] spec
 * return 0 on invalid spec, non-zero on valid spec
 */
int
#if USE_ANSI_PROTO
parseMark(const char *pcFile, const int iLine, const char *pcMark,
	  time_t tyme, CONSENT * pCE)
#else
parseMark(pcFile, iLine, pcMark, tyme, pCE)
    const char *pcFile;
    const int iLine;
    const char *pcMark;
    time_t tyme;
    CONSENT *pCE;
#endif
{
    static STRING mark = { (char *)0, 0, 0 };
    char *p, *n = (char *)0;
    int activity = 0, bactivity = 0;
    int factor = 0, pfactor = 0;
    int value = 0, pvalue = 0;

    if ((pcMark == (char *)0) || (*pcMark == '\000'))
	return 0;
    buildMyString((char *)0, &mark);
    buildMyString(pcMark, &mark);

    for (p = mark.string; *p != '\000'; p++) {
	if (*p == 'a' || *p == 'A') {
	    if (n != (char *)0) {
		Error
		    ("%s(%d) bad timestamp specification `%s': numeral before `a' (ignoring numeral)",
		     pcFile, iLine, pcMark);
	    }
	    activity = 1;
	} else if (*p == 'b' || *p == 'B') {
	    if (n != (char *)0) {
		Error
		    ("%s(%d) bad timestamp specification `%s': numeral before `b' (ignoring numeral)",
		     pcFile, iLine, pcMark);
	    }
	    bactivity = 1;
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

    Debug(1,
	  "Mark spec of `%s' parsed: factor=%d, value=%d, activity=%d, bactivity=%d",
	  pcMark, factor, value, activity, bactivity);

    if (pCE != (CONSENT *) 0) {
	pCE->activitylog = activity;
	pCE->breaklog = bactivity;
	if (factor && value) {
	    pCE->mark = value;
	    if (factor > 0) {
		tyme -= (tyme % 60);	/* minute boundary */
		if ((value <= 60 * 60 && (60 * 60) % value == 0)
		    || (value > 60 * 60 && (60 * 60 * 24) % value == 0)) {
		    struct tm *tm;
		    time_t now;

		    /* the increment is a "nice" subdivision of an hour
		     * or a day
		     */
		    now = tyme;
		    if ((struct tm *)0 != (tm = localtime(&tyme))) {
			tyme -= tm->tm_min * 60;	/* hour boundary */
			tyme -= tm->tm_hour * 60 * 60;	/* day boundary */
			tyme += ((now - tyme) / value) * value;
			/* up to nice bound */
		    }
		}
		pCE->nextMark = tyme + value;	/* next boundary */
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
#if USE_ANSI_PROTO
pruneSpace(char *string)
#else
pruneSpace(string)
    char *string;
#endif
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
#if USE_ANSI_PROTO
ReadCfg(char *pcFile, FILE * fp)
#else
ReadCfg(pcFile, fp, master)
    char *pcFile;
    FILE *fp;
#endif
{
    ACCESS *pACtmp;
    ACCESS **ppAC;
    GRPENT **ppGE;
    GRPENT *pGE = (GRPENT *) 0;
    GRPENT *pGEtmp = (GRPENT *) 0;
    GRPENT *pGEmatch = (GRPENT *) 0;
    GRPENT *pGEstage = (GRPENT *) 0;
    int iLine;
    unsigned char *acIn;
    static STRING acInSave = { (char *)0, 0, 0 };
    char *acStart;
    CONSENT *pCE = (CONSENT *) 0;
    CONSENT *pCEtmp = (CONSENT *) 0;
    CONSENT *pCEmatch = (CONSENT *) 0;
    REMOTE **ppRC;
    REMOTE *pRCtmp;
    static STRING LogDirectory = { (char *)0, 0, 0 };
    time_t tyme;
    static STRING defMark = { (char *)0, 0, 0 };
    int isStartup = (pGroups == (GRPENT *) 0 && pRCList == (REMOTE *) 0);
    REMOTE *pRCListOld = (REMOTE *) 0;
    GRPENT *pGroupsOld = (GRPENT *) 0;
    CONSCLIENT *pCLtmp = (CONSCLIENT *) 0;

    /* if we're the master process, this will either be the first time
     * reading the config file (in which case we'll just build the two
     * data structures: local and remote consoles), or it will be the
     * Nth time through, and we'll adjust the existing data structures
     * so that everything looks straight (using the same adjustment
     * logic as the children so everyone is in sync).  now, by adjusting
     * i actually mean that we move aside all the old groups and start
     * moving them back into the active list as we come across them in
     * the config file.  anything we haven't moved back into the active
     * list then gets nuked.
     *
     * if we're the children, this is a reread of the config file (by
     * definition).  in that case, we just need to remove any consoles
     * that have left our control or adjust the attributes of any consoles
     * we get to keep.
     *
     * yep, slippery little slope we're walking here.  hope we survive!
     */
    if (!isStartup) {
	pGroupsOld = pGroups;
	pRCListOld = pRCList;
	pGroups = (GRPENT *) 0;
	pRCList = (REMOTE *) 0;
    }

    tyme = time((time_t *) 0);
    buildMyString((char *)0, &defMark);
    buildMyString((char *)0, &LogDirectory);
    buildMyString((char *)0, &acInSave);
    ppRC = &pRCList;

    /* initialize the break lists */
    if ((STRING *) 0 == breakList) {
	breakList = (STRING *) calloc(9, sizeof(STRING));
	if ((STRING *) 0 == breakList) {
	    OutOfMem();
	}
    } else {
	for (iLine = 0; iLine < 9; iLine++) {
	    buildMyString((char *)0, &breakList[iLine]);
	}
    }
    buildMyString("\\z", &breakList[0]);
    buildMyString("\\r~^b", &breakList[1]);
    buildMyString("#.reset -x\\r", &breakList[2]);

    /* nuke the groups lists (should be a noop, but...) */
    while (pGroups != (GRPENT *) 0) {
	pGEtmp = pGroups->pGEnext;
	destroyGroup(pGroups);
	pGroups = pGEtmp;
    }

    /* nuke the remote consoles */
    while (pRCList != (REMOTE *) 0) {
	pRCtmp = pRCList->pRCnext;
	destroyString(&pRCList->rserver);
	destroyString(&pRCList->rhost);
	free(pRCList);
	pRCList = pRCtmp;
    }

    iLine = 0;
    while ((acIn =
	    (unsigned char *)readLine(fp, &acInSave,
				      &iLine)) != (unsigned char *)0) {
	char *pcLine, *pcMode, *pcLog, *pcRem, *pcStart, *pcMark, *pcBreak;
	char *pcColon;

	acStart = pruneSpace((char *)acIn);

	if ('%' == acStart[0] && '%' == acStart[1] && '\000' == acStart[2]) {
	    break;
	}
	if ((char *)0 != (pcLine = strchr(acStart, '=')) &&
	    ((char *)0 == (pcColon = strchr(acStart, ':')) ||
	     pcColon > pcLine)) {
	    *pcLine++ = '\000';
	    acStart = pruneSpace(acStart);
	    pcLine = pruneSpace(pcLine);
	    if (0 == strcmp(acStart, "LOGDIR")) {
		buildMyString((char *)0, &LogDirectory);
		buildMyString(pcLine, &LogDirectory);
	    } else if (0 == strcmp(acStart, "TIMESTAMP")) {
		buildMyString((char *)0, &defMark);
		if (parseMark(pcFile, iLine, pcLine, tyme, NULL)) {
		    buildMyString(pcLine, &defMark);
		}
	    } else if (0 == strcmp(acStart, "DOMAINHACK")) {
		domainHack = 1;
	    } else if (0 == strncmp(acStart, "BREAK", 5) &&
		       acStart[5] >= '1' && acStart[5] <= '9' &&
		       acStart[6] == '\000') {
		Debug(1, "BREAK%c found with `%s'", acStart[5], pcLine);
		if (pcLine[0] == '\000') {
		    buildMyString((char *)0, &breakList[acStart[5] - '1']);
		} else {
		    buildMyString((char *)0, &breakList[acStart[5] - '1']);
		    buildMyString(pcLine, &breakList[acStart[5] - '1']);
		    cleanupBreak(acStart[5] - '0');
		}
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

	/* before going any further, we might was well check for
	 * duplicates.  gotta do it somewhere, and we only need
	 * the console name to do it.  we have to look through
	 * the pGroups and pGEstage lists.  we don't look at the
	 * pGroupsOld list 'cause that's where the "to be
	 * reconfiged" consoles live.
	 *
	 * i hope this is right...and why i said what i did above:
	 *   in master during startup,
	 *     pGroupsOld = *empty*
	 *     pGroups = filling with groups of consoles
	 *     pGEstage = *empty*
	 *   in master during reread,
	 *     pGroupsOld = shrinking groups as they move to pGEstage
	 *     pGroups = filling with groups of new consoles
	 *     pGEstage = filling with groups from pGroupsOld
	 *   in slave during reread,
	 *     pGroupsOld = shrinking groups as they move to pGEstage
	 *     pGroups = *empty*
	 *     pGEstage = filling with groups from pGroupsOld
	 *
	 * now, pGroups in the slave during a reread may actually be
	 * temporarily used to hold stuff that's moving to pGEstage.
	 * in the master it might also have group stubs as well.
	 * but by the end, if it has anything, it's all empty groups
	 * in the slave and a mix of real (new) and empty in the master.
	 */
	for (pGEtmp = pGroups; pGEtmp != (GRPENT *) 0;
	     pGEtmp = pGEtmp->pGEnext) {
	    for (pCEtmp = pGEtmp->pCElist; pCEtmp != (CONSENT *) 0;
		 pCEtmp = pCEtmp->pCEnext) {
		if (pCEtmp->server.used &&
		    strcmp(acStart, pCEtmp->server.string) == 0) {
		    if (isMaster)
			Error("%s(%d) duplicate console name `%s'", pcFile,
			      iLine, acStart);
		    break;
		}
	    }
	    if (pCEtmp != (CONSENT *) 0)
		break;
	}
	if (pCEtmp != (CONSENT *) 0)
	    continue;
	for (pGEtmp = pGEstage; pGEtmp != (GRPENT *) 0;
	     pGEtmp = pGEtmp->pGEnext) {
	    for (pCEtmp = pGEtmp->pCElist; pCEtmp != (CONSENT *) 0;
		 pCEtmp = pCEtmp->pCEnext) {
		if (pCEtmp->server.used &&
		    strcmp(acStart, pCEtmp->server.string) == 0) {
		    if (isMaster)
			Error("%s(%d) duplicate console name `%s'", pcFile,
			      iLine, acStart);
		    break;
		}
	    }
	    if (pCEtmp != (CONSENT *) 0)
		break;
	}
	if (pCEtmp != (CONSENT *) 0)
	    continue;

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

	if ((char *)0 == pcMark) {
	    pcBreak = (char *)0;
	} else {
	    if ((char *)0 != (pcBreak = strchr(pcMark, ':'))) {
		*pcBreak++ = '\000';
		pcMark = pruneSpace(pcMark);
		pcBreak = pruneSpace(pcBreak);
		/* Ignore null specs */
		if (pcMark[0] == '\000')
		    pcMark = (char *)0;
		if (pcBreak[0] == '\000')
		    pcBreak = (char *)0;
	    }
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
		/* the master process just gets this added to the list.
		 * if it existed as a local console before, it'll be
		 * pruned later.
		 */
		if (isMaster) {
		    REMOTE *pRCTemp;
		    pRCTemp = (REMOTE *) calloc(1, sizeof(REMOTE));
		    if ((REMOTE *) 0 == pRCTemp) {
			OutOfMem();
		    }
		    buildMyString((char *)0, &pRCTemp->rhost);
		    buildMyString(pcRem, &pRCTemp->rhost);
		    buildMyString((char *)0, &pRCTemp->rserver);
		    buildMyString(acStart, &pRCTemp->rserver);
		    *ppRC = pRCTemp;
		    ppRC = &pRCTemp->pRCnext;
		    if (fVerbose) {
			Info("%s remote on %s", acStart, pcRem);
		    }
		}
		continue;
	    }
	}

	if (!isStartup) {
	    CONSENT **ppCE;
	    /* hunt for a local match, "pCEmatch != (CONSENT *)0" if found */
	    pCEmatch = (CONSENT *) 0;
	    for (pGEmatch = pGroupsOld; pGEmatch != (GRPENT *) 0;
		 pGEmatch = pGEmatch->pGEnext) {
		for (ppCE = &pGEmatch->pCElist, pCEmatch =
		     pGEmatch->pCElist; pCEmatch != (CONSENT *) 0;
		     ppCE = &pCEmatch->pCEnext, pCEmatch =
		     pCEmatch->pCEnext) {
		    if (0 == strcmp(acStart, pCEmatch->server.string)) {
			/* extract pCEmatch from the linked list */
			*ppCE = pCEmatch->pCEnext;
			pGEmatch->imembers--;
			break;
		    }
		}
		if (pCEmatch != (CONSENT *) 0)
		    break;
	    }

	    /* we're a child and we didn't find a match, next! */
	    if (!isMaster && (pCEmatch == (CONSENT *) 0))
		continue;

	    /* otherwise....we'll fall through and build a group with a
	     * single console.  at then end we'll do all the hard work
	     * of shuffling things around, comparing, etc.  this way we
	     * end up with the same parsed/pruned strings in the same
	     * fields and we don't have to do a lot of the same work here
	     * (especially the whitespace pruning)
	     */
	}

	/* ok, we're ready to rock and roll...first, lets make
	 * sure we have a group to go in and then we'll pop
	 * out a console and start filling it up
	 */
	/* let's get going with a group */
	if (pGroups == (GRPENT *) 0) {
	    pGroups = (GRPENT *) calloc(1, sizeof(GRPENT));
	    if (pGroups == (GRPENT *) 0)
		OutOfMem();
	    pGE = pGroups;
	    pGE->pid = -1;
	    pGE->id = groupID++;
	}

	/* if we've filled up the group, get another...
	 */
	if (cMaxMemb == pGE->imembers) {
	    pGE->pGEnext = (GRPENT *) calloc(1, sizeof(GRPENT));
	    if (pGE->pGEnext == (GRPENT *) 0)
		OutOfMem();
	    pGE = pGE->pGEnext;
	    pGE->pid = -1;
	    pGE->id = groupID++;
	}

	pCE = (CONSENT *) calloc(1, sizeof(CONSENT));
	if (pCE == (CONSENT *) 0)
	    OutOfMem();
	pCE->pCEnext = pGE->pCElist;
	pGE->pCElist = pCE;
	pGE->imembers++;

	if (pGE->imembers > cMaxMemb) {
	    Error
		("%s(%d) group has more than %d members -- but we'll give it a spin - THIS SHOULD NEVER HAPPEN",
		 pcFile, iLine, cMaxMemb);
	}

	/* fill in the console entry
	 * everything is calloc()ed, so STRING types are ready to rock
	 */

	buildMyString(acStart, &pCE->server);

	/*
	 *  Here we substitute the console name for any '&' character in the
	 *  logfile name.  That way you can just have something like
	 *  "/var/console/&" for each of the conserver.cf entries.
	 */
	pcStart = pcLog;
	while ((char *)0 != (pcRem = strchr(pcStart, '&'))) {
	    *pcRem = '\000';
	    buildMyString(pcStart, &pCE->lfile);
	    buildMyString(acStart, &pCE->lfile);
	    pcStart = pcRem + 1;
	}
	buildMyString(pcStart, &pCE->lfile);
	if (LogDirectory.used && pCE->lfile.used &&
	    *pCE->lfile.string != '/') {
	    char *p;
	    buildString((char *)0);
	    p = buildString(pCE->lfile.string);
	    buildMyString((char *)0, &pCE->lfile);
	    buildMyString(LogDirectory.string, &pCE->lfile);
	    buildMyStringChar('/', &pCE->lfile);
	    buildMyString(p, &pCE->lfile);
	    buildString((char *)0);
	}

	if (pcMark) {
	    (void)parseMark(pcFile, iLine, pcMark, tyme, pCE);
	} else {
	    (void)parseMark(pcFile, iLine, defMark.string, tyme, pCE);
	}

	pCE->breakType = 1;
	if (pcBreak) {
	    int bt;
	    bt = atoi(pcBreak);
	    if (bt > 9 || bt < 0) {
		Error("%s(%d) bad break spec `%d'", pcFile, iLine, bt);
	    } else {
		pCE->breakType = (short int)bt;
		Debug(1, "breakType set to %d", pCE->breakType);
	    }
	}

	pCE->ipid = pCE->fdtty = -1;
	pCE->fup = pCE->autoReUp = 0;
	pCE->pCLon = pCE->pCLwr = (CONSCLIENT *) 0;
	pCE->fdlog = (CONSFILE *) 0;

	if (pcLine[0] == '!') {
	    char acOut[100];
	    pcLine = pruneSpace(pcLine + 1);
	    pCE->isNetworkConsole = 1;
	    pCE->telnetState = 0;
	    buildMyString((char *)0, &pCE->networkConsoleHost);
	    buildMyString(pcLine, &pCE->networkConsoleHost);
	    pCE->networkConsolePort = atoi(pcMode);
	    pCE->fvirtual = 0;
	    buildMyString((char *)0, &pCE->dfile);
	    buildMyString(pCE->networkConsoleHost.string, &pCE->dfile);
	    sprintf(acOut, "/%d", pCE->networkConsolePort);
	    buildMyString(acOut, &pCE->dfile);
	    pCE->pbaud = FindBaud("Netwk");
	    pCE->pparity = FindParity(" ");
	    if (isStartup && fVerbose) {
		Info("%s is network on %s logged to %s", acStart,
		     pCE->dfile.string, pCE->lfile.string);
	    }
	} else if ('|' == pcLine[0]) {
	    pcLine = pruneSpace(pcLine + 1);
	    pCE->isNetworkConsole = 0;
	    pCE->telnetState = 0;
	    pCE->fvirtual = 1;
	    buildMyString((char *)0, &pCE->pccmd);
	    buildMyString(pcLine, &pCE->pccmd);
	    buildMyString((char *)0, &pCE->dfile);
	    buildMyString("/dev/null", &pCE->dfile);
	    buildMyString((char *)0, &pCE->acslave);
	    buildMyString("/dev/null", &pCE->acslave);
	    pCE->pbaud = FindBaud("Local");
	    pCE->pparity = FindParity(" ");
	    if (isStartup && fVerbose) {
		Info("%s with command `%s' logged to %s", acStart,
		     pCE->pccmd.string, pCE->lfile.string);
	    }
	} else {
	    pCE->isNetworkConsole = 0;
	    pCE->telnetState = 0;
	    pCE->fvirtual = 0;
	    buildMyString((char *)0, &pCE->dfile);
	    buildMyString(pcLine, &pCE->dfile);
	    pCE->pbaud = FindBaud(pcMode);
	    if (pCE->pbaud->irate == 0) {
		Error("%s(%d) invalid baud rate `%s'", pcFile, iLine,
		      pcMode);
		destroyConsent(pGE, pCE);
		continue;
	    }
	    pCE->pparity = FindParity(pcMode);
	    if (isStartup && fVerbose) {
		Info("%s is on %s (%s%c) logged to %s", acStart,
		     pCE->dfile.string, pCE->pbaud->acrate,
		     pCE->pparity->ckey, pCE->lfile.string);
	    }
	}

	/* ok, now for the hard part of the reread */
	if (pCEmatch != (CONSENT *) 0) {
	    short int closeMatch = 1;
	    /* see if the group is already staged */
	    for (pGEtmp = pGEstage; pGEtmp != (GRPENT *) 0;
		 pGEtmp = pGEtmp->pGEnext) {
		if (pGEtmp->id == pGEmatch->id)
		    break;
	    }

	    /* if not, allocate one, copy the data, and reset things */
	    if (pGEtmp == (GRPENT *) 0) {
		if ((GRPENT *) 0 ==
		    (pGEtmp = (GRPENT *) calloc(1, sizeof(GRPENT))))
		    OutOfMem();

		/* copy the data */
		*pGEtmp = *pGEmatch;

		/* don't destroy the fake console */
		pGEmatch->pCEctl = (CONSENT *) 0;

		/* prep counters and such */
		pGEtmp->pCElist = (CONSENT *) 0;
		pGEtmp->pCLall = (CONSCLIENT *) 0;
		pGEtmp->imembers = 0;
		FD_ZERO(&pGEtmp->rinit);

		/* link in to the staging area */
		pGEtmp->pGEnext = pGEstage;
		pGEstage = pGEtmp;

		/* fix the free list (the easy one) */
		/* the ppCLbnext link needs to point to the new group */
		if (pGEtmp->pCLfree != (CONSCLIENT *) 0)
		    pGEtmp->pCLfree->ppCLbnext = &pGEtmp->pCLfree;
		pGEmatch->pCLfree = (CONSCLIENT *) 0;

		if (pGEtmp->pCEctl) {
		    /* fix the half-logged in clients */
		    /* the pCLscan list needs to be rebuilt */
		    /* file descriptors need to be watched */
		    for (pCLtmp = pGEtmp->pCEctl->pCLon;
			 pCLtmp != (CONSCLIENT *) 0;
			 pCLtmp = pCLtmp->pCLnext) {
			/* remove cleanly from the old group */
			if ((CONSCLIENT *) 0 != pCLtmp->pCLscan) {
			    pCLtmp->pCLscan->ppCLbscan = pCLtmp->ppCLbscan;
			}
			*(pCLtmp->ppCLbscan) = pCLtmp->pCLscan;
			/* insert into the new group */
			pCLtmp->pCLscan = pGEtmp->pCLall;
			pCLtmp->ppCLbscan = &pGEtmp->pCLall;
			if (pCLtmp->pCLscan != (CONSCLIENT *) 0) {
			    pCLtmp->pCLscan->ppCLbscan = &pCLtmp->pCLscan;
			}
			pGEtmp->pCLall = pCLtmp;
			/* set file descriptors */
			FD_SET(fileFDNum(pCLtmp->fd), &pGEtmp->rinit);
		    }
		}
	    }
	    /* fix the real clients */
	    /* the pCLscan list needs to be rebuilt */
	    /* file descriptors need to be watched */
	    for (pCLtmp = pCEmatch->pCLon; pCLtmp != (CONSCLIENT *) 0;
		 pCLtmp = pCLtmp->pCLnext) {
		/* remove cleanly from the old group */
		if ((CONSCLIENT *) 0 != pCLtmp->pCLscan) {
		    pCLtmp->pCLscan->ppCLbscan = pCLtmp->ppCLbscan;
		}
		*(pCLtmp->ppCLbscan) = pCLtmp->pCLscan;
		/* insert into the new group */
		pCLtmp->pCLscan = pGEtmp->pCLall;
		pCLtmp->ppCLbscan = &pGEtmp->pCLall;
		if (pCLtmp->pCLscan != (CONSCLIENT *) 0) {
		    pCLtmp->pCLscan->ppCLbscan = &pCLtmp->pCLscan;
		}
		pGEtmp->pCLall = pCLtmp;
		/* set file descriptors */
		FD_SET(fileFDNum(pCLtmp->fd), &pGEtmp->rinit);
	    }

	    /* add the original console to the new group */
	    pCEmatch->pCEnext = pGEtmp->pCElist;
	    pGEtmp->pCElist = pCEmatch;
	    pGEtmp->imembers++;
	    if (pCEmatch->fdtty != -1) {
		FD_SET(pCEmatch->fdtty, &pGEtmp->rinit);
	    }

	    /* now check for any changes between pCEmatch & pCE! */

	    if (pCEmatch->isNetworkConsole != pCE->isNetworkConsole ||
		pCEmatch->fvirtual != pCE->fvirtual)
		closeMatch = 0;
	    if (pCEmatch->dfile.used && pCE->dfile.used) {
		if (strcmp(pCEmatch->dfile.string, pCE->dfile.string) != 0) {
		    buildMyString((char *)0, &pCEmatch->dfile);
		    buildMyString(pCE->dfile.string, &pCEmatch->dfile);
		    if (!pCE->fvirtual)
			closeMatch = 0;
		}
	    } else if (pCEmatch->dfile.used || pCE->dfile.used) {
		buildMyString((char *)0, &pCEmatch->dfile);
		buildMyString(pCE->dfile.string, &pCEmatch->dfile);
		if (!pCE->fvirtual)
		    closeMatch = 0;
	    }
	    if (pCEmatch->lfile.used && pCE->lfile.used) {
		if (strcmp(pCEmatch->lfile.string, pCE->lfile.string) != 0) {
		    buildMyString((char *)0, &pCEmatch->lfile);
		    buildMyString(pCE->lfile.string, &pCEmatch->lfile);
		    fileClose(&pCEmatch->fdlog);
		    closeMatch = 0;
		}
	    } else if (pCEmatch->lfile.used || pCE->lfile.used) {
		buildMyString((char *)0, &pCEmatch->lfile);
		buildMyString(pCE->lfile.string, &pCEmatch->lfile);
		fileClose(&pCEmatch->fdlog);
		closeMatch = 0;
	    }
	    if (pCEmatch->pbaud != pCE->pbaud) {
		pCEmatch->pbaud = pCE->pbaud;
		closeMatch = 0;
	    }
	    if (pCEmatch->pparity != pCE->pparity) {
		pCEmatch->pparity = pCE->pparity;
		closeMatch = 0;
	    }
	    if (pCEmatch->isNetworkConsole != pCE->isNetworkConsole) {
		pCEmatch->isNetworkConsole = pCE->isNetworkConsole;
		closeMatch = 0;
	    }
	    if (pCEmatch->fvirtual != pCE->fvirtual) {
		pCEmatch->fvirtual = pCE->fvirtual;
		closeMatch = 0;
	    }
	    if (pCE->isNetworkConsole) {
		if (pCEmatch->networkConsoleHost.used &&
		    pCE->networkConsoleHost.used) {
		    if (strcmp
			(pCEmatch->networkConsoleHost.string,
			 pCE->networkConsoleHost.string) != 0) {
			buildMyString((char *)0,
				      &pCEmatch->networkConsoleHost);
			buildMyString(pCE->networkConsoleHost.string,
				      &pCEmatch->networkConsoleHost);
			closeMatch = 0;
		    }
		} else if (pCEmatch->networkConsoleHost.used ||
			   pCE->networkConsoleHost.used) {
		    buildMyString((char *)0,
				  &pCEmatch->networkConsoleHost);
		    buildMyString(pCE->networkConsoleHost.string,
				  &pCEmatch->networkConsoleHost);
		    closeMatch = 0;
		}
		if (pCEmatch->networkConsolePort !=
		    pCE->networkConsolePort) {
		    pCEmatch->networkConsolePort = pCE->networkConsolePort;
		    closeMatch = 0;
		}
		if (pCEmatch->telnetState != pCE->telnetState) {
		    pCEmatch->telnetState = pCE->telnetState;
		    closeMatch = 0;
		}
	    }
	    if (pCE->fvirtual) {
		if (pCEmatch->pccmd.used && pCE->pccmd.used) {
		    if (strcmp(pCEmatch->pccmd.string, pCE->pccmd.string)
			!= 0) {
			buildMyString((char *)0, &pCEmatch->pccmd);
			buildMyString(pCE->pccmd.string, &pCEmatch->pccmd);
			closeMatch = 0;
		    }
		} else if (pCEmatch->pccmd.used || pCE->pccmd.used) {
		    buildMyString((char *)0, &pCEmatch->pccmd);
		    buildMyString(pCE->pccmd.string, &pCEmatch->pccmd);
		    closeMatch = 0;
		}
	    }
	    pCEmatch->activitylog = pCE->activitylog;
	    pCEmatch->breaklog = pCE->breaklog;
	    pCEmatch->mark = pCE->mark;
	    pCEmatch->nextMark = pCE->nextMark;
	    pCEmatch->breakType = pCE->breakType;

	    if (!closeMatch && !isMaster) {
		/* fdtty/fup/fronly/acslave/ipid */
		SendClientsMsg(pCEmatch,
			       "[-- Conserver reconfigured - console reset --]\r\n");
		ConsDown(pCEmatch, &pGEtmp->rinit);
	    }

	    /* nuke the temp data structure */
	    destroyConsent(pGE, pCE);
	}
    }

    /* go through and nuke groups (if a child or are empty) */
    for (ppGE = &pGroups; *ppGE != (GRPENT *) 0;) {
	if (!isMaster || (*ppGE)->imembers == 0) {
	    pGEtmp = *ppGE;
	    *ppGE = (*ppGE)->pGEnext;
	    destroyGroup(pGEtmp);
	} else {
	    ppGE = &((*ppGE)->pGEnext);
	}
    }
    /* now append the staged groups */
    *ppGE = pGEstage;

    /* nuke the old groups lists */
    while (pGroupsOld != (GRPENT *) 0) {
	pGEtmp = pGroupsOld->pGEnext;
	destroyGroup(pGroupsOld);
	pGroupsOld = pGEtmp;
    }

    /* nuke the old remote consoles */
    while (pRCListOld != (REMOTE *) 0) {
	pRCtmp = pRCListOld->pRCnext;
	destroyString(&pRCListOld->rserver);
	destroyString(&pRCListOld->rhost);
	free(pRCListOld);
	pRCListOld = pRCtmp;
    }

    *ppRC = (REMOTE *) 0;

    /* clean out the access restrictions
     */
    while (pACList != (ACCESS *) 0) {
	if (pACList->pcwho != (char *)0)
	    free(pACList->pcwho);
	pACtmp = pACList->pACnext;
	free(pACList);
	pACList = pACtmp;
    }
    pACList = (ACCESS *) 0;
    ppAC = &pACList;

    while ((acIn =
	    (unsigned char *)readLine(fp, &acInSave,
				      &iLine)) != (unsigned char *)0) {
	char *pcMach, *pcNext, *pcMem;
	char cType;
	int iLen;

	acStart = pruneSpace((char *)acIn);

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

	    if ((ACCESS *) 0 ==
		(pACtmp = (ACCESS *) calloc(1, sizeof(ACCESS)))) {
		OutOfMem();
	    }
	    iLen = strlen(pcMach);
	    if ((char *)0 == (pcMem = malloc(iLen + 1))) {
		OutOfMem();
	    }
	    pACtmp->ctrust = cType;
	    pACtmp->ilen = iLen;
	    pACtmp->pcwho = strcpy(pcMem, pcMach);
	    pACtmp->isCIDR = isCIDR;
	    *ppAC = pACtmp;
	    ppAC = &pACtmp->pACnext;
	}
    }

    destroyString(&LogDirectory);
    destroyString(&defMark);
}

/* Unless otherwise stated, returns the same values as send(2) */
void
#if USE_ANSI_PROTO
ReReadCfg(void)
#else
ReReadCfg()
#endif
{
    FILE *fpConfig;

    if ((FILE *) 0 == (fpConfig = fopen(pcConfig, "r"))) {
	Error("fopen: %s: %s", pcConfig, strerror(errno));
	return;
    }

    ReadCfg(pcConfig, fpConfig);

    fclose(fpConfig);

    if (pGroups == (GRPENT *) 0 && pRCList == (REMOTE *) 0) {
	if (isMaster) {
	    Error("No consoles found in configuration file");
	    kill(thepid, SIGTERM);	/* shoot myself in the head */
	    return;
	} else {
	    Error("No consoles to manage after reconfiguration - exiting");
	    exit(EX_OK);
	}
    }

    /* if no one can use us we need to come up with a default
     */
    if (pACList == (ACCESS *) 0) {
	SetDefAccess(&acMyAddr, acMyHost);
    }

    if (isMaster) {
	GRPENT *pGE;
	CONSENT *pCE;
	/* spawn all the children, so fix kids has an initial pid
	 */
	for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
	    if (pGE->imembers == 0 || pGE->pid != -1)
		continue;

	    Spawn(pGE);

	    if (fVerbose) {
		Info("group #%d pid %d on port %u", pGE->id, pGE->pid,
		     ntohs(pGE->port));
	    }
	    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0;
		 pCE = pCE->pCEnext) {
		if (-1 != pCE->fdtty)
		    (void)close(pCE->fdtty);
	    }
	}

	if (fVerbose) {
	    ACCESS *pACtmp;
	    for (pACtmp = pACList; pACtmp != (ACCESS *) 0;
		 pACtmp = pACtmp->pACnext) {
		Info("access type '%c' for \"%s\"", pACtmp->ctrust,
		     pACtmp->pcwho);
	    }
	}

	pRCUniq = FindUniq(pRCList);

	/* output unique console server peers?
	 */
	if (fVerbose) {
	    REMOTE *pRC;
	    for (pRC = pRCUniq; (REMOTE *) 0 != pRC; pRC = pRC->pRCuniq) {
		Info("peer server on `%s'", pRC->rhost.string);
	    }
	}
    }
}
