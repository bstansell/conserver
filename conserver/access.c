/*
 *  $Id: access.c,v 5.53 2003-04-06 05:31:54-07 bryan Exp $
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

#include <config.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>

#include <compat.h>
#include <util.h>

#include <access.h>
#include <consent.h>
#include <client.h>
#include <group.h>
#include <readcfg.h>
#include <main.h>



/* Compare an Internet address (IPv4 expected), with an address pattern
 * passed as a character string representing an address in the Internet
 * standard `.' notation, optionally followed by a slash and an integer
 * specifying the number of bits in the network portion of the address
 * (the netmask size). If not specified explicitly, the netmask size used
 * is that implied by the address class. If either the netmask is specified
 * explicitly, or the local network address part of the pattern is zero,
 * then only the network number parts of the addresses are compared;
 * otherwise the entire addresses are compared.
 *
 * Returns 0 if the addresses match, else returns 1.
 */
int
#if PROTOTYPES
AddrCmp(struct in_addr *addr, char *pattern)
#else
AddrCmp(addr, pattern)
    struct in_addr *addr;
    char *pattern;
#endif
{
    in_addr_t hostaddr, pattern_addr, netmask;
    char *p, *slash_posn;
    static STRING *buf = (STRING *) 0;

    if (buf == (STRING *) 0)
	buf = AllocString();
    slash_posn = strchr(pattern, '/');
    if (slash_posn != NULL) {
	BuildString((char *)0, buf);
	BuildString(pattern, buf);
	buf->string[slash_posn - pattern] = '\0';	/* isolate the address */
	p = buf->string;
    } else
	p = pattern;

    pattern_addr = inet_addr(p);
    if (pattern_addr == (in_addr_t) (-1))
	return 1;		/* malformed address */

    if (slash_posn) {
	/* convert explicit netmask */
	int mask_bits = atoi(slash_posn + 1);
	for (netmask = 0; mask_bits > 0; --mask_bits)
	    netmask = 0x80000000 | (netmask >> 1);
    } else {
	/* netmask implied by address class */
	in_addr_t ia = ntohl(pattern_addr);
	if (IN_CLASSA(ia))
	    netmask = IN_CLASSA_NET;
	else if (IN_CLASSB(ia))
	    netmask = IN_CLASSB_NET;
	else if (IN_CLASSC(ia))
	    netmask = IN_CLASSC_NET;
	else
	    return 1;		/* unsupported address class */
    }
    netmask = htonl(netmask);
    if (~netmask & pattern_addr)
	netmask = 0xffffffff;	/* compare entire addresses */
    hostaddr = addr->s_addr;

    Debug(1, "AddrCmp(): host=%lx(%lx/%lx) acl=%lx(%lx/%lx)",
	  hostaddr & netmask, hostaddr, netmask, pattern_addr & netmask,
	  pattern_addr, netmask);
    return (hostaddr & netmask) != (pattern_addr & netmask);
}

/* return the access type for a given host entry			(ksb)
 */
char
#if PROTOTYPES
AccType(struct in_addr *addr, char *hname)
#else
AccType(addr, hname)
    struct in_addr *addr;
    char *hname;
#endif
{
    char *pcName;
    int len;
    ACCESS *pACtmp;

    if (fDebug) {
	if (hname)
	    Debug(1, "AccType(): hostname=%s, ip=%s", hname,
		  inet_ntoa(*addr));
	else
	    Debug(1, "AccType(): hostname=<unresolvable>, ip=%s",
		  inet_ntoa(*addr));
    }
    for (pACtmp = pACList; pACtmp != (ACCESS *) 0;
	 pACtmp = pACtmp->pACnext) {
	Debug(1, "AccType(): who=%s, trust=%c", pACtmp->pcwho,
	      pACtmp->ctrust);
	if (pACtmp->isCIDR != 0) {
	    if (0 == AddrCmp(addr, pACtmp->pcwho)) {
		return pACtmp->ctrust;
	    }
	    continue;
	}
	if (hname && hname[0] != '\000') {
	    pcName = hname;
	    len = strlen(pcName);
	    while (len >= pACtmp->ilen) {
		Debug(1, "AccType(): name=%s", pcName);
		if (0 == strcasecmp(pcName, pACtmp->pcwho)) {
		    return pACtmp->ctrust;
		}
		pcName = strchr(pcName, '.');
		if ((char *)0 == pcName) {
		    break;
		}
		++pcName;
		len = strlen(pcName);
	    }
	}
    }
    return chDefAcc;
}

void
#if PROTOTYPES
SetDefAccess(struct in_addr *pAddr, char *pHost)
#else
SetDefAccess(pAddr, pHost)
    struct in_addr *pAddr;
    char *pHost;
#endif
{
    char *pcWho, *pcDomain;
    int iLen;
    char *addr;

    addr = inet_ntoa(*pAddr);
    iLen = strlen(addr);
    if ((ACCESS *) 0 == (pACList = (ACCESS *) calloc(1, sizeof(ACCESS)))) {
	OutOfMem();
    }
    if ((char *)0 == (pcWho = malloc(iLen + 1))) {
	OutOfMem();
    }
    pACList->ctrust = 'a';
    pACList->ilen = iLen;
    pACList->pcwho = strcpy(pcWho, addr);

    Debug(1, "SetDefAccess(): trust=%c, who=%s", pACList->ctrust,
	  pACList->pcwho);

    if ((char *)0 == (pcDomain = strchr(pHost, '.'))) {
	return;
    }
    ++pcDomain;
    iLen = strlen(pcDomain);

    if ((ACCESS *) 0 ==
	(pACList->pACnext = (ACCESS *) calloc(1, sizeof(ACCESS)))) {
	OutOfMem();
    }
    if ((char *)0 == (pcWho = malloc(iLen + 1))) {
	OutOfMem();
    }
    pACList->pACnext->ctrust = 'a';
    pACList->pACnext->ilen = iLen;
    pACList->pACnext->pcwho = strcpy(pcWho, pcDomain);

    Debug(1, "SetDefAccess(): trust=%c, who=%s", pACList->pACnext->ctrust,
	  pACList->pACnext->pcwho);
}

/* thread ther list of uniq console server machines, aliases for	(ksb)
 * machines will screw us up
 */
REMOTE *
#if PROTOTYPES
FindUniq(REMOTE * pRCAll)
#else
FindUniq(pRCAll)
    REMOTE *pRCAll;
#endif
{
    REMOTE *pRC;

    /* INV: tail of the list we are building always contains only
     * uniq hosts, or the empty list.
     */
    if ((REMOTE *) 0 == pRCAll) {
	return (REMOTE *) 0;
    }

    pRCAll->pRCuniq = FindUniq(pRCAll->pRCnext);

    /* if it is in the returned list of uniq hosts, return that list
     * else add us by returning our node
     */
    for (pRC = pRCAll->pRCuniq; (REMOTE *) 0 != pRC; pRC = pRC->pRCuniq) {
	if (0 == strcasecmp(pRC->rhost.string, pRCAll->rhost.string)) {
	    return pRCAll->pRCuniq;
	}
    }
    return pRCAll;
}

void
#if PROTOTYPES
DestroyRemoteConsole(REMOTE * pRCList)
#else
DestroyRemoteConsole(pRCList)
    REMOTE *pRCList;
#endif
{
    DestroyString(&pRCList->rserver);
    DestroyString(&pRCList->rhost);
    free(pRCList);
}

void
#if PROTOTYPES
DestroyAccessList(ACCESS * pACList)
#else
DestroyAccessList(pACList)
    ACCESS *pACList;
#endif
{
    if (pACList->pcwho != (char *)0)
	free(pACList->pcwho);
    free(pACList);
}
