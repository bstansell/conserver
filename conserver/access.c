/*
 *  $Id: access.c,v 5.35 2001-07-23 00:45:49-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000-2001
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

#include <sys/types.h>
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
#include <port.h>
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
AddrCmp(addr, pattern)
    struct in_addr *addr;
    char *pattern;
{
    unsigned long int hostaddr, pattern_addr, netmask;
    char buf[200], *p, *slash_posn;

    slash_posn = strchr(pattern, '/');
    if (slash_posn != NULL) {
	if (strlen(pattern) >= sizeof(buf))
	    return 1;		/* too long to handle */
	strncpy(buf, pattern, sizeof(buf));
	buf[slash_posn - pattern] = '\0';	/* isolate the address */
	p = buf;
    } else
	p = pattern;

    pattern_addr = inet_addr(p);
    if (pattern_addr == -1)
	return 1;		/* malformed address */

    if (slash_posn) {
	/* convert explicit netmask */
	int mask_bits = atoi(slash_posn + 1);
	for (netmask = 0; mask_bits > 0; --mask_bits)
	    netmask = 0x80000000 | (netmask >> 1);
    } else {
	/* netmask implied by address class */
	unsigned long int ia = ntohl(pattern_addr);
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
    hostaddr = *(unsigned long int *)addr;

    Debug("Access check:       host=%lx(%lx/%lx)", hostaddr & netmask,
	  hostaddr, netmask);
    Debug("Access check:        acl=%lx(%lx/%lx)", pattern_addr & netmask,
	  pattern_addr, netmask);
    return (hostaddr & netmask) != (pattern_addr & netmask);
}

/* return the access type for a given host entry			(ksb)
 */
char
AccType(addr, hname)
    struct in_addr *addr;
    char *hname;
{
    int i;
    char *pcName;
    int len;

    if (fDebug) {
	if (hname)
	    Debug("Access check: hostname=%s, ip=%s", hname,
		  inet_ntoa(*addr));
	else
	    Debug("Access check: hostname=<unresolvable>, ip=%s",
		  inet_ntoa(*addr));
    }
    for (i = 0; i < iAccess; ++i) {
	Debug("Access check:    who=%s, trust=%c", pACList[i].pcwho,
	      pACList[i].ctrust);
	if (pACList[i].isCIDR != 0) {
	    if (0 == AddrCmp(addr, pACList[i].pcwho)) {
		return pACList[i].ctrust;
	    }
	    continue;
	}
	if (hname && hname[0] != '\000') {
	    pcName = hname;
	    len = strlen(pcName);
	    while (len >= pACList[i].ilen) {
		Debug("Access check:       name=%s", pcName);
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
    }
    return chDefAcc;
}

/* we know iAccess == 0, we want to setup a nice default access list	(ksb)
 */
void
SetDefAccess(hpLocal)
    struct hostent *hpLocal;
{
    char *pcWho, *pcDomain;
    int iLen;
    char *addr;
    struct in_addr *aptr;

    aptr = (struct in_addr *)(hpLocal->h_addr);
    addr = inet_ntoa(*aptr);
    pACList = (ACCESS *) calloc(3, sizeof(ACCESS));
    if ((ACCESS *) 0 == pACList) {
	OutOfMem();
    }
    if ((char *)0 == (pcWho = malloc(strlen(addr) + 1))) {
	OutOfMem();
    }
    strcpy(pcWho, addr);
    pACList[iAccess].ctrust = 'a';
    pACList[iAccess].ilen = strlen(pcWho);
    pACList[iAccess].pcwho = pcWho;

    Debug("Access list prime: trust=%c, who=%s", pACList[iAccess].ctrust,
	  pACList[iAccess].pcwho);

    iAccess++;

    if ((char *)0 == (pcDomain = strchr(hpLocal->h_name, '.'))) {
	return;
    }
    ++pcDomain;
    iLen = strlen(pcDomain);
    pcWho = malloc(iLen + 1);
    pACList[iAccess].ctrust = 'a';
    pACList[iAccess].ilen = iLen;
    pACList[iAccess].pcwho = strcpy(pcWho, pcDomain);

    Debug("Access list prime: trust=%c, who=%s", pACList[iAccess].ctrust,
	  pACList[iAccess].pcwho);

    iAccess++;
}

/* thread ther list of uniq console server machines, aliases for	(ksb)
 * machines will screw us up
 */
REMOTE *
FindUniq(pRCAll)
    REMOTE *pRCAll;
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
	if (0 == strcmp(pRC->rhost, pRCAll->rhost)) {
	    return pRCAll->pRCuniq;
	}
    }
    return pRCAll;
}
