/*
 *  $Id: client.c,v 5.20 1999-01-13 11:48:11-08 bryan Exp $
 *
 *  GNAC, Inc., 1998
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
#include "consent.h"
#include "client.h"

#if USE_STRINGS
#include <strings.h>
#else
#include <string.h>
#endif

/* find the next guy who wants to write on the console			(ksb)
 */
CLIENT *
FindWrite(pCL)
CLIENT *pCL;
{
	/* return the first guy to have the `want write' bit set
	 * (tell him of the promotion, too)  we could look for the
	 * most recent or some such... I guess it doesn't matter that
	 * much.
	 */
	for (/*passed in*/; (CLIENT *)0 != pCL; pCL = pCL->pCLnext) {
		if (!pCL->fwantwr)
			continue;
		if (!pCL->pCEto->fup || pCL->pCEto->fronly)
			break;
		pCL->fwantwr = 0;
		pCL->fwr = 1;
		if ( pCL->pCEto->nolog ) {
		    CSTROUT(pCL->fd, "\r\n[attached (nologging)]\r\n");
		} else {
		    CSTROUT(pCL->fd, "\r\n[attached]\r\n");
		}
		return pCL;
	}
	return (CLIENT *)0;
}

#if HAVE_IDENTD
/* use identd to verify a user at a host				(ksb)
 * we have a list of login@host:passwd:trust after the general host
 * limits.  We call identd/tap/auth to get info and compare
 */
IdentifyMe(pCL)
CLIENT *pCL;
{
	/* ZZZ */
	/* we would have to getsockname(fdClient)
	 * getpeername(fdClient)
	 * identd_client(addr, addr, acBuffer
	 * check for identifier in allowed list
	 * return the permision (modify in pCL)
	 */
}
#endif

/* show a character as a string so the user cannot mistake it for	(ksb)
 * another
 * 
 * must pass us at least 16 characters to put fill with text
 */
char *
FmtCtl(ci, pcIn)
int ci;
char *pcIn;
{
	register char *pcOut = pcIn;
	unsigned char c;

	c = ci & 0xff;
	if (c > 127) {
		c -= 128;
		*pcOut++ = 'M';
		*pcOut++ = '-';
	}

	if (c < ' ' || c == '\177') {
		*pcOut++ = '^';
		*pcOut++ = c ^ 0100;
		*pcOut = '\000';
	} else if (c == ' ') {
		(void)strcpy(pcOut, "<space>");
	} else if (c == '^') {
		(void)strcpy(pcOut, "<circumflex>");
	} else if (c == '\\') {
		(void)strcpy(pcOut, "<backslash>");
	} else {
		*pcOut++ = c;
		*pcOut = '\000';
	}
	return pcIn;
}

/* replay last iBack lines of the log file upon connect to console	(ksb)
 *
 * NB: we know the console might be spewing when the replay happens,
 * we want to just output what is in the log file and get out,
 * so we don't drop chars...
 */
void
Replay(fdLog, fdOut, iBack)
int fdLog, fdOut, iBack;
{
	register int tot, nCr;
	register char *pc;
	register off_t where;
	auto char bf[MAXREPLAY+2];
	auto struct stat stLog;

	if (-1 == fdLog) {
		CSTROUT(fdOut, "[no log file on this console]\r\n");
		return;
	}

	/* find the size of the file
	 */
	if (0 != fstat(fdLog, & stLog)) {
		return;
	}

	if (MAXREPLAY > stLog.st_size) {
		where = 0L;
	} else {
		where = stLog.st_size - MAXREPLAY;
	}

#if defined(SEEK_SET)
	/* PTX and maybe other Posix systems
	 */
	if (lseek(fdLog, where, SEEK_SET) < 0) {
		return;
	}
#else
	if (lseek(fdLog, where, L_SET) < 0) {
		return;
	}
#endif

	if ((tot = read(fdLog, bf, MAXREPLAY)) <= 0) {
		return;
	}
	bf[tot] = '@';

	pc = & bf[tot];
	nCr = 0;
	while (--pc != bf) {
		if ('\n' == *pc && iBack == nCr++) {
			++pc;	/* get rid of a blank line */
			break;
		}
	}

	(void)write(fdOut, pc, tot-(pc - bf));
}


/* these bit tell us which parts of the Truth to tell the client	(ksb)
 */
#define WHEN_SPY	0x01
#define WHEN_ATTACH	0x02
#define WHEN_VT100	0x04
#define WHEN_EXPERT	0x08	/* ZZZ no way to set his yet	*/
#define WHEN_ALWAYS	0x40

#define HALFLINE	40
typedef struct HLnode {
	int iwhen;
	char actext[HALFLINE];
} HELP;

static HELP aHLTable[] = {
	{ WHEN_ALWAYS,	".    disconnect"},
	{ WHEN_ALWAYS,	"a    attach read/write"},
	{ WHEN_ATTACH,	"c    toggle flow control"},
	{ WHEN_ATTACH,	"d    down a console"},
	{ WHEN_ALWAYS,	"e    change escape sequence"},
	{ WHEN_ALWAYS,	"f    force attach read/write"},
	{ WHEN_ALWAYS,	"g    group info"},
	{ WHEN_ATTACH,	"L    toggle logging on/off"},
	{ WHEN_ATTACH,	"l1   send break (halt host!)"},
	{ WHEN_ALWAYS,	"o    (re)open the tty and log file"},
	{ WHEN_ALWAYS,	"p    replay the last 60 lines"},
	{ WHEN_ALWAYS,	"r    replay the last 20 lines"},
	{ WHEN_ATTACH,	"s    spy read only"},
	{ WHEN_ALWAYS,	"u    show host status"},
	{ WHEN_ALWAYS,	"v    show version info"},
	{ WHEN_ALWAYS,	"w    who is on this console"},
	{ WHEN_ALWAYS,	"x    show console baud info"},
	{ WHEN_ALWAYS,	"z    suspend the connection"},
	{ WHEN_ALWAYS,	"<cr> ignore/abort command"},
	{ WHEN_ALWAYS,	"?    print this message"},
	{ WHEN_ALWAYS,	"^R   short replay"},
	{ WHEN_ATTACH, "\\ooo send character by octal code"},
	{ WHEN_EXPERT,	"^I   toggle tab expansion"},
	{ WHEN_EXPERT,	";    change to another console"},
	{ WHEN_EXPERT,	"+(-) do (not) drop line"},
	{ WHEN_VT100,	"PF1  print this message"},
	{ WHEN_VT100,	"PF2  disconnect"},
	{ WHEN_VT100,	"PF3  replay the last 20 lines"},
	{ WHEN_VT100,	"PF4  spy read only"}
};

/* list the commands we know for the user				(ksb)
 */
void
HelpUser(pCL)
CLIENT *pCL;
{
	register int i, j, iCmp;
	static char
		acH1[] = "help]\r\n",
		acH2[] = "help spy mode]\r\n",
		acEoln[] = "\r\n";
	auto char acLine[HALFLINE*2+3];

	iCmp = WHEN_ALWAYS|WHEN_SPY;
	if (pCL->fwr) {
		(void)write(pCL->fd, acH1, sizeof(acH1)-1);
		iCmp |= WHEN_ATTACH;
	} else {
		(void)write(pCL->fd, acH2, sizeof(acH2)-1);
	}
	if ('\033' == pCL->ic[0] && 'O' == pCL->ic[1]) {
		iCmp |= WHEN_VT100;
	}

	acLine[0] = '\000';
	for (i = 0; i < sizeof(aHLTable)/sizeof(HELP); ++i) {
		if (0 == (aHLTable[i].iwhen & iCmp)) {
			continue;
		}
		if ('\000' == acLine[0]) {
			acLine[0] = ' ';
			(void)strcpy(acLine+1, aHLTable[i].actext);
			continue;
		}
		for (j = strlen(acLine); j < HALFLINE+1; ++j) {
			acLine[j] = ' ';
		}
		(void)strcpy(acLine+j, aHLTable[i].actext);
		(void)strcat(acLine+j, acEoln);
		(void)write(pCL->fd, acLine, strlen(acLine));
		acLine[0] = '\000';
	}
	if ('\000' != acLine[0]) {
		(void)strcat(acLine, acEoln);
		(void)write(pCL->fd, acLine, strlen(acLine));
	}
}
