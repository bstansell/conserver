/*
 * $Id: consent.h,v 5.11 1998-12-14 11:20:15-08 bryan Exp $
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
/*
 * Network console modifications by Robert Olson, olson@mcs.anl.gov.
 */


/* stuff to keep track of a console entry
 */
typedef struct baud {		/* a baud rate table			*/
	char acrate[8];
	int irate;
} BAUD;

typedef struct parity {		/* a parity bits table			*/
	char ckey;
	int iset;
	int iclr;
} PARITY;

#define MAXSERVLEN	32	/* max length of server name		*/
#define MAXDEVLEN	512	/* max length of /dev/ttyax		*/
#define MAXLOGLEN	1024	/* max length of /usr/adm/consoles/foo	*/
#define MAXTTYLINE	(133*2)	/* max length of a single buf'd line	*/
#define ALARMTIME	60	/* time between chimes			*/

typedef struct consent {	/* console information			*/
	char server[MAXSERVLEN];/* server name				*/
	char dfile[MAXDEVLEN];	/* device file				*/
	char lfile[MAXLOGLEN];	/* log file				*/
	BAUD *pbaud;		/* the baud on this console port	*/
	PARITY *pparity;	/* the parity on this line		*/
	int mark;		/* Mark (chime) interval		*/
	long nextMark;		/* Next mark (chime) time		*/

 	/* Used if network console */
 	int isNetworkConsole;
	char networkConsoleHost[MAXSERVLEN];
	int networkConsolePort;

#if DO_VIRTUAL
	/* used if virtual console */
	char acslave[MAXDEVLEN];/* pseudo-device slave side		*/
	int fvirtual;		/* is a pty device we use as a console	*/
	char *pccmd;		/* virtual console command		*/
	int ipid;		/* pid of virtual command		*/
#endif
	/* only used in child */
	int nolog;		/* don't log output			*/
	int fdlog;		/* the local log file			*/
	int fdtty;		/* the port to talk to machine on	*/
	short int fup;		/* we setup this line?			*/
	short int fronly;	/* we can only read this console	*/
	short int iend;		/* like icursor in CLIENT		*/
	short int inamelen;	/* strlen(server)			*/
	struct client *pCLon;	/* clients on this console		*/
	struct client *pCLwr;	/* client that is writting on console	*/
	char acline[132*2+2];	/* max chars we will call a line	*/
} CONSENT;

extern PARITY *FindParity();
extern BAUD *FindBaud();
extern void ConsInit();
extern void ConsDown();
