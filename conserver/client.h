/*
 *  $Id: client.h,v 5.25 2002-02-25 14:00:38-08 bryan Exp $
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
/* states for a server fsm
 */
#define S_NORMAL 0		/* just pass character                          */
#define S_ESC1	 1		/* first escape character received              */
#define S_CMD	 2		/* second interrupt character received          */
#define S_CATTN	 3		/* change 1 escape character to next input char */
#define S_CESC	 4		/* change 2 escape character to next input char */
#define S_HALT1	 5		/* we have a halt sequence in progress          */
#define S_SUSP	 6		/* we are suspened, first char wakes us up      */
#define S_IDENT	 7		/* probational connection (who is this)         */
#define S_HOST	 8		/* still needs a host name to connect           */
#define S_PASSWD 9		/* still needs a passwd to connect              */
#define S_QUOTE 10		/* send any character we can spell              */
#define S_BCAST 11		/* send a broadcast message to all connections  */

typedef struct client {		/* Connection Information:              */
    CONSFILE *fd;		/* file descriptor                      */
    short fcon;			/* currently connect or not             */
    short fwr;			/* (client) write enable flag           */
    short fwantwr;		/* (client) wants to write              */
    short fecho;		/* echo commands (not set by machines)  */
    STRING acid;		/* login and location of client         */
    STRING peername;		/* location of client                   */
    time_t tym;			/* time of connect                      */
    time_t typetym;		/* time of last keystroke               */
    char actym[32];		/* pre-formatted time                   */
    struct consent
     *pCEwant,			/* what machine we would like to be on  */
     *pCEto;			/* host a client gets output from       */
    struct client
    **ppCLbscan,		/* back link for scan ptr               */
     *pCLscan,			/* next client fd to scan after select  */
	/* scan lists link ALL clients together */
    **ppCLbnext,		/* back link for next ptr               */
     *pCLnext;			/* next person on this list             */
    /* next lists link clients on a console */
    char ic[2];			/* two character escape sequence        */
    char iState;		/* state for fsm in server              */
    char caccess;		/* did we trust the remote machine      */
    STRING accmd;		/* the command the user issued          */
    STRING msg;			/* the broadcast message                */
    struct sockaddr_in
      cnct_port;		/* where from                           */
} CONSCLIENT;

#if USE_ANSI_PROTO
extern char *FmtCtl(int, STRING *);
extern void Replay(CONSFILE *, CONSFILE *, int);
extern void HelpUser(CONSCLIENT *);
extern CONSCLIENT *FindWrite(CONSCLIENT *);
#else
extern char *FmtCtl();
extern void Replay();
extern void HelpUser();
extern CONSCLIENT *FindWrite();
#endif
