/*
 *  $Id: consent.h,v 5.35 2003-03-09 15:21:49-08 bryan Exp $
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
/*
 * Network console modifications by Robert Olson, olson@mcs.anl.gov.
 */


/* stuff to keep track of a console entry
 */
typedef struct baud {		/* a baud rate table                    */
    char acrate[8];
    int irate;
} BAUD;

typedef struct parity {		/* a parity bits table                  */
    char ckey;
    int iset;
    int iclr;
} PARITY;

typedef struct consent {	/* console information                  */
    STRING server;		/* server name                          */
    STRING dfile;		/* device file                          */
    STRING lfile;		/* log file                             */
    BAUD *pbaud;		/* the baud on this console port        */
    PARITY *pparity;		/* the parity on this line              */
    int mark;			/* Mark (chime) interval                */
    long nextMark;		/* Next mark (chime) time               */
    short breakType;		/* break type [1-9]                     */
    int autoReUp;

    /* Used if network console */
    int isNetworkConsole;
    STRING networkConsoleHost;
    unsigned short networkConsolePort;
    int telnetState;

    /* used if virtual console */
    STRING acslave;		/* pseudo-device slave side             */
    int fvirtual;		/* is a pty device we use as a console  */
    STRING pccmd;		/* virtual console command              */
    pid_t ipid;			/* pid of virtual command               */

    /* only used in child */
    int nolog;			/* don't log output                     */
    CONSFILE *fdlog;		/* the local log file                   */
    int fdtty;			/* the port to talk to machine on       */
    int activitylog;		/* log attach/detach/bump               */
    int breaklog;		/* log breaks sent                      */
    short fup;			/* we setup this line?                  */
    short fronly;		/* we can only read this console        */
    struct client *pCLon;	/* clients on this console              */
    struct client *pCLwr;	/* client that is writting on console   */
    char acline[132 * 2 + 2];	/* max chars we will call a line        */
    short iend;			/* length of data stored in acline      */
    struct consent *pCEnext;	/* next console entry                   */
} CONSENT;

struct hostcache {
    STRING hostname;
    struct hostcache *next;
};

extern PARITY *FindParity PARAMS((char *));
extern BAUD *FindBaud PARAMS((char *));
extern void ConsInit PARAMS((CONSENT *, fd_set *, int));
extern void ConsDown PARAMS((CONSENT *, fd_set *));
extern int CheckHostCache PARAMS((const char *));
extern void AddHostCache PARAMS((const char *));
extern void ClearHostCache PARAMS((void));
