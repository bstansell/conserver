/*
 *  $Id: main.h,v 5.9 1998-12-17 17:21:24-08 bryan Exp $
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

/* program options and stuff
 */
extern char rcsid[];
extern char *progname;
extern int fAll, fVerbose, fSoftcar, fInteractive;
extern char chDefAcc;
extern char *pcConfig;
extern struct sockaddr_in in_port;
extern char acMyHost[];
extern int domainHack;

#if defined(SERVICE)
extern char acService[];
#endif
