/*
 *  $Id: port.h,v 1.20 2001-02-08 15:32:49-08 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
 */

#include <config.h>

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

/* Wait for a part of a second before slapping console server.
 * Good for CISCO terminal servers that get upset when you
 * attack with intense socket connections
 */
#if !defined(USLEEP_FOR_SLOW_PORTS)
# define USLEEP_FOR_SLOW_PORTS 100000
#endif

/* the default escape sequence used to give meta commands
 */
#if !defined(DEFATTN)
# define DEFATTN	'\005'
#endif
#if !defined(DEFESC)
# define DEFESC		'c'
#endif

/* the max number of characters conserver will replay for you (the r command)
 */
#if !defined(MAXREPLAY)
# define MAXREPLAY	(80*25)
#endif

/* the console server will provide a pseudo-device console which
 * allows operators to run backups and such without a hard wired
 * line (this is also good for testing the server to see if you
 * might wanna use it).  Turn this on only if you (might) need it.
 */
#if !defined(DO_VIRTUAL)
# define DO_VIRTUAL	1
#endif

#if DO_VIRTUAL
/* if the virtual console option is on we need a source to ptys,
 * the PUCC ptyd daemon is the best source be know, else fall back
 * on some emulation code?? (XXX)
 */
#if !defined(HAVE_PTYD)
# define HAVE_PTYD	(defined(S81)||defined(VAX8800))
#endif

#endif /* virtual (process on a pseudo-tty) console support */

/* communication constants
 */
#define OB_SUSP		'Z'		/* suspended by server		*/
#define OB_DROP		'.'		/* dropped by server		*/

/* Due to C's poor man's macros the macro below would break if statements,
 * What we want
 *	macro()			{ stuff }
 * but the syntax gives us
 *	macro()			{ stuff };
 *
 * the extra semicolon breaks if statements!
 * Of course, the one we use makes lint scream:
 *	macro()			do { stuff } while (0)
 *
 * which is a statement and makes if statements safe
 */
#if defined(lint)
extern int shut_up_lint;
#else
# define shut_up_lint	0
#endif

/* this macro efficently outputs a constant string to a fd
 * of course it doesn't check the write :-(
 */
#define CSTROUT(Mfd, Mstr)	do {	\
	static char _ac[] = Mstr; \
	write(Mfd, _ac, sizeof(_ac)-1); \
	} while (shut_up_lint)

