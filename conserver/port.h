/*
 *  $Id: port.h,v 1.31 2002-01-21 02:48:33-08 bryan Exp $
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

/* If, when processing a logfile for replaying the last N lines,
 * we end up seeing more than MAXREPLAYLINELEN characters in a line,
 * abort processing and display the data.  Why?  There could be some
 * very large logfiles and very long lines and we'd chew up lots of
 * memory and send a LOT of data down to the client - all potentially
 * bad.  If there's a line over this in size, would you really want to
 * see the whole thing (and possibly others)?
 */
#if !defined(MAXREPLAYLINELEN)
# define MAXREPLAYLINELEN 10000
#endif

/* the default escape sequence used to give meta commands
 */
#if !defined(DEFATTN)
# define DEFATTN	'\005'
#endif
#if !defined(DEFESC)
# define DEFESC		'c'
#endif

/* communication constants
 */
#define OB_SUSP		'Z'	/* suspended by server          */
#define OB_DROP		'.'	/* dropped by server            */

/* For legacy compile-time setting of the port...
 */
#if ! defined(DEFPORT)
#  if defined(SERVICENAME)
#    define DEFPORT SERVICENAME
#  else
#    if defined(PORTNUMBER)
#      define DEFPORT PORTNUMBER
#    else
#      define DEFPORT "conserver"
#    endif
#  endif
#endif
