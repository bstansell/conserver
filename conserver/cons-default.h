/*
 *  $Id: cons-default.h,v 1.7 2000-12-13 12:31:07-08 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
 */

/*
 * Socket used to communicate
 * Choose either PORT or SERVICE...
 */
/*#define PORT		782*/
#define SERVICE		"conserver"

/*
 * Hostname of console server
 */
#define HOST		"console"

/*
 * Config file path
 */
#define CONFIG		"/etc/conserver.cf"

/*
 * Password file path
 */
#define PASSWD_FILE	"/etc/conserver.passwd"

/*
 * Number of consoles per child process
 */
#define MAXMEMB		8

/*
 * Number of child processes
 */
#define MAXGRP		32

/*
 * Clear parity (high-bit) [true/false setting]
 */
#define CPARITY		1

/*
 * TCP connection timeout
 */
#define CONNECTTIMEOUT	10
