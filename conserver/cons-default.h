/*
 *  $Id: cons-default.h,v 1.5 2000-09-08 16:09:04-07 bryan Exp $
 *
 *  Copyright GNAC, Inc., 1998
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@gnac.com)
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
#define CONNECTTIMEOUT	60
