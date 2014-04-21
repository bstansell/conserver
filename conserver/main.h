/*
 *  $Id: main.h,v 5.55 2014/04/20 06:45:07 bryan Exp $
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

/* program options and stuff
 */
extern char rcsid[];
extern int fAll, fNoinit, fInteractive, fStrip, fDaemon, fReopen,
    fNoautoreup, fSyntaxOnly;
#if USE_IPV6
extern struct addrinfo *bindAddr;
extern struct addrinfo *bindBaseAddr;
#else
extern in_addr_t bindAddr;
extern struct sockaddr_in in_port;
#endif
extern unsigned short bindPort, bindBasePort;
extern char *pcConfig;
extern int cMaxMemb;
extern CONFIG *optConf;
extern CONFIG *config;
extern CONFIG defConfig;
extern CONSFILE *unifiedlog;
#if USE_UNIX_DOMAIN_SOCKETS
extern char *interface;
#endif
#if HAVE_OPENSSL
extern SSL_CTX *ctx;
#endif
#if HAVE_GSSAPI
extern gss_name_t gss_myname;
extern gss_cred_id_t gss_mycreds;
#endif
extern void ReopenLogfile(void);
extern void ReopenUnifiedlog(void);
extern void DumpDataStructures(void);
