/*
 *  $Id: main.c,v 5.120 2003-03-09 15:20:43-08 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
 */

/*
 * Copyright (c) 1990 The Ohio State University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by The Ohio State University and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <config.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>

#include <compat.h>
#include <util.h>

#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <master.h>
#include <readcfg.h>
#include <version.h>

int fAll = 0, fSoftcar = 0, fNoinit = 0, fVersion = 0, fStrip =
    0, fDaemon = 0, fUseLogfile = 0, fReopen = 0, fReopenall =
    0, fNoautoreup = 0, fNoredir = 0;

char chDefAcc = 'r';

char *pcLogfile = LOGFILEPATH;
char *pcConfig = CONFIGFILE;
char *pcPasswd = PASSWDFILE;
char *pcPort = DEFPORT;
char *pcBasePort = DEFBASEPORT;
STRING *defaultShell = (STRING *) 0;
int domainHack = 0;
int isMaster = 1;
int cMaxMemb = MAXMEMB;
char *pcAddress = NULL;
in_addr_t bindAddr;
unsigned short bindPort;
unsigned short bindBasePort;

struct sockaddr_in in_port;
struct in_addr acMyAddr;
char acMyHost[1024];		/* staff.cc.purdue.edu                  */

#if HAVE_OPENSSL
SSL_CTX *ctx = (SSL_CTX *) 0;
int fReqEncryption = 1;
char *pcCredFile = (char *)0;
DH *dh512 = (DH *) 0;
DH *dh1024 = (DH *) 0;
DH *dh2048 = (DH *) 0;
DH *dh4096 = (DH *) 0;


DH *
#if PROTOTYPES
GetDH512(void)
#else
GetDH512()
#endif
{
    static unsigned char dh512_p[] = {
	0xF5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40, 0x18, 0x11, 0x8D,
	0x7C, 0x84, 0xA7, 0x0A, 0x72, 0xD6, 0x86, 0xC4, 0x03, 0x19,
	0xC8, 0x07, 0x29, 0x7A, 0xCA, 0x95, 0x0C, 0xD9, 0x96, 0x9F,
	0xAB, 0xD0, 0x0A, 0x50, 0x9B, 0x02, 0x46, 0xD3, 0x08, 0x3D,
	0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C, 0x7C, 0xBD, 0x89, 0x4B,
	0x22, 0x19, 0x26, 0xBA, 0xAB, 0xA2, 0x5E, 0xC3, 0x55, 0xE9,
	0x2A, 0x05, 0x5F,
    };
    static unsigned char dh512_g[] = {
	0x02,
    };
    DH *dh;

    if ((dh = DH_new()) == NULL)
	return (NULL);
    dh->p = BN_bin2bn(dh512_p, sizeof(dh512_p), NULL);
    dh->g = BN_bin2bn(dh512_g, sizeof(dh512_g), NULL);
    if ((dh->p == NULL) || (dh->g == NULL)) {
	DH_free(dh);
	return (NULL);
    }
    return (dh);
}

DH *
#if PROTOTYPES
GetDH1024(void)
#else
GetDH1024()
#endif
{
    static unsigned char dh1024_p[] = {
	0xF4, 0x88, 0xFD, 0x58, 0x4E, 0x49, 0xDB, 0xCD, 0x20, 0xB4, 0x9D,
	0xE4, 0x91, 0x07, 0x36, 0x6B, 0x33, 0x6C, 0x38, 0x0D, 0x45,
	0x1D, 0x0F, 0x7C, 0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E,
	0xF6, 0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B, 0x18,
	0x8D, 0x8E, 0xBB, 0x55, 0x8C, 0xB8, 0x5D, 0x38, 0xD3, 0x34,
	0xFD, 0x7C, 0x17, 0x57, 0x43, 0xA3, 0x1D, 0x18, 0x6C, 0xDE,
	0x33, 0x21, 0x2C, 0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29,
	0x40, 0x18, 0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72, 0xD6,
	0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29, 0x7A, 0xCA, 0x95,
	0x0C, 0xD9, 0x96, 0x9F, 0xAB, 0xD0, 0x0A, 0x50, 0x9B, 0x02,
	0x46, 0xD3, 0x08, 0x3D, 0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C,
	0x7C, 0xBD, 0x89, 0x4B, 0x22, 0x19, 0x26, 0xBA, 0xAB, 0xA2,
	0x5E, 0xC3, 0x55, 0xE9, 0x2F, 0x78, 0xC7,
    };
    static unsigned char dh1024_g[] = {
	0x02,
    };
    DH *dh;

    if ((dh = DH_new()) == NULL)
	return (NULL);
    dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
    dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);
    if ((dh->p == NULL) || (dh->g == NULL)) {
	DH_free(dh);
	return (NULL);
    }
    return (dh);
}

DH *
#if PROTOTYPES
GetDH2048(void)
#else
GetDH2048()
#endif
{
    static unsigned char dh2048_p[] = {
	0xF6, 0x42, 0x57, 0xB7, 0x08, 0x7F, 0x08, 0x17, 0x72, 0xA2, 0xBA,
	0xD6, 0xA9, 0x42, 0xF3, 0x05, 0xE8, 0xF9, 0x53, 0x11, 0x39,
	0x4F, 0xB6, 0xF1, 0x6E, 0xB9, 0x4B, 0x38, 0x20, 0xDA, 0x01,
	0xA7, 0x56, 0xA3, 0x14, 0xE9, 0x8F, 0x40, 0x55, 0xF3, 0xD0,
	0x07, 0xC6, 0xCB, 0x43, 0xA9, 0x94, 0xAD, 0xF7, 0x4C, 0x64,
	0x86, 0x49, 0xF8, 0x0C, 0x83, 0xBD, 0x65, 0xE9, 0x17, 0xD4,
	0xA1, 0xD3, 0x50, 0xF8, 0xF5, 0x59, 0x5F, 0xDC, 0x76, 0x52,
	0x4F, 0x3D, 0x3D, 0x8D, 0xDB, 0xCE, 0x99, 0xE1, 0x57, 0x92,
	0x59, 0xCD, 0xFD, 0xB8, 0xAE, 0x74, 0x4F, 0xC5, 0xFC, 0x76,
	0xBC, 0x83, 0xC5, 0x47, 0x30, 0x61, 0xCE, 0x7C, 0xC9, 0x66,
	0xFF, 0x15, 0xF9, 0xBB, 0xFD, 0x91, 0x5E, 0xC7, 0x01, 0xAA,
	0xD3, 0x5B, 0x9E, 0x8D, 0xA0, 0xA5, 0x72, 0x3A, 0xD4, 0x1A,
	0xF0, 0xBF, 0x46, 0x00, 0x58, 0x2B, 0xE5, 0xF4, 0x88, 0xFD,
	0x58, 0x4E, 0x49, 0xDB, 0xCD, 0x20, 0xB4, 0x9D, 0xE4, 0x91,
	0x07, 0x36, 0x6B, 0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F,
	0x7C, 0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E, 0xF6, 0xF3,
	0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B, 0x18, 0x8D, 0x8E,
	0xBB, 0x55, 0x8C, 0xB8, 0x5D, 0x38, 0xD3, 0x34, 0xFD, 0x7C,
	0x17, 0x57, 0x43, 0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21,
	0x2C, 0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40, 0x18,
	0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72, 0xD6, 0x86, 0xC4,
	0x03, 0x19, 0xC8, 0x07, 0x29, 0x7A, 0xCA, 0x95, 0x0C, 0xD9,
	0x96, 0x9F, 0xAB, 0xD0, 0x0A, 0x50, 0x9B, 0x02, 0x46, 0xD3,
	0x08, 0x3D, 0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C, 0x7C, 0xBD,
	0x89, 0x4B, 0x22, 0x19, 0x26, 0xBA, 0xAB, 0xA2, 0x5E, 0xC3,
	0x55, 0xE9, 0x32, 0x0B, 0x3B,
    };
    static unsigned char dh2048_g[] = {
	0x02,
    };
    DH *dh;

    if ((dh = DH_new()) == NULL)
	return (NULL);
    dh->p = BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL);
    dh->g = BN_bin2bn(dh2048_g, sizeof(dh2048_g), NULL);
    if ((dh->p == NULL) || (dh->g == NULL)) {
	DH_free(dh);
	return (NULL);
    }
    return (dh);
}

DH *
#if PROTOTYPES
GetDH4096(void)
#else
GetDH4096()
#endif
{
    static unsigned char dh4096_p[] = {
	0xFA, 0x14, 0x72, 0x52, 0xC1, 0x4D, 0xE1, 0x5A, 0x49, 0xD4, 0xEF,
	0x09, 0x2D, 0xC0, 0xA8, 0xFD, 0x55, 0xAB, 0xD7, 0xD9, 0x37,
	0x04, 0x28, 0x09, 0xE2, 0xE9, 0x3E, 0x77, 0xE2, 0xA1, 0x7A,
	0x18, 0xDD, 0x46, 0xA3, 0x43, 0x37, 0x23, 0x90, 0x97, 0xF3,
	0x0E, 0xC9, 0x03, 0x50, 0x7D, 0x65, 0xCF, 0x78, 0x62, 0xA6,
	0x3A, 0x62, 0x22, 0x83, 0xA1, 0x2F, 0xFE, 0x79, 0xBA, 0x35,
	0xFF, 0x59, 0xD8, 0x1D, 0x61, 0xDD, 0x1E, 0x21, 0x13, 0x17,
	0xFE, 0xCD, 0x38, 0x87, 0x9E, 0xF5, 0x4F, 0x79, 0x10, 0x61,
	0x8D, 0xD4, 0x22, 0xF3, 0x5A, 0xED, 0x5D, 0xEA, 0x21, 0xE9,
	0x33, 0x6B, 0x48, 0x12, 0x0A, 0x20, 0x77, 0xD4, 0x25, 0x60,
	0x61, 0xDE, 0xF6, 0xB4, 0x4F, 0x1C, 0x63, 0x40, 0x8B, 0x3A,
	0x21, 0x93, 0x8B, 0x79, 0x53, 0x51, 0x2C, 0xCA, 0xB3, 0x7B,
	0x29, 0x56, 0xA8, 0xC7, 0xF8, 0xF4, 0x7B, 0x08, 0x5E, 0xA6,
	0xDC, 0xA2, 0x45, 0x12, 0x56, 0xDD, 0x41, 0x92, 0xF2, 0xDD,
	0x5B, 0x8F, 0x23, 0xF0, 0xF3, 0xEF, 0xE4, 0x3B, 0x0A, 0x44,
	0xDD, 0xED, 0x96, 0x84, 0xF1, 0xA8, 0x32, 0x46, 0xA3, 0xDB,
	0x4A, 0xBE, 0x3D, 0x45, 0xBA, 0x4E, 0xF8, 0x03, 0xE5, 0xDD,
	0x6B, 0x59, 0x0D, 0x84, 0x1E, 0xCA, 0x16, 0x5A, 0x8C, 0xC8,
	0xDF, 0x7C, 0x54, 0x44, 0xC4, 0x27, 0xA7, 0x3B, 0x2A, 0x97,
	0xCE, 0xA3, 0x7D, 0x26, 0x9C, 0xAD, 0xF4, 0xC2, 0xAC, 0x37,
	0x4B, 0xC3, 0xAD, 0x68, 0x84, 0x7F, 0x99, 0xA6, 0x17, 0xEF,
	0x6B, 0x46, 0x3A, 0x7A, 0x36, 0x7A, 0x11, 0x43, 0x92, 0xAD,
	0xE9, 0x9C, 0xFB, 0x44, 0x6C, 0x3D, 0x82, 0x49, 0xCC, 0x5C,
	0x6A, 0x52, 0x42, 0xF8, 0x42, 0xFB, 0x44, 0xF9, 0x39, 0x73,
	0xFB, 0x60, 0x79, 0x3B, 0xC2, 0x9E, 0x0B, 0xDC, 0xD4, 0xA6,
	0x67, 0xF7, 0x66, 0x3F, 0xFC, 0x42, 0x3B, 0x1B, 0xDB, 0x4F,
	0x66, 0xDC, 0xA5, 0x8F, 0x66, 0xF9, 0xEA, 0xC1, 0xED, 0x31,
	0xFB, 0x48, 0xA1, 0x82, 0x7D, 0xF8, 0xE0, 0xCC, 0xB1, 0xC7,
	0x03, 0xE4, 0xF8, 0xB3, 0xFE, 0xB7, 0xA3, 0x13, 0x73, 0xA6,
	0x7B, 0xC1, 0x0E, 0x39, 0xC7, 0x94, 0x48, 0x26, 0x00, 0x85,
	0x79, 0xFC, 0x6F, 0x7A, 0xAF, 0xC5, 0x52, 0x35, 0x75, 0xD7,
	0x75, 0xA4, 0x40, 0xFA, 0x14, 0x74, 0x61, 0x16, 0xF2, 0xEB,
	0x67, 0x11, 0x6F, 0x04, 0x43, 0x3D, 0x11, 0x14, 0x4C, 0xA7,
	0x94, 0x2A, 0x39, 0xA1, 0xC9, 0x90, 0xCF, 0x83, 0xC6, 0xFF,
	0x02, 0x8F, 0xA3, 0x2A, 0xAC, 0x26, 0xDF, 0x0B, 0x8B, 0xBE,
	0x64, 0x4A, 0xF1, 0xA1, 0xDC, 0xEE, 0xBA, 0xC8, 0x03, 0x82,
	0xF6, 0x62, 0x2C, 0x5D, 0xB6, 0xBB, 0x13, 0x19, 0x6E, 0x86,
	0xC5, 0x5B, 0x2B, 0x5E, 0x3A, 0xF3, 0xB3, 0x28, 0x6B, 0x70,
	0x71, 0x3A, 0x8E, 0xFF, 0x5C, 0x15, 0xE6, 0x02, 0xA4, 0xCE,
	0xED, 0x59, 0x56, 0xCC, 0x15, 0x51, 0x07, 0x79, 0x1A, 0x0F,
	0x25, 0x26, 0x27, 0x30, 0xA9, 0x15, 0xB2, 0xC8, 0xD4, 0x5C,
	0xCC, 0x30, 0xE8, 0x1B, 0xD8, 0xD5, 0x0F, 0x19, 0xA8, 0x80,
	0xA4, 0xC7, 0x01, 0xAA, 0x8B, 0xBA, 0x53, 0xBB, 0x47, 0xC2,
	0x1F, 0x6B, 0x54, 0xB0, 0x17, 0x60, 0xED, 0x79, 0x21, 0x95,
	0xB6, 0x05, 0x84, 0x37, 0xC8, 0x03, 0xA4, 0xDD, 0xD1, 0x06,
	0x69, 0x8F, 0x4C, 0x39, 0xE0, 0xC8, 0x5D, 0x83, 0x1D, 0xBE,
	0x6A, 0x9A, 0x99, 0xF3, 0x9F, 0x0B, 0x45, 0x29, 0xD4, 0xCB,
	0x29, 0x66, 0xEE, 0x1E, 0x7E, 0x3D, 0xD7, 0x13, 0x4E, 0xDB,
	0x90, 0x90, 0x58, 0xCB, 0x5E, 0x9B, 0xCD, 0x2E, 0x2B, 0x0F,
	0xA9, 0x4E, 0x78, 0xAC, 0x05, 0x11, 0x7F, 0xE3, 0x9E, 0x27,
	0xD4, 0x99, 0xE1, 0xB9, 0xBD, 0x78, 0xE1, 0x84, 0x41, 0xA0,
	0xDF,
    };
    static unsigned char dh4096_g[] = {
	0x02,
    };
    DH *dh;

    if ((dh = DH_new()) == NULL)
	return (NULL);
    dh->p = BN_bin2bn(dh4096_p, sizeof(dh4096_p), NULL);
    dh->g = BN_bin2bn(dh4096_g, sizeof(dh4096_g), NULL);
    if ((dh->p == NULL) || (dh->g == NULL)) {
	DH_free(dh);
	return (NULL);
    }
    return (dh);
}

DH *
#if PROTOTYPES
TmpDHCallback(SSL * ssl, int is_export, int keylength)
#else
TmpDHCallback(ssl, is_export, keylength)
    SSL *ssl;
    int is_export;
    int keylength;
#endif
{
    Debug(1, "TmpDHCallback(): asked for a DH key length %u", keylength);
    switch (keylength) {
	case 512:
	    if (dh512 == (DH *) 0)
		dh512 = GetDH512();
	    return dh512;
	case 1024:
	    if (dh1024 == (DH *) 0)
		dh1024 = GetDH1024();
	    return dh1024;
	case 2048:
	    if (dh2048 == (DH *) 0)
		dh2048 = GetDH2048();
	    return dh2048;
	default:
	    if (dh4096 == (DH *) 0)
		dh4096 = GetDH4096();
	    return dh4096;
    }
}

void
#if PROTOTYPES
SetupSSL(void)
#else
SetupSSL()
#endif
{
    if (ctx == (SSL_CTX *) 0) {
	SSL_load_error_strings();
	if (!SSL_library_init()) {
	    Error("SetupSSL(): SSL_library_init() failed");
	    exit(EX_UNAVAILABLE);
	}
	if ((ctx = SSL_CTX_new(SSLv23_method())) == (SSL_CTX *) 0) {
	    Error("SetupSSL(): SSL_CTX_new() failed");
	    exit(EX_UNAVAILABLE);
	}
	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
	    Error
		("SetupSSL(): could not load SSL default CA file and/or directory");
	    exit(EX_UNAVAILABLE);
	}
	if (pcCredFile != (char *)0) {
	    if (SSL_CTX_use_certificate_chain_file(ctx, pcCredFile) != 1) {
		Error
		    ("SetupSSL(): could not load SSL certificate from `%s'",
		     pcCredFile);
		exit(EX_UNAVAILABLE);
	    }
	    if (SSL_CTX_use_PrivateKey_file
		(ctx, pcCredFile, SSL_FILETYPE_PEM) != 1) {
		Error("SetupSSL(): could not SSL private key from `%s'",
		      pcCredFile);
		exit(EX_UNAVAILABLE);
	    }
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, SSLVerifyCallback);
	SSL_CTX_set_options(ctx,
			    SSL_OP_ALL | SSL_OP_NO_SSLv2 |
			    SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_mode(ctx,
			 SSL_MODE_ENABLE_PARTIAL_WRITE |
			 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
			 SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_tmp_dh_callback(ctx, TmpDHCallback);
	if (SSL_CTX_set_cipher_list(ctx, "ALL:!LOW:!EXP:!MD5:@STRENGTH") !=
	    1) {
	    Error("SetupSSL(): setting SSL cipher list failed");
	    exit(EX_UNAVAILABLE);
	}
	/* might want to turn this back on at some point, but i can't
	 * see why right now.
	 */
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    }
}
#endif

void
#if PROTOTYPES
ReopenLogfile(void)
#else
ReopenLogfile()
#endif
{
    /* redirect stdout and stderr to the logfile.
     *
     * first time through any problems will show up (stderr still there).
     * after that, all bets are off...probably not see the errors (well,
     * aside from the tail of the old logfile, if it was rolled).
     */
    if (!fUseLogfile)
	return;

    close(1);
    if (1 != open(pcLogfile, O_WRONLY | O_CREAT | O_APPEND, 0644)) {
	Error("ReopenLogfile(): open(%s): %s", pcLogfile, strerror(errno));
	exit(EX_TEMPFAIL);
    }
    close(2);
    dup(1);
}

/* become a daemon							(ksb)
 */
static void
#if PROTOTYPES
Daemonize()
#else
Daemonize()
#endif
{
    int res;
#if !HAVE_SETSID
    int td;
#endif

    SimpleSignal(SIGQUIT, SIG_IGN);
    SimpleSignal(SIGINT, SIG_IGN);
#if defined(SIGTTOU)
    SimpleSignal(SIGTTOU, SIG_IGN);
#endif
#if defined(SIGTTIN)
    SimpleSignal(SIGTTIN, SIG_IGN);
#endif
#if defined(SIGTSTP)
    SimpleSignal(SIGTSTP, SIG_IGN);
#endif

    fflush(stdout);
    fflush(stderr);

    switch (res = fork()) {
	case -1:
	    Error("Daemonize(): fork(): %s", strerror(errno));
	    exit(EX_UNAVAILABLE);
	case 0:
	    thepid = getpid();
	    break;
	default:
	    Bye(EX_OK);
    }

    ReopenLogfile();

    /* Further disassociate this process from the terminal
     * Maybe this will allow you to start a daemon from rsh,
     * i.e. with no controlling terminal.
     */
#if HAVE_SETSID
    setsid();
#else
    setpgrp(0, getpid());

    /* lose our controlling terminal
     */
    if (-1 != (td = open("/dev/tty", O_RDWR, 0600))) {
	ioctl(td, TIOCNOTTY, (char *)0);
	close(td);
    }
#endif
}


/* output a long message to the user					(ksb)
 */
static void
#if PROTOTYPES
Usage(int wantfull)
#else
Usage(wantfull)
    int wantfull;
#endif
{
    static char u_terse[] =
	"[-7dDEFhinRouvV] [-a type] [-m max] [-M addr] [-p port] [-b port] [-c cred] [-C config] [-P passwd] [-L logfile] [-O min]";
    static char *full[] = {
	"7          strip the high bit of all console data",
	"a type     set the default access type",
	"b port     base port for secondary channel (any by default)",
#if HAVE_OPENSSL
	"c cred     load an SSL certificate and key from the PEM encoded file",
#else
	"c cred     ignored - encryption not compiled into code",
#endif
	"C config   give a new config file to the server process",
	"d          become a daemon, redirecting stdout/stderr to logfile",
	"D          enable debug output, sent to stderr",
#if HAVE_OPENSSL
	"E          don't require encrypted client connections",
#else
	"E          ignored - encryption not compiled into code",
#endif
	"F          do not automatically reinitialize failed consoles",
	"h          output this message",
	"i          initialize console connections on demand",
	"L logfile  give a new logfile path to the server process",
	"m max      maximum consoles managed per process",
	"M addr     address to listen on (all addresses by default)",
	"n          obsolete - see -u",
	"o          reopen downed console on client connect",
	"O min      reopen all downed consoles every <min> minutes",
	"p port     port to listen on",
	"P passwd   give a new passwd file to the server process",
	"R          disable automatic client redirection",
	"u          copy \"unloved\" console data to stdout",
	"v          be verbose on startup",
	"V          output version info",
	(char *)0
    };
    fprintf(stderr, "%s: usage %s\n", progname, u_terse);
    if (wantfull) {
	int i;
	for (i = 0; full[i] != (char *)0; i++)
	    fprintf(stderr, "\t%s\n", full[i]);
    }
}

/* show the user our version info					(ksb)
 */
static void
#if PROTOTYPES
Version()
#else
Version()
#endif
{
    static STRING *acA1 = (STRING *) 0;
    static STRING *acA2 = (STRING *) 0;
    int i;
    char *optionlist[] = {
#if HAVE_DMALLOC
	"dmalloc",
#endif
#if USE_LIBWRAP
	"libwrap",
#endif
#if HAVE_OPENSSL
	"openssl",
#endif
#if HAVE_PAM
	"pam",
#endif
#if HAVE_POSIX_REGCOMP
	"regex",
#endif
	(char *)0
    };

    if (acA1 == (STRING *) 0)
	acA1 = AllocString();
    if (acA2 == (STRING *) 0)
	acA2 = AllocString();

    isMultiProc = 0;

    Msg("%s", THIS_VERSION);
    Msg("default access type `%c'", chDefAcc);
    Msg("default escape sequence `%s%s'", FmtCtl(DEFATTN, acA1),
	FmtCtl(DEFESC, acA2));
    Msg("configuration in `%s'", pcConfig);
    Msg("password in `%s'", pcPasswd);
    Msg("logfile is `%s'", pcLogfile);
    Msg("pidfile is `%s'", PIDFILE);
    Msg("limited to %d member%s per group", cMaxMemb,
	cMaxMemb == 1 ? "" : "s");

    /* Look for non-numeric characters */
    for (i = 0; pcPort[i] != '\000'; i++)
	if (!isdigit((int)pcPort[i]))
	    break;

    if (pcPort[i] == '\000') {
	/* numeric only */
	bindPort = atoi(pcPort);
	Msg("on port %hu (referenced as `%s')", bindPort, pcPort);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 == (pSE = getservbyname(pcPort, "tcp"))) {
	    Error("Version(): getservbyname(%s): %s", pcPort,
		  strerror(errno));
	} else {
	    bindPort = ntohs((unsigned short)pSE->s_port);
	    Msg("on port %hu (referenced as `%s')", bindPort, pcPort);
	}
    }

    /* Look for non-numeric characters */
    for (i = 0; pcBasePort[i] != '\000'; i++)
	if (!isdigit((int)pcBasePort[i]))
	    break;

    if (pcBasePort[i] == '\000') {
	/* numeric only */
	bindBasePort = atoi(pcBasePort);
	Msg("secondary channel base port %hu (referenced as `%s')",
	    bindBasePort, pcBasePort);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 ==
	    (pSE = getservbyname(pcBasePort, "tcp"))) {
	    Error("Version(): getservbyname(%s): %s", pcBasePort,
		  strerror(errno));
	} else {
	    bindBasePort = ntohs((unsigned short)pSE->s_port);
	    Msg("secondary channel base port %hu (referenced as `%s')",
		bindBasePort, pcBasePort);
	}
    }
    BuildString((char *)0, acA1);
    if (optionlist[0] == (char *)0)
	BuildString("none", acA1);
    for (i = 0; optionlist[i] != (char *)0; i++) {
	if (i == 0)
	    BuildString(optionlist[i], acA1);
	else {
	    BuildString(", ", acA1);
	    BuildString(optionlist[i], acA1);
	}
    }
    Msg("options: %s", acA1->string);
    Msg("built with `%s'", CONFIGINVOCATION);

    if (fVerbose)
	printf(COPYRIGHT);
    Bye(EX_OK);
}

void
#if PROTOTYPES
DestroyDataStructures(void)
#else
DestroyDataStructures()
#endif
{
    GRPENT *pGE;
    REMOTE *pRC;
    ACCESS *pAC;

    while (pGroups != (GRPENT *) 0) {
	pGE = pGroups->pGEnext;
	DestroyGroup(pGroups);
	pGroups = pGE;
    }

    while (pRCList != (REMOTE *) 0) {
	pRC = pRCList->pRCnext;
	DestroyRemoteConsole(pRCList);
	pRCList = pRC;
    }

    while (pACList != (ACCESS *) 0) {
	pAC = pACList->pACnext;
	DestroyAccessList(pACList);
	pACList = pAC;
    }

#if HAVE_OPENSSL
    if (ctx != (SSL_CTX *) 0)
	SSL_CTX_free(ctx);
    if (dh512 != (DH *) 0)
	DH_free(dh512);
    if (dh1024 != (DH *) 0)
	DH_free(dh1024);
    if (dh2048 != (DH *) 0)
	DH_free(dh2048);
    if (dh4096 != (DH *) 0)
	DH_free(dh4096);
#endif

    DestroyBreakList();
    DestroyStrings();
}

void
#if PROTOTYPES
DumpDataStructures(void)
#else
DumpDataStructures()
#endif
{
    GRPENT *pGE;
    CONSENT *pCE;
    REMOTE *pRC;
    char *empty = "<empty>";

    if (!fDebug)
	return;

    for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
	Debug(1,
	      "DumpDataStructures(): group: id=%u pid=%lu, port=%hu, imembers=%d",
	      pGE->id, pGE->port, (unsigned long)pGE->pid, pGE->imembers);

	for (pCE = pGE->pCElist; pCE != (CONSENT *) 0; pCE = pCE->pCEnext) {
	    if (pCE->pccmd.string == (char *)0)
		pCE->pccmd.string = empty;
	    if (pCE->server.string == (char *)0)
		pCE->server.string = empty;
	    if (pCE->dfile.string == (char *)0)
		pCE->dfile.string = empty;
	    if (pCE->lfile.string == (char *)0)
		pCE->lfile.string = empty;
	    if (pCE->networkConsoleHost.string == (char *)0)
		pCE->networkConsoleHost.string = empty;
	    if (pCE->acslave.string == (char *)0)
		pCE->acslave.string = empty;

	    Debug(1,
		  "DumpDataStructures():  server=%s, dfile=%s, lfile=%s",
		  pCE->server.string, pCE->dfile.string,
		  pCE->lfile.string);
	    Debug(1,
		  "DumpDataStructures():  mark=%d, nextMark=%ld, breakType=%d",
		  pCE->mark, pCE->nextMark, pCE->breakType);

	    Debug(1,
		  "DumpDataStructures():  isNetworkConsole=%d, networkConsoleHost=%s",
		  pCE->isNetworkConsole, pCE->networkConsoleHost.string);
	    Debug(1,
		  "DumpDataStructures():  networkConsolePort=%hu, telnetState=%d, autoReup=%d",
		  pCE->networkConsolePort, pCE->telnetState,
		  pCE->autoReUp);

	    Debug(1, "DumpDataStructures():  baud=%s, parity=%c",
		  pCE->pbaud->acrate, pCE->pparity->ckey);

	    Debug(1,
		  "DumpDataStructures():  fvirtual=%d, acslave=%s, pccmd=%s, ipid=%lu",
		  pCE->fvirtual, pCE->acslave.string, pCE->pccmd.string,
		  (unsigned long)pCE->ipid);

	    Debug(1,
		  "DumpDataStructures():  nolog=%d, fdtty=%d, activitylog=%d, breaklog=%d",
		  pCE->nolog, pCE->fdtty, pCE->activitylog, pCE->breaklog);
	    Debug(1, "DumpDataStructures():  fup=%d, fronly=%d", pCE->fup,
		  pCE->fronly);
	    Debug(1, "DumpDataStructures():  ------");
	}
    }
    for (pRC = pRCList; (REMOTE *) 0 != pRC; pRC = pRC->pRCnext) {
	if (pRC->rserver.string == (char *)0)
	    pRC->rserver.string = empty;
	if (pRC->rhost.string == (char *)0)
	    pRC->rhost.string = empty;
	Debug(1, "DumpDataStructures(): remote: rserver=%s, rhost =%s",
	      pRC->rserver.string, pRC->rhost.string);
    }
}

/* find out where/who we are						(ksb)
 * parse optons
 * read in the config file, open the log file
 * spawn the kids to drive the console groups
 * become the master server
 * shutdown with grace
 * exit happy
 */
int
#if PROTOTYPES
main(int argc, char **argv)
#else
main(argc, argv)
    int argc;
    char **argv;
#endif
{
    int i;
    FILE *fpConfig;
    struct hostent *hpMe;
    static char acOpts[] = "7a:b:c:C:dDEFhiL:m:M:noO:p:P:RsuVv";
    extern int optopt;
    extern char *optarg;
    struct passwd *pwd;
    char *origuser = (char *)0;
    char *curuser = (char *)0;
    int curuid;
    GRPENT *pGE;
    CONSENT *pCE;

    isMultiProc = 1;		/* make sure stuff has the pid */

    thepid = getpid();
    if ((char *)0 == (progname = strrchr(argv[0], '/'))) {
	progname = argv[0];
    } else {
	++progname;
    }

    setpwent();

#if HAVE_SETLINEBUF
    setlinebuf(stdout);
    setlinebuf(stderr);
#endif
#if HAVE_SETVBUF
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
    setvbuf(stderr, NULL, _IOLBF, BUFSIZ);
#endif


    gethostname(acMyHost, sizeof(acMyHost));
    if ((struct hostent *)0 == (hpMe = gethostbyname(acMyHost))) {
	Error("gethostbyname(%s): %s", acMyHost, hstrerror(h_errno));
	exit(EX_UNAVAILABLE);
    }
    if (4 != hpMe->h_length || AF_INET != hpMe->h_addrtype) {
	Error("wrong address size (4 != %d) or adress family (%d != %d)",
	      hpMe->h_length, AF_INET, hpMe->h_addrtype);
	exit(EX_UNAVAILABLE);
    }
#if HAVE_MEMCPY
    memcpy(&acMyAddr, hpMe->h_addr, hpMe->h_length);
#else
    bcopy(hpMe->h_addr, &acMyAddr, hpMe->h_length);
#endif

    while (EOF != (i = getopt(argc, argv, acOpts))) {
	switch (i) {
	    case '7':
		fStrip = 1;
		break;
	    case 'a':
		chDefAcc = '\000' == *optarg ? 'r' : *optarg;
		if (isupper((int)(chDefAcc))) {
		    chDefAcc = tolower(chDefAcc);
		}
		switch (chDefAcc) {
		    case 'r':
		    case 'a':
		    case 't':
			break;
		    default:
			Error("unknown access type `%s'", optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
	    case 'b':
		pcBasePort = optarg;
		break;
	    case 'c':
#if HAVE_OPENSSL
		pcCredFile = optarg;
#endif
		break;
	    case 'C':
		pcConfig = optarg;
		break;
	    case 'd':
		fDaemon = 1;
		fUseLogfile = 1;
		break;
	    case 'D':
		fDebug++;
		break;
	    case 'E':
#if HAVE_OPENSSL
		fReqEncryption = 0;
#endif
		break;
	    case 'F':
		fNoautoreup = 1;
		break;
	    case 'h':
		Usage(1);
		Bye(EX_OK);
	    case 'i':
		fNoinit = 1;
		break;
	    case 'L':
		pcLogfile = optarg;
		break;
	    case 'm':
		cMaxMemb = atoi(optarg);
		break;
	    case 'M':
		pcAddress = optarg;
		break;
	    case 'n':
		/* noop now */
		break;
	    case 'o':
		/* try reopening downed consoles on connect */
		fReopen = 1;
		break;
	    case 'O':
		/* How often to try opening all down consoles, in minutes */
		fReopenall = atoi(optarg);
		break;
	    case 'p':
		pcPort = optarg;
		break;
	    case 'P':
		pcPasswd = optarg;
		break;
	    case 'R':
		fNoredir = 1;
		break;
	    case 's':
		fSoftcar ^= 1;
		break;
	    case 'u':
		fAll = 1;
		break;
	    case 'V':
		fVersion = 1;
		break;
	    case 'v':
		fVerbose = 1;
		break;
	    case '\?':
		Usage(0);
		exit(EX_UNAVAILABLE);
	    default:
		Error("option %c needs a parameter", optopt);
		exit(EX_UNAVAILABLE);
	}
    }

    if (cMaxMemb <= 0) {
	Error("ignoring invalid -m option (%d <= 0)", cMaxMemb);
	cMaxMemb = MAXMEMB;
    }

    /* if we read from stdin (by accident) we don't wanna block.
     * we just don't want any more input at this point.
     */
    close(0);
    if (0 != open("/dev/null", O_RDWR, 0644)) {
	Error("open(/dev/null): %s", strerror(errno));
	exit(EX_UNAVAILABLE);
    }

    if (fVersion) {
	Version();
	Bye(EX_OK);
    }

    if (fDaemon) {
	Daemonize();
    }

    Msg("%s", THIS_VERSION);

#if HAVE_GETLOGIN
    origuser = getlogin();
#endif
    curuid = getuid();

    if (defaultShell == (STRING *) 0)
	defaultShell = AllocString();
    if ((pwd = getpwuid(0)) != (struct passwd *)0 &&
	pwd->pw_shell[0] != '\000') {
	BuildString(pwd->pw_shell, defaultShell);
    } else {
	BuildString("/bin/sh", defaultShell);
    }

    if ((struct passwd *)0 != (pwd = getpwuid(curuid)))
	curuser = pwd->pw_name;

    /* chuck any empty username */
    if (curuser != (char *)0 && curuser[0] == '\000')
	curuser = (char *)0;

    if (curuser == (char *)0)
	if (origuser == (char *)0)
	    Msg("started as uid %d by uid %d", curuid, curuid);
	else
	    Msg("started as uid %d by `%s'", curuid, origuser);
    else
	Msg("started as `%s' by `%s'", curuser,
	    (origuser == (char *)0) ? curuser : origuser);
    endpwent();

#if HAVE_GETSPNAM && !HAVE_PAM
    if (0 != geteuid()) {
	Msg("Warning: running as a non-root user - any shadow password usage will most likely fail!");
    }
#endif

    if (pcAddress == NULL) {
	bindAddr = INADDR_ANY;
    } else {
	bindAddr = inet_addr(pcAddress);
	if (bindAddr == (in_addr_t) (-1)) {
	    Error("inet_addr(%s): %s", pcAddress, "invalid IP address");
	    exit(EX_UNAVAILABLE);
	}
	acMyAddr.s_addr = bindAddr;
    }
    if (fDebug) {
	struct in_addr ba;
	ba.s_addr = bindAddr;
	Debug(1, "main(): bind address set to `%s'", inet_ntoa(ba));
    }

    if (pcPort == NULL) {
	Error
	    ("main(): severe error - pcPort is NULL????  how can that be?");
	exit(EX_UNAVAILABLE);
    }

    /* Look for non-numeric characters */
    for (i = 0; pcPort[i] != '\000'; i++)
	if (!isdigit((int)pcPort[i]))
	    break;

    if (pcPort[i] == '\000') {
	/* numeric only */
	bindPort = atoi(pcPort);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 == (pSE = getservbyname(pcPort, "tcp"))) {
	    Error("getservbyname(%s): %s", pcPort, strerror(errno));
	    exit(EX_UNAVAILABLE);
	} else {
	    bindPort = ntohs((unsigned short)pSE->s_port);
	}
    }

    /* Look for non-numeric characters */
    for (i = 0; pcBasePort[i] != '\000'; i++)
	if (!isdigit((int)pcBasePort[i]))
	    break;

    if (pcBasePort[i] == '\000') {
	/* numeric only */
	bindBasePort = atoi(pcBasePort);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 ==
	    (pSE = getservbyname(pcBasePort, "tcp"))) {
	    Error("getservbyname(%s): %s", pcBasePort, strerror(errno));
	    exit(EX_UNAVAILABLE);
	} else {
	    bindBasePort = ntohs((unsigned short)pSE->s_port);
	}
    }

    /* read the config file
     */
    if ((FILE *) 0 == (fpConfig = fopen(pcConfig, "r"))) {
	Error("fopen(%s): %s", pcConfig, strerror(errno));
	exit(EX_UNAVAILABLE);
    }

    ReadCfg(pcConfig, fpConfig);

    if (pGroups == (GRPENT *) 0 && pRCList == (REMOTE *) 0) {
	Error("no consoles found in configuration file");
    } else {
#if HAVE_OPENSSL
	/* Prep the SSL layer */
	SetupSSL();
#endif

	/* if no one can use us we need to come up with a default
	 */
	if (pACList == (ACCESS *) 0) {
	    SetDefAccess(&acMyAddr, acMyHost);
	}

	/* spawn all the children, so fix kids has an initial pid
	 */
	for (pGE = pGroups; pGE != (GRPENT *) 0; pGE = pGE->pGEnext) {
	    if (pGE->imembers == 0)
		continue;

	    Spawn(pGE);

	    Verbose("group #%d pid %lu on port %hu", pGE->id,
		    (unsigned long)pGE->pid, ntohs(pGE->port));
	    for (pCE = pGE->pCElist; pCE != (CONSENT *) 0;
		 pCE = pCE->pCEnext) {
		if (-1 != pCE->fdtty)
		    close(pCE->fdtty);
	    }
	}

	if (fVerbose) {
	    ACCESS *pACtmp;
	    for (pACtmp = pACList; pACtmp != (ACCESS *) 0;
		 pACtmp = pACtmp->pACnext) {
		Verbose("access type `%c' for `%s'", pACtmp->ctrust,
			pACtmp->pcwho);
	    }
	}

	pRCUniq = FindUniq(pRCList);
	/* output unique console server peers?
	 */
	if (fVerbose) {
	    REMOTE *pRC;
	    for (pRC = pRCUniq; (REMOTE *) 0 != pRC; pRC = pRC->pRCuniq) {
		Verbose("peer server on `%s'", pRC->rhost.string);
	    }
	}

	fflush(stdout);
	fflush(stderr);
	Master();

	/* stop putting kids back, and shoot them
	 */
	SimpleSignal(SIGCHLD, SIG_DFL);
	SignalKids(SIGTERM);
    }

    DumpDataStructures();

    Msg("terminated");
    endpwent();
    fclose(fpConfig);
    Bye(EX_OK);
    return EX_OK;		/* never gets here clears the compiler warning */
}
