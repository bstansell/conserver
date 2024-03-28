/*
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

#include <compat.h>

#include <pwd.h>

#include <cutil.h>
#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <master.h>
#include <readcfg.h>
#include <version.h>

#include <dirent.h>
#if HAVE_OPENSSL
# include <openssl/opensslv.h>
#endif
#if HAVE_GSSAPI
# include <gssapi/gssapi.h>
#endif


int fAll = 0, fNoinit = 0, fVersion = 0, fStrip = 0, fReopen =
    0, fNoautoreup = 0, fSyntaxOnly = 0;

char *pcConfig = CONFIGFILE;
int cMaxMemb = MAXMEMB;
#if USE_IPV6
struct addrinfo *bindAddr = (struct addrinfo *)0;
struct addrinfo *bindBaseAddr = (struct addrinfo *)0;
#else
in_addr_t bindAddr = INADDR_ANY;
unsigned short bindPort;
unsigned short bindBasePort;
struct sockaddr_in in_port;
#endif
static STRING *startedMsg = (STRING *)0;
CONFIG *optConf = (CONFIG *)0;
CONFIG *config = (CONFIG *)0;
char *interface = (char *)0;
CONFIG defConfig =
    { (STRING *)0, FLAGTRUE, 'r', FLAGFALSE, LOGFILEPATH, PASSWDFILE,
    DEFPORT,
    FLAGTRUE, FLAGTRUE, 0, DEFBASEPORT, (char *)0, 0
#if HAVE_SETPROCTITLE
	, FLAGFALSE
#endif
#if HAVE_OPENSSL
	, (char *)0, FLAGTRUE, FLAGFALSE, (char *)0
#endif
};

CONSFILE *unifiedlog = (CONSFILE *)0;

#if HAVE_DMALLOC && DMALLOC_MARK_MAIN
unsigned long dmallocMarkMain = 0;
#endif

#if HAVE_OPENSSL
# if OPENSSL_VERSION_NUMBER < 0x10100000L
int
DH_set0_pqg(DH *dh, BIGNUM * p, BIGNUM * q, BIGNUM * g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
	|| (dh->g == NULL && g == NULL))
	return 0;

    if (p != NULL) {
	BN_free(dh->p);
	dh->p = p;
    }
    if (q != NULL) {
	BN_free(dh->q);
	dh->q = q;
    }
    if (g != NULL) {
	BN_free(dh->g);
	dh->g = g;
    }

    if (q != NULL) {
	dh->length = BN_num_bits(q);
    }

    return 1;
}
# endif/* OPENSSL_VERSION_NUMBER < 0x10100000L */

SSL_CTX *ctx = (SSL_CTX *)0;
DH *dh512 = (DH *)0;
DH *dh1024 = (DH *)0;
DH *dh2048 = (DH *)0;
DH *dh4096 = (DH *)0;

DH *
DHFromArray(unsigned char *dh_p, size_t dh_p_size, unsigned char *dh_g,
	    size_t dh_g_size)
{
    DH *dh;
    BIGNUM *p, *g;

    p = BN_bin2bn(dh_p, dh_p_size, NULL);
    if (p == NULL) {
	return (NULL);
    }

    g = BN_bin2bn(dh_g, dh_g_size, NULL);
    if (g == NULL) {
	BN_free(g);
	return (NULL);
    }

    if ((dh = DH_new()) == NULL) {
	BN_free(p);
	BN_free(g);
	return (NULL);
    }

    if (!DH_set0_pqg(dh, p, NULL, g)) {
	BN_free(p);
	BN_free(g);
	DH_free(dh);
	return (NULL);
    }

    return (dh);
}

DH *
GetDH512(void)
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

    return DHFromArray(dh512_p, sizeof(dh512_p), dh512_g, sizeof(dh512_g));
}

DH *
GetDH1024(void)
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

    return DHFromArray(dh1024_p, sizeof(dh1024_p), dh1024_g,
		       sizeof(dh1024_g));
}

DH *
GetDH2048(void)
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

    return DHFromArray(dh2048_p, sizeof(dh2048_p), dh2048_g,
		       sizeof(dh2048_g));
}

DH *
GetDH4096(void)
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

    return DHFromArray(dh4096_p, sizeof(dh4096_p), dh4096_g,
		       sizeof(dh4096_g));
}

DH *
TmpDHCallback(SSL *ssl, int is_export, int keylength)
{
    CONDDEBUG((1, "TmpDHCallback(): asked for a DH key length %u",
	       keylength));
    switch (keylength) {
	case 512:
	    if (dh512 == (DH *)0)
		dh512 = GetDH512();
	    return dh512;
	case 1024:
	    if (dh1024 == (DH *)0)
		dh1024 = GetDH1024();
	    return dh1024;
	case 2048:
	    if (dh2048 == (DH *)0)
		dh2048 = GetDH2048();
	    return dh2048;
	default:
	    if (dh4096 == (DH *)0)
		dh4096 = GetDH4096();
	    return dh4096;
    }
}

void
SetupSSL(void)
{
    if (ctx == (SSL_CTX *)0) {
	char *ciphers;
	int verifymode;
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_load_error_strings();
	if (!SSL_library_init()) {
	    Error("SetupSSL(): SSL_library_init() failed");
	    Bye(EX_SOFTWARE);
	}
# endif/* OPENSSL_VERSION_NUMBER < 0x10100000L */
	if ((ctx = SSL_CTX_new(TLS_method())) == (SSL_CTX *)0) {
	    Error("SetupSSL(): SSL_CTX_new() failed");
	    Bye(EX_SOFTWARE);
	}
	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
	    Error
		("SetupSSL(): could not load SSL default CA file and/or directory");
	    Bye(EX_SOFTWARE);
	}
	if (config->sslcredentials != (char *)0) {
	    if (SSL_CTX_use_certificate_chain_file
		(ctx, config->sslcredentials) != 1) {
		Error
		    ("SetupSSL(): could not load SSL certificate from `%s'",
		     config->sslcredentials);
		Bye(EX_SOFTWARE);
	    }
	    if (SSL_CTX_use_PrivateKey_file
		(ctx, config->sslcredentials, SSL_FILETYPE_PEM) != 1) {
		Error
		    ("SetupSSL(): could not load SSL private key from `%s'",
		     config->sslcredentials);
		Bye(EX_SOFTWARE);
	    }
	    ciphers = "ALL:!LOW:!EXP:!MD5:!aNULL:@STRENGTH";
	} else {
	    ciphers = "ALL:aNULL:!LOW:!EXP:!MD5:@STRENGTH" CIPHER_SEC0;
	}
	if (config->sslcacertificatefile != (char *)0) {
	    STACK_OF(X509_NAME) * cert_names;

	    cert_names =
		SSL_load_client_CA_file(config->sslcacertificatefile);
	    if (cert_names != NULL) {
		SSL_CTX_set_client_CA_list(ctx, cert_names);
		if (SSL_CTX_load_verify_locations
		    (ctx, config->sslcacertificatefile, NULL) != 1) {
		    Error("Could not setup CA certificate file to '%s'",
			  config->sslcacertificatefile);
		    Bye(EX_UNAVAILABLE);
		}
	    } else {
		Error
		    ("SetupSSL(): could not load SSL client CA list from `%s'",
		     config->sslcacertificatefile);
		Bye(EX_SOFTWARE);
	    }
	}

	verifymode = SSL_VERIFY_PEER;
	if (config->sslreqclientcert == FLAGTRUE)
	    verifymode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	SSL_CTX_set_verify(ctx, verifymode, SSLVerifyCallback);
	SSL_CTX_set_options(ctx,
			    SSL_OP_ALL | SSL_OP_NO_SSLv2 |
			    SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_mode(ctx,
			 SSL_MODE_ENABLE_PARTIAL_WRITE |
			 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
			 SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_tmp_dh_callback(ctx, TmpDHCallback);
	if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1) {
	    Error("SetupSSL(): setting SSL cipher list failed");
	    Bye(EX_SOFTWARE);
	}
	/* might want to turn this back on at some point, but i can't
	 * see why right now.
	 */
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    }
}
#endif

#if HAVE_GSSAPI
gss_name_t gss_myname = GSS_C_NO_NAME;
gss_cred_id_t gss_mycreds = GSS_C_NO_CREDENTIAL;

void
SetupGSSAPI(void)
{
    OM_uint32 stmaj, stmin;
    char namestr[128];
    gss_buffer_desc namebuf;

    snprintf(namestr, 128, "host@%s", myHostname);
    namebuf.value = namestr;
    namebuf.length = strlen(namestr) + 1;
    stmaj =
	gss_import_name(&stmin, &namebuf, GSS_C_NT_HOSTBASED_SERVICE,
			&gss_myname);
    /* XXX: handle error */
    if (stmaj != GSS_S_COMPLETE) {
	Error("gss_import_name failed");
    }
    /* Get some initial credentials */
    stmaj =
	gss_acquire_cred(&stmin, gss_myname, 0, GSS_C_NULL_OID_SET,
			 GSS_C_ACCEPT, &gss_mycreds, NULL, NULL);
    if (stmaj != GSS_S_COMPLETE) {
	Error("Could not acquire GSS-API credentials");
    }

}
#endif

void
ReopenLogfile(void)
{
    static int tag = 1;
    /* redirect stdout and stderr to the logfile.
     *
     * first time through any problems will show up (stderr still there).
     * after that, all bets are off...probably not see the errors (well,
     * aside from the tail of the old logfile, if it was rolled).
     */
    if (config->daemonmode != FLAGTRUE)
	return;

    close(1);

    /* so, if we aren't in daemon mode, we just return before closing
     * anything.  if we are, there are two possibilities.  first, if
     * logfile is set, we close fd 1, open a file, etc.  all should be
     * well.  if logfile isn't set, we end up closing fd 1 and 2 and
     * returning (in case the logfile was set and then unset [config
     * file change]).
     */
    if (config->logfile == (char *)0) {
	close(2);
	return;
    }

    if (1 != open(config->logfile, O_WRONLY | O_CREAT | O_APPEND, 0644)) {
	tag = 0;
	Error("ReopenLogfile(): open(%s): %s", config->logfile,
	      strerror(errno));
	Bye(EX_TEMPFAIL);
    }
    close(2);
    dup(1);
    if (isMaster && tag) {
	Msg(MyVersion());
	Msg(startedMsg->string);
    }
    tag = 0;
}

void
ReopenUnifiedlog(void)
{
    /* close any existing */
    if (unifiedlog != (CONSFILE *)0)
	FileClose(&unifiedlog);

    /* return if we aren't opening again */
    if (config->unifiedlog == (char *)0)
	return;

    /* open a new one */
    if ((unifiedlog =
	 FileOpen(config->unifiedlog, O_WRONLY | O_CREAT | O_APPEND,
		  0644)) == (CONSFILE *)0) {
	Error("ReopenUnifiedlog(): open(%s): %s", config->unifiedlog,
	      strerror(errno));
	return;
    }
}

/* become a daemon							(ksb)
 */
static void
Daemonize(void)
{
    int res;
#if !HAVE_SETSID
    int td;
#endif

    Msg("daemonizing");
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
#if defined(SIGXFSZ)
    SimpleSignal(SIGXFSZ, SIG_IGN);
#endif

    fflush(stdout);
    fflush(stderr);

    switch (res = fork()) {
	case -1:
	    Error("Daemonize(): fork(): %s", strerror(errno));
	    Bye(EX_TEMPFAIL);
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
    tcsetpgrp(0, getpid());

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
Usage(int wantfull)
{
    static char u_terse[] =
	"[-7dDEFhinoRSuvV] [-a type] [-m max] [-M master] [-p port] [-b port] [-c cred] [-C config] [-P passwd] [-L logfile] [-O min] [-U logfile]";
    static char *full[] = {
	"7          strip the high bit off all console data",
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
#if USE_UNIX_DOMAIN_SOCKETS
	"M master   directory that holds the Unix domain sockets",
#else
	"M master   address to listen on (all addresses by default)",
#endif
	"n          obsolete - see -u",
	"o          reopen downed console on client connect",
	"O min      reopen all downed consoles every <min> minutes",
#if USE_UNIX_DOMAIN_SOCKETS
	"p port     ignored - Unix domain sockets compiled into code",
#else
	"p port     port to listen on",
#endif
	"P passwd   give a new passwd file to the server process",
	"R          disable automatic client redirection",
	"S          syntax check of configuration file",
	"u          copy \"unloved\" console data to stdout",
	"U logfile  copy all console data to the \"unified\" logfile",
	"v          be verbose on startup",
	"V          output version info",
	(char *)0
    };
    fprintf(stderr, "usage: %s %s\n", progname, u_terse);
    if (wantfull) {
	int i;
	for (i = 0; full[i] != (char *)0; i++)
	    fprintf(stderr, "\t%s\n", full[i]);
    }
}

/* show the user our version info					(ksb)
 */
static void
Version(void)
{
    static STRING *acA1 = (STRING *)0;
    static STRING *acA2 = (STRING *)0;
    int i;
    char *optionlist[] = {
#if HAVE_DMALLOC
	"dmalloc",
#endif
#if HAVE_FREEIPMI
	"freeipmi",
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
#if TRUST_REVERSE_DNS
	"trustrevdns",
#endif
#if USE_UNIX_DOMAIN_SOCKETS
	"uds",
#endif
	(char *)0
    };

    if (acA1 == (STRING *)0)
	acA1 = AllocString();
    if (acA2 == (STRING *)0)
	acA2 = AllocString();

    isMultiProc = 0;

    Msg(MyVersion());
    Msg("default access type `%c'", defConfig.defaultaccess);
    Msg("default escape sequence `%s%s'", FmtCtl(DEFATTN, acA1),
	FmtCtl(DEFESC, acA2));
    Msg("default configuration in `%s'", CONFIGFILE);
    Msg("default password in `%s'", defConfig.passwdfile);
    Msg("default logfile is `%s'", defConfig.logfile);
    Msg("default pidfile is `%s'", PIDFILE);
    Msg("default limit is %d member%s per group", MAXMEMB,
	MAXMEMB == 1 ? "" : "s");
#if USE_UNIX_DOMAIN_SOCKETS
    Msg("default socket directory `%s'", UDSDIR);
#else
    Msg("default primary port referenced as `%s'", defConfig.primaryport);
    Msg("default secondary base port referenced as `%s'",
	defConfig.secondaryport);
#endif

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
#if HAVE_DMALLOC
    BuildString((char *)0, acA1);
    BuildStringChar('0' + DMALLOC_VERSION_MAJOR, acA1);
    BuildStringChar('.', acA1);
    BuildStringChar('0' + DMALLOC_VERSION_MINOR, acA1);
    BuildStringChar('.', acA1);
    BuildStringChar('0' + DMALLOC_VERSION_PATCH, acA1);
# if defined(DMALLOC_VERSION_BETA)
    if (DMALLOC_VERSION_BETA != 0) {
	BuildString("-b", acA1);
	BuildStringChar('0' + DMALLOC_VERSION_BETA, acA1);
    }
# endif
    Msg("dmalloc version: %s", acA1->string);
#endif
#if HAVE_FREEIPMI
    BuildString((char *)0, acA1);
    BuildStringChar('0' + LIBIPMICONSOLE_VERSION_MAJOR, acA1);
    BuildStringChar('.', acA1);
    BuildStringChar('0' + LIBIPMICONSOLE_VERSION_MINOR, acA1);
    BuildStringChar('.', acA1);
    BuildStringChar('0' + LIBIPMICONSOLE_VERSION_PATCH, acA1);
    Msg("freeipmi version: %s", acA1->string);
#endif
#if HAVE_OPENSSL
    Msg("openssl version: %s", OPENSSL_VERSION_TEXT);
#endif
    Msg("built with `%s'", CONFIGINVOCATION);

    if (fVerbose)
	printf(COPYRIGHT);
    Bye(EX_OK);
}

void
DestroyDataStructures(void)
{
    GRPENT *pGE;
    REMOTE *pRC;
    ACCESS *pAC;

    while (pGroups != (GRPENT *)0) {
	pGE = pGroups->pGEnext;
	DestroyGroup(pGroups);
	pGroups = pGE;
    }

    while (pRCList != (REMOTE *)0) {
	pRC = pRCList->pRCnext;
	DestroyRemoteConsole(pRCList);
	pRCList = pRC;
    }

    while (pACList != (ACCESS *)0) {
	pAC = pACList->pACnext;
	DestroyAccessList(pACList);
	pACList = pAC;
    }
    DestroyConsentUsers(&pADList);
    DestroyConsentUsers(&pLUList);

    DestroyConfig(pConfig);
    DestroyConfig(optConf);
    DestroyConfig(config);

#if HAVE_OPENSSL
    if (ctx != (SSL_CTX *)0)
	SSL_CTX_free(ctx);
    if (dh512 != (DH *)0)
	DH_free(dh512);
    if (dh1024 != (DH *)0)
	DH_free(dh1024);
    if (dh2048 != (DH *)0)
	DH_free(dh2048);
    if (dh4096 != (DH *)0)
	DH_free(dh4096);
#endif

#if USE_IPV6
    /* clean up addrinfo stucts */
    if ((struct addrinfo *)0 != bindAddr)
	freeaddrinfo(bindAddr);
    if ((struct addrinfo *)0 != bindBaseAddr)
	freeaddrinfo(bindBaseAddr);
#else
    if (myAddrs != (struct in_addr *)0)
	free(myAddrs);
#endif

    DestroyBreakList();
    DestroyTaskList();
    DestroyStrings();
    DestroyUserList();
    if (substData != (SUBST *)0)
	free(substData);
}

void
SummarizeDataStructures(void)
{
    GRPENT *pGE;
    REMOTE *pRC;
    ACCESS *pAC;
    STRING *str;
    CONSENT *pCE;
    NAMES *usr;
    int count;
    long size;
    long total = 0;
    extern STRING *allStrings;

    if (!fDebug)
	return;

    for (size = 0, count = 0, pGE = pGroups; pGE != (GRPENT *)0;
	 pGE = pGE->pGEnext, count++) {
	size += sizeof(GRPENT);
    }
    CONDDEBUG((1, "Memory Usage (GRPENT objects): %ld (%d)", size, count));
    total += size;

    for (size = 0, count = 0, pGE = pGroups; pGE != (GRPENT *)0;
	 pGE = pGE->pGEnext) {
	for (pCE = pGE->pCElist; pCE != (CONSENT *)0;
	     pCE = pCE->pCEnext, count++) {
	    size += strlen(pCE->server) + sizeof(CONSENT);
	    if (pCE->host != (char *)0)
		size += strlen(pCE->server);
	    if (pCE->device != (char *)0)
		size += strlen(pCE->device);
	    if (pCE->exec != (char *)0)
		size += strlen(pCE->exec);
	    if (pCE->master != (char *)0)
		size += strlen(pCE->master);
	    if (pCE->logfile != (char *)0)
		size += strlen(pCE->logfile);
	    if (pCE->initcmd != (char *)0)
		size += strlen(pCE->initcmd);
	    if (pCE->execSlave != (char *)0)
		size += strlen(pCE->execSlave);
	    if (pCE->motd != (char *)0)
		size += strlen(pCE->motd);
	    if (pCE->idlestring != (char *)0)
		size += strlen(pCE->idlestring);
	    if (pCE->replstring != (char *)0)
		size += strlen(pCE->replstring);
	    if (pCE->tasklist != (char *)0)
		size += strlen(pCE->tasklist);
	    if (pCE->breaklist != (char *)0)
		size += strlen(pCE->breaklist);
#if HAVE_FREEIPMI
	    if (pCE->username != (char *)0)
		size += strlen(pCE->username);
	    if (pCE->password != (char *)0)
		size += strlen(pCE->password);
#endif
	    if (pCE->fdlog != (CONSFILE *)0)
		size += sizeof(CONSFILE);
	    if (pCE->cofile != (CONSFILE *)0)
		size += sizeof(CONSFILE);
	    if (pCE->initfile != (CONSFILE *)0)
		size += sizeof(CONSFILE);
	    if (pCE->taskfile != (CONSFILE *)0)
		size += sizeof(CONSFILE);
	    if (pCE->aliases != (NAMES *)0) {
		NAMES *n;
		for (n = pCE->aliases; n != (NAMES *)0; n = n->next) {
		    size += sizeof(NAMES) + strlen(n->name);
		}
	    }
	    if (pCE->ro) {
		CONSENTUSERS *u;
		for (u = pCE->ro; u != (CONSENTUSERS *)0; u = u->next) {
		    size += sizeof(CONSENTUSERS) + strlen(u->user->name);
		}
	    }
	    if (pCE->rw) {
		CONSENTUSERS *u;
		for (u = pCE->rw; u != (CONSENTUSERS *)0; u = u->next) {
		    size += sizeof(CONSENTUSERS) + strlen(u->user->name);
		}
	    }
	}
    }
    CONDDEBUG((1, "Memory Usage (CONSENT objects): %ld (%d)", size,
	       count));
    total += size;

    for (size = 0, count = 0, pRC = pRCList; pRC != (REMOTE *)0;
	 pRC = pRC->pRCnext, count++) {
	size += strlen(pRC->rserver) + strlen(pRC->rhost) + sizeof(REMOTE);
	if (pRC->aliases != (NAMES *)0) {
	    NAMES *n;
	    for (n = pRC->aliases; n != (NAMES *)0; n = n->next) {
		size += sizeof(NAMES) + strlen(n->name);
	    }
	}
    }
    CONDDEBUG((1, "Memory Usage (REMOTE objects): %ld (%d)", size, count));
    total += size;

    for (size = 0, count = 0, pAC = pACList; pAC != (ACCESS *)0;
	 pAC = pAC->pACnext, count++) {
	size += strlen(pAC->pcwho) + sizeof(ACCESS);
    }
    CONDDEBUG((1, "Memory Usage (ACCESS objects): %ld (%d)", size, count));
    total += size;

    for (size = 0, count = 0, str = allStrings; str != (STRING *)0;
	 str = str->next, count++) {
	size += str->allocated + sizeof(STRING);
    }
    CONDDEBUG((1, "Memory Usage (STRING objects): %ld (%d)", size, count));
    total += size;

    for (size = 0, count = 0, usr = userList; usr != (NAMES *)0;
	 usr = usr->next, count++) {
	size += strlen(usr->name) + sizeof(NAMES);
    }
    CONDDEBUG((1, "Memory Usage (userList objects): %ld (%d)", size,
	       count));
    total += size;

    CONDDEBUG((1, "Memory Usage (total): %ld", total));
}

void
DumpDataStructures(void)
{
    GRPENT *pGE;
    CONSENT *pCE;
    REMOTE *pRC;
    int i;
    TASKS *t;
#if HAVE_FREEIPMI
    static STRING *tmpString = (STRING *)0;
    if (tmpString == (STRING *)0)
	tmpString = AllocString();
#endif

#if HAVE_DMALLOC && DMALLOC_MARK_MAIN
    CONDDEBUG((1, "DumpDataStructures(): dmalloc / MarkMain"));
    dmalloc_log_changed(dmallocMarkMain, 1, 0, 1);
#endif
#define EMPTYSTR(x) x == (char *)0 ? "(null)" : x
#define FLAGSTR(x) x == FLAGTRUE ? "true" : (x == FLAGFALSE ? "false" : "unset")
    if (!fDebug)
	return;

    SummarizeDataStructures();

    for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
	CONDDEBUG((1,
		   "DumpDataStructures(): group: id=%u port=%hu, pid=%lu, imembers=%d",
		   pGE->id, pGE->port, (unsigned long)pGE->pid,
		   pGE->imembers));

	for (pCE = pGE->pCElist; pCE != (CONSENT *)0; pCE = pCE->pCEnext) {
	    switch (pCE->type) {
		case DEVICE:
		    CONDDEBUG((1,
			       "DumpDataStructures():  server=%s, type=DEVICE",
			       EMPTYSTR(pCE->server)));
		    CONDDEBUG((1,
			       "DumpDataStructures():  baud=%s, parity=%s, device=%s",
			       pCE->baud->acrate, pCE->parity->key,
			       EMPTYSTR(pCE->device)));
		    break;
		case EXEC:
		    CONDDEBUG((1,
			       "DumpDataStructures():  server=%s, type=EXEC",
			       EMPTYSTR(pCE->server)));
		    CONDDEBUG((1,
			       "DumpDataStructures():  execSlave=%s, exec=%s, ipid=%lu",
			       EMPTYSTR(pCE->execSlave),
			       EMPTYSTR(pCE->exec),
			       (unsigned long)pCE->ipid));
		    CONDDEBUG((1,
			       "DumpDataStructures():  execuid=%d, execgid=%d",
			       pCE->execuid, pCE->execgid));

		    break;
#if HAVE_FREEIPMI
		case IPMI:
		    CONDDEBUG((1,
			       "DumpDataStructures():  server=%s, type=IPMI",
			       EMPTYSTR(pCE->server)));
		    CONDDEBUG((1,
			       "DumpDataStructures():  host=%s, username=%s, password=%s, ipmiprivlevel=%d",
			       EMPTYSTR(pCE->host),
			       EMPTYSTR(pCE->username),
			       EMPTYSTR(pCE->password),
			       pCE->ipmiprivlevel));
		    CONDDEBUG((1,
			       "DumpDataStructures():  ipmiwrkset=%d, ipmiworkaround=%u, ipmiciphersuite=%d",
			       pCE->ipmiwrkset, pCE->ipmiworkaround,
			       pCE->ipmiciphersuite));
		    FmtCtlStr(pCE->ipmikg->string, pCE->ipmikg->used - 1,
			      tmpString);
		    CONDDEBUG((1, "DumpDataStructures():  ipmikg=%s",
			       EMPTYSTR(tmpString->string)));
		    break;
#endif
		case HOST:
		    CONDDEBUG((1,
			       "DumpDataStructures():  server=%s, type=HOST",
			       EMPTYSTR(pCE->server)));
		    CONDDEBUG((1,
			       "DumpDataStructures():  host=%s, raw=%s, netport=%hu, port=%hu, telnetState=%d",
			       EMPTYSTR(pCE->host), FLAGSTR(pCE->raw),
			       pCE->netport, pCE->port, pCE->telnetState));
		    break;
		case NOOP:
		    CONDDEBUG((1,
			       "DumpDataStructures():  server=%s, type=NOOP",
			       EMPTYSTR(pCE->server)));
		    break;
		case UDS:
		    CONDDEBUG((1,
			       "DumpDataStructures():  server=%s, type=UDS",
			       EMPTYSTR(pCE->server)));
		    CONDDEBUG((1, "DumpDataStructures():  uds=%s",
			       EMPTYSTR(pCE->uds)));
		    break;
		case UNKNOWNTYPE:
		    CONDDEBUG((1,
			       "DumpDataStructures():  server=%s, type=UNKNOWNTYPE",
			       EMPTYSTR(pCE->server)));
		    break;
	    }
	    if (pCE->aliases != (NAMES *)0) {
		NAMES *n;
		for (n = pCE->aliases; n != (NAMES *)0; n = n->next) {
		    CONDDEBUG((1, "DumpDataStructures():  alias=%s",
			       n->name));
		}
	    }
	    CONDDEBUG((1,
		       "DumpDataStructures():  fup=%d, fronly=%d, logfile=%s, breakNum=%d",
		       pCE->fup, pCE->fronly, EMPTYSTR(pCE->logfile),
		       pCE->breakNum));
	    CONDDEBUG((1,
		       "DumpDataStructures():  mark=%d, nextMark=%ld, autoReup=%hu, downHard=%s",
		       pCE->mark, pCE->nextMark, pCE->autoReUp,
		       FLAGSTR(pCE->downHard)));
	    CONDDEBUG((1,
		       "DumpDataStructures():  nolog=%d, cofile=%d, activitylog=%s, breaklog=%s",
		       pCE->nolog, FileFDNum(pCE->cofile),
		       FLAGSTR(pCE->activitylog), FLAGSTR(pCE->breaklog)));
	    CONDDEBUG((1,
		       "DumpDataStructures():  tasklog=%s, ixon=%s, ixany=%s, ixoff=%s",
		       FLAGSTR(pCE->tasklog), FLAGSTR(pCE->ixon),
		       FLAGSTR(pCE->ixany), FLAGSTR(pCE->ixoff)));
	    CONDDEBUG((1,
		       "DumpDataStructures():  autoreinit=%s, hupcl=%s, cstopb=%s, ondemand=%s",
		       FLAGSTR(pCE->autoreinit), FLAGSTR(pCE->hupcl),
		       FLAGSTR(pCE->cstopb), FLAGSTR(pCE->ondemand)));
#if defined(CRTSCTS)
	    CONDDEBUG((1, "DumpDataStructures():  crtscts=%s",
		       FLAGSTR(pCE->crtscts)));
#endif
	    CONDDEBUG((1,
		       "DumpDataStructures():  reinitoncc=%s, striphigh=%s",
		       FLAGSTR(pCE->reinitoncc), FLAGSTR(pCE->striphigh)));
	    CONDDEBUG((1, "DumpDataStructures():  unloved=%s, login=%s",
		       FLAGSTR(pCE->unloved), FLAGSTR(pCE->login)));
	    CONDDEBUG((1,
		       "DumpDataStructures():  initpid=%lu, initcmd=%s, initfile=%d",
		       (unsigned long)pCE->initpid, EMPTYSTR(pCE->initcmd),
		       FileFDNum(pCE->initfile)));
	    CONDDEBUG((1, "DumpDataStructures():  inituid=%d, initgid=%d",
		       pCE->inituid, pCE->initgid));
	    CONDDEBUG((1,
		       "DumpDataStructures():  motd=%s, idletimeout=%d, idlestring=%s, replstring=%s",
		       EMPTYSTR(pCE->motd), pCE->idletimeout,
		       EMPTYSTR(pCE->idlestring),
		       EMPTYSTR(pCE->replstring)));
	    CONDDEBUG((1,
		       "DumpDataStructures():  tasklist=%s, breaklist=%s, taskpid=%lu, taskfile=%d",
		       EMPTYSTR(pCE->tasklist), EMPTYSTR(pCE->breaklist),
		       (unsigned long)pCE->taskpid,
		       FileFDNum(pCE->taskfile)));
	    if (pCE->ro) {
		CONSENTUSERS *u;
		for (u = pCE->ro; u != (CONSENTUSERS *)0; u = u->next) {
		    CONDDEBUG((1, "DumpDataStructures():  ro=%s%s",
			       (u->not ? "!" : ""), u->user->name));
		}
	    }
	    if (pCE->rw) {
		CONSENTUSERS *u;
		for (u = pCE->rw; u != (CONSENTUSERS *)0; u = u->next) {
		    CONDDEBUG((1, "DumpDataStructures():  rw=%s%s",
			       (u->not ? "!" : ""), u->user->name));
		}
	    }
	    CONDDEBUG((1, "DumpDataStructures():  ------"));
	}
    }
    for (pRC = pRCList; (REMOTE *)0 != pRC; pRC = pRC->pRCnext) {
	CONDDEBUG((1, "DumpDataStructures(): remote: rserver=%s, rhost=%s",
		   EMPTYSTR(pRC->rserver), EMPTYSTR(pRC->rhost)));
	if (pRC->aliases != (NAMES *)0) {
	    NAMES *n;
	    for (n = pRC->aliases; n != (NAMES *)0; n = n->next) {
		CONDDEBUG((1, "DumpDataStructures():  alias=%s", n->name));
	    }
	}
    }
    for (i = 0; i < BREAKLISTSIZE; i++) {
	CONDDEBUG((1,
		   "DumpDataStructures(): break: #%c, string=%s, delay=%d, confirm=%s",
		   '1' + i + (i > 8 ? BREAKALPHAOFFSET : 0),
		   EMPTYSTR(breakList[i].seq->string), breakList[i].delay,
		   FLAGSTR(breakList[i].confirm)));
    }
    for (t = taskList; t != (TASKS *)0; t = t->next) {
	CONDDEBUG((1,
		   "DumpDataStructures(): task: id=%c, cmd=%s, descr=%s, uid=%d, gid=%d, subst=%s, confirm=%s",
		   t->id, EMPTYSTR(t->cmd->string),
		   EMPTYSTR(t->descr->string), t->uid, t->gid,
		   EMPTYSTR(t->subst), FLAGSTR(t->confirm)));
    }
}

/* This makes sure a directory exists and tries to create it if it
 * doesn't.  returns 0 for success, -1 for error
 */
#if USE_UNIX_DOMAIN_SOCKETS
int
VerifyEmptyDirectory(char *d)
{
    struct stat dstat;
    DIR *dir;
    struct dirent *de;
# if 0				/* See below */
    STRING *path = (STRING *)0;
# endif
    int retval = 0;

    while (1) {
	if (stat(d, &dstat) == -1) {
	    if (errno == ENOENT) {
		if (mkdir(d, 0755) == -1) {
		    Error("mkdir(%s): %s", d, strerror(errno));
		    return -1;
		}
		CONDDEBUG((1, "VerifyEmptyDirectory: created `%s'", d));
		continue;
	    } else {
		Error("stat(%s): %s", d, strerror(errno));
		return -1;
	    }
	}
	if (S_ISDIR(dstat.st_mode))
	    break;
	return -1;
    }

    /* now make sure it's empty...erase anything you see, etc */
    if ((dir = opendir(d)) == (DIR *) 0) {
	Error("opendir(%s): %s", d, strerror(errno));
	return -1;
    }

    while ((de = readdir(dir)) != (struct dirent *)0) {
	if ((strcmp(de->d_name, ".") == 0) ||
	    (strcmp(de->d_name, "..") == 0))
	    continue;
/* we're going to just let the user deal with non-empty directories */
	Error("non-empty directory `%s'", d);
	retval = -1;
	break;
/* this is probably too extreme.  if someone happens to point conserver
 * at /etc, for example, it could (if running as root) nuke the password
 * database, config files, etc.  too many important files could be
 * shredded with a small typo.
 */
# if 0
	if (path == (STRING *)0)
	    path = AllocString();
	BuildStringPrint(path, "%s/%s", d, de->d_name);
	if (stat(path->string, &dstat) == -1) {
	    Error("stat(%s): %s", path->string, strerror(errno));
	    retval = -1;
	    break;
	}
	if (S_ISDIR(dstat.st_mode)) {
	    if (rmdir(path->string) != 0) {
		Error("rmdir(%s): %s", path->string, strerror(errno));
		retval = -1;
		break;
	    }
	} else {
	    if (unlink(path->string) != 0) {
		Error("unlink(%s): %s", path->string, strerror(errno));
		retval = -1;
		break;
	    }
	}
# endif
    }

# if 0				/* See above */
    if (path != (STRING *)0)
	DestroyString(path);
# endif

    /* free dir data structure */
    closedir(dir);

    return retval;
}
#endif

/* find out where/who we are						(ksb)
 * parse optons
 * read in the config file, open the log file
 * spawn the kids to drive the console groups
 * become the master server
 * shutdown with grace
 * exit happy
 */
int
main(int argc, char **argv)
{
    int i;
    FILE *fpConfig = (FILE *)0;
    static char acOpts[] = "7a:b:c:C:dDEFhiL:m:M:noO:p:P:RSuU:Vv";
    extern int optopt;
    extern char *optarg;
    struct passwd *pwd;
    char *origuser = (char *)0;
    char *curuser = (char *)0;
    int curuid = 0;
    GRPENT *pGE = (GRPENT *)0;
#if !USE_UNIX_DOMAIN_SOCKETS
# if USE_IPV6
    int s;
    struct addrinfo hints;
# else
#  if HAVE_INET_ATON
    struct in_addr inetaddr;
#  endif
# endif
#endif

    isMultiProc = 1;		/* make sure stuff has the pid */

    thepid = getpid();
    if ((char *)0 == (progname = strrchr(argv[0], '/'))) {
	progname = argv[0];
    } else {
	++progname;
    }

    setpwent();

    /* if we read from stdin (by accident) we don't wanna block.
     * we just don't want any more input at this point.
     */
    close(0);
    if (0 != open("/dev/null", O_RDWR, 0644)) {
	Error("open(/dev/null): %s", strerror(errno));
	Bye(EX_OSFILE);
    }
#if HAVE_SETLINEBUF
    setlinebuf(stdout);
    setlinebuf(stderr);
#endif
#if HAVE_SETVBUF
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
    setvbuf(stderr, NULL, _IOLBF, BUFSIZ);
#endif

    /* Initialize the break list */
    InitBreakList();

    /* prep the config options */
    if ((optConf = (CONFIG *)calloc(1, sizeof(CONFIG)))
	== (CONFIG *)0)
	OutOfMem();
    if ((config = (CONFIG *)calloc(1, sizeof(CONFIG)))
	== (CONFIG *)0)
	OutOfMem();

    while (EOF != (i = getopt(argc, argv, acOpts))) {
	switch (i) {
	    case '7':
		fStrip = 1;
		break;
	    case 'a':
		optConf->defaultaccess = *optarg;
		if (isupper((int)(optConf->defaultaccess)))
		    optConf->defaultaccess =
			tolower(optConf->defaultaccess);
		switch (optConf->defaultaccess) {
		    case 'r':
		    case 'a':
		    case 't':
			break;
		    default:
			Error("unknown access type `%s'", optarg);
			Bye(EX_USAGE);
		}
		break;
	    case 'b':
		if ((optConf->secondaryport = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;
	    case 'c':
#if HAVE_OPENSSL
		if ((optConf->sslcredentials =
		     StrDup(optarg)) == (char *)0)
		    OutOfMem();
#endif
		break;
	    case 'C':
		pcConfig = optarg;
		break;
	    case 'd':
		optConf->daemonmode = FLAGTRUE;
		break;
	    case 'D':
		fDebug++;
		break;
	    case 'E':
#if HAVE_OPENSSL
		optConf->sslrequired = FLAGFALSE;
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
		if ((optConf->logfile = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;
	    case 'm':
		cMaxMemb = atoi(optarg);
		if (cMaxMemb <= 0) {
		    Error("ignoring invalid -m option (%d <= 0)",
			  cMaxMemb);
		    cMaxMemb = MAXMEMB;
		}
		break;
	    case 'M':
		interface = StrDup(optarg);
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
		optConf->reinitcheck = atoi(optarg) * 60;
		break;
	    case 'p':
		if ((optConf->primaryport = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;
	    case 'P':
		if ((optConf->passwdfile = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;
	    case 'R':
		optConf->redirect = FLAGFALSE;
		break;
	    case 'S':
		fSyntaxOnly++;
		break;
	    case 'u':
		fAll = 1;
		break;
	    case 'U':
		if ((optConf->unifiedlog = StrDup(optarg)) == (char *)0)
		    OutOfMem();
		break;
	    case 'V':
		fVersion = 1;
		break;
	    case 'v':
		fVerbose = 1;
		break;
	    case '\?':
		Usage(0);
		Bye(EX_USAGE);
	    default:
		Error("option %c needs a parameter", optopt);
		Bye(EX_USAGE);
	}
    }

    if (fVersion) {
	Version();
	Bye(EX_OK);
    }

    Msg(MyVersion());

#if HAVE_GETLOGIN
    origuser = getlogin();
#endif
    curuid = getuid();

    if ((struct passwd *)0 != (pwd = getpwuid(curuid)))
	curuser = pwd->pw_name;

    /* chuck any empty username */
    if (curuser != (char *)0 && curuser[0] == '\000')
	curuser = (char *)0;

    if (startedMsg == (STRING *)0)
	startedMsg = AllocString();
    if (curuser == (char *)0)
	if (origuser == (char *)0)
	    BuildStringPrint(startedMsg, "started as uid %d by uid %d",
			     curuid, curuid);
	else
	    BuildStringPrint(startedMsg, "started as uid %d by `%s'",
			     curuid, origuser);
    else
	BuildStringPrint(startedMsg, "started as `%s' by `%s'", curuser,
			 (origuser == (char *)0) ? curuser : origuser);
    endpwent();
    Msg("%s", startedMsg->string);

#if HAVE_GETSPNAM && !HAVE_PAM
    if (!fSyntaxOnly && (geteuid() != 0)) {
	Msg("warning: running as a non-root user - any shadow password usage will most likely fail!");
    }
#endif

    if (fSyntaxOnly)
	Msg("performing configuration file syntax check");

    /* must do all this so IsMe() works right */
    if (gethostname(myHostname, MAXHOSTNAME) != 0) {
	Error("gethostname(): %s", strerror(errno));
	Bye(EX_OSERR);
    }
#if !USE_IPV6
    ProbeInterfaces(bindAddr);
#endif
#if !HAVE_CLOSEFROM
    i = GetMaxFiles();
    CONDDEBUG((1, "main(): GetMaxFiles=%d", i));
#endif

    /* initialize the timers */
    for (i = 0; i < T_MAX; i++)
	timers[i] = (time_t)0;

    /* read the config file */
    if ((FILE *)0 == (fpConfig = fopen(pcConfig, "r"))) {
	Error("fopen(%s): %s", pcConfig, strerror(errno));
	Bye(EX_NOINPUT);
    }
    ReadCfg(pcConfig, fpConfig);
    fclose(fpConfig);

#if !USE_UNIX_DOMAIN_SOCKETS
    /* set up the port to bind to */
    if (optConf->primaryport != (char *)0)
	config->primaryport = StrDup(optConf->primaryport);
    else if (pConfig->primaryport != (char *)0)
	config->primaryport = StrDup(pConfig->primaryport);
    else
	config->primaryport = StrDup(defConfig.primaryport);
    if (config->primaryport == (char *)0)
	OutOfMem();

# if !USE_IPV6
    /* Look for non-numeric characters */
    for (i = 0; config->primaryport[i] != '\000'; i++)
	if (!isdigit((int)config->primaryport[i]))
	    break;

    if (config->primaryport[i] == '\000') {
	/* numeric only */
	bindPort = atoi(config->primaryport);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 ==
	    (pSE = getservbyname(config->primaryport, "tcp"))) {
	    Error("getservbyname(%s) failed", config->primaryport);
	    Bye(EX_OSERR);
	} else {
	    bindPort = ntohs((unsigned short)pSE->s_port);
	}
    }
# endif

    /* set up the secondary port to bind to */
    if (optConf->secondaryport != (char *)0)
	config->secondaryport = StrDup(optConf->secondaryport);
    else if (pConfig->secondaryport != (char *)0)
	config->secondaryport = StrDup(pConfig->secondaryport);
    else
	config->secondaryport = StrDup(defConfig.secondaryport);
    if (config->secondaryport == (char *)0)
	OutOfMem();

# if !USE_IPV6
    /* Look for non-numeric characters */
    for (i = 0; config->secondaryport[i] != '\000'; i++)
	if (!isdigit((int)config->secondaryport[i]))
	    break;

    if (config->secondaryport[i] == '\000') {
	/* numeric only */
	bindBasePort = atoi(config->secondaryport);
    } else {
	/* non-numeric only */
	struct servent *pSE;
	if ((struct servent *)0 ==
	    (pSE = getservbyname(config->secondaryport, "tcp"))) {
	    Error("getservbyname(%s) failed", config->secondaryport);
	    Bye(EX_OSERR);
	} else {
	    bindBasePort = ntohs((unsigned short)pSE->s_port);
	}
    }
# endif
#endif

#if USE_IPV6
    /* set up the address to bind to */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_PASSIVE;

    /* create list or IPs suitable for primaryport */
    s = getaddrinfo(interface, config->primaryport, &hints, &bindAddr);
    if (s) {
	Error("getaddrinfo(%s): %s", interface, gai_strerror(s));
	Bye(EX_OSERR);
    }

    /* create list or IPs suitable for secondaryport */
    s = getaddrinfo(interface, config->secondaryport, &hints,
		    &bindBaseAddr);
    if (s) {
	Error("getaddrinfo(%s): %s", interface, gai_strerror(s));
	Bye(EX_OSERR);
    }
#elif USE_UNIX_DOMAIN_SOCKETS
    /* Don't do any redirects if we're purely local
     * (but it allows them to see where remote consoles are)
     */
    optConf->redirect = FLAGFALSE;
    if (interface == (char *)0)
	interface = UDSDIR;
#else
    /* set up the address to bind to */
    if (interface == (char *)0 ||
	(interface[0] == '*' && interface[1] == '\000'))
	bindAddr = INADDR_ANY;
    else {
# if HAVE_INET_ATON
	if (inet_aton(interface, &inetaddr) == 0) {
	    Error("inet_aton(%s): %s", interface, "invalid IP address");
	    Bye(EX_OSERR);
	}
	bindAddr = inetaddr.s_addr;
# else
	bindAddr = inet_addr(interface);
	if (bindAddr == (in_addr_t) (-1)) {
	    Error("inet_addr(%s): %s", interface, "invalid IP address");
	    Bye(EX_OSERR);
	}
# endif
    }
    if (fDebug) {
	struct in_addr ba;
	ba.s_addr = bindAddr;
	CONDDEBUG((1, "main(): bind address set to `%s'", inet_ntoa(ba)));
    }
#endif

    if (optConf->passwdfile != (char *)0)
	config->passwdfile = StrDup(optConf->passwdfile);
    else if (pConfig->passwdfile != (char *)0)
	config->passwdfile = StrDup(pConfig->passwdfile);
    else
	config->passwdfile = StrDup(defConfig.passwdfile);
    if (config->passwdfile == (char *)0)
	OutOfMem();

    if (optConf->logfile != (char *)0)
	config->logfile = StrDup(optConf->logfile);
    else if (pConfig->logfile != (char *)0)
	config->logfile = StrDup(pConfig->logfile);
    else
	config->logfile = StrDup(defConfig.logfile);
    if (config->logfile == (char *)0)
	OutOfMem();

    if (optConf->reinitcheck != 0)
	config->reinitcheck = optConf->reinitcheck;
    else if (pConfig->reinitcheck != 0)
	config->reinitcheck = pConfig->reinitcheck;
    else
	config->reinitcheck = defConfig.reinitcheck;

    if (optConf->defaultaccess != '\000')
	config->defaultaccess = optConf->defaultaccess;
    else if (pConfig->defaultaccess != '\000')
	config->defaultaccess = pConfig->defaultaccess;
    else
	config->defaultaccess = defConfig.defaultaccess;

    if (optConf->daemonmode != FLAGUNKNOWN)
	config->daemonmode = optConf->daemonmode;
    else if (pConfig->daemonmode != FLAGUNKNOWN)
	config->daemonmode = pConfig->daemonmode;
    else
	config->daemonmode = defConfig.daemonmode;

    if (optConf->redirect != FLAGUNKNOWN)
	config->redirect = optConf->redirect;
    else if (pConfig->redirect != FLAGUNKNOWN)
	config->redirect = pConfig->redirect;
    else
	config->redirect = defConfig.redirect;

    if (optConf->autocomplete != FLAGUNKNOWN)
	config->autocomplete = optConf->autocomplete;
    else if (pConfig->autocomplete != FLAGUNKNOWN)
	config->autocomplete = pConfig->autocomplete;
    else
	config->autocomplete = defConfig.autocomplete;

    if (optConf->loghostnames != FLAGUNKNOWN)
	config->loghostnames = optConf->loghostnames;
    else if (pConfig->loghostnames != FLAGUNKNOWN)
	config->loghostnames = pConfig->loghostnames;
    else
	config->loghostnames = defConfig.loghostnames;

    if (optConf->unifiedlog != (char *)0) {
	config->unifiedlog = StrDup(optConf->unifiedlog);
	if (config->unifiedlog == (char *)0)
	    OutOfMem();
    } else if (pConfig->unifiedlog != (char *)0) {
	config->unifiedlog = StrDup(pConfig->unifiedlog);
	if (config->unifiedlog == (char *)0)
	    OutOfMem();
    } else if (defConfig.unifiedlog != (char *)0) {
	config->unifiedlog = StrDup(defConfig.unifiedlog);
	if (config->unifiedlog == (char *)0)
	    OutOfMem();
    }

    if (optConf->initdelay != 0)
	config->initdelay = optConf->initdelay;
    else if (pConfig->initdelay != 0)
	config->initdelay = pConfig->initdelay;
    else
	config->initdelay = defConfig.initdelay;

#if HAVE_OPENSSL
    if (optConf->sslrequired != FLAGUNKNOWN)
	config->sslrequired = optConf->sslrequired;
    else if (pConfig->sslrequired != FLAGUNKNOWN)
	config->sslrequired = pConfig->sslrequired;
    else
	config->sslrequired = defConfig.sslrequired;

    if (optConf->sslreqclientcert != FLAGUNKNOWN)
	config->sslreqclientcert = optConf->sslreqclientcert;
    else if (pConfig->sslreqclientcert != FLAGUNKNOWN)
	config->sslreqclientcert = pConfig->sslreqclientcert;
    else
	config->sslreqclientcert = defConfig.sslreqclientcert;

    if (optConf->sslcredentials != (char *)0)
	config->sslcredentials = StrDup(optConf->sslcredentials);
    else if (pConfig->sslcredentials != (char *)0)
	config->sslcredentials = StrDup(pConfig->sslcredentials);
    else
	config->sslcredentials = StrDup(defConfig.sslcredentials);

    if (optConf->sslcacertificatefile != (char *)0)
	config->sslcacertificatefile =
	    StrDup(optConf->sslcacertificatefile);
    else if (pConfig->sslcacertificatefile != (char *)0)
	config->sslcacertificatefile =
	    StrDup(pConfig->sslcacertificatefile);
    else
	config->sslcacertificatefile =
	    StrDup(defConfig.sslcacertificatefile);
#endif

#if HAVE_SETPROCTITLE
    if (optConf->setproctitle != FLAGUNKNOWN)
	config->setproctitle = optConf->setproctitle;
    else if (pConfig->setproctitle != FLAGUNKNOWN)
	config->setproctitle = pConfig->setproctitle;
    else
	config->setproctitle = defConfig.setproctitle;
#endif

#if HAVE_DMALLOC && DMALLOC_MARK_MAIN
    dmallocMarkMain = dmalloc_mark();
#endif

    if (pGroups == (GRPENT *)0 && pRCList == (REMOTE *)0) {
	Error("no consoles found in configuration file");
    } else if (fSyntaxOnly) {
	/* short-circuit */
#if USE_UNIX_DOMAIN_SOCKETS
    } else if (VerifyEmptyDirectory(interface) == -1) {
	Error("Master(): %s: unusable socket directory", interface);
#endif
    } else {
#if HAVE_OPENSSL
	/* Prep the SSL layer */
	SetupSSL();
#endif
#if HAVE_GSSAPI
	SetupGSSAPI();
#endif

	if (config->daemonmode == FLAGTRUE)
	    Daemonize();

	ReopenUnifiedlog();

	/* if no one can use us we need to come up with a default
	 */
	if (pACList == (ACCESS *)0)
#if USE_IPV6
	    SetDefAccess();
#else
	    SetDefAccess(myAddrs, myHostname);
#endif

	/* spawn all the children, so fix kids has an initial pid
	 */
	for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext) {
	    if (pGE->imembers == 0)
		continue;

	    Spawn(pGE, -1);
	    Verbose("group #%d pid %lu on port %hu", pGE->id,
		    (unsigned long)pGE->pid, pGE->port);
	}

#if HAVE_SETPROCTITLE
	if (config->setproctitle == FLAGTRUE) {
	    REMOTE *pRC;
	    GRPENT *pGE;
	    int local = 0, remote = 0;
	    for (pGE = pGroups; pGE != (GRPENT *)0; pGE = pGE->pGEnext)
		local += pGE->imembers;
	    for (pRC = pRCList; (REMOTE *)0 != pRC; pRC = pRC->pRCnext)
		remote++;
	    setproctitle("master: port %hu, %d local, %d remote",
# if USE_IPV6
			 (unsigned short)strtol(config->primaryport, NULL, 10),
# elif USE_UNIX_DOMAIN_SOCKETS
			 (unsigned short)0,
# else
			 bindPort,
# endif
			 local, remote);
	}
#endif

	if (fVerbose) {
	    ACCESS *pACtmp;
	    for (pACtmp = pACList; pACtmp != (ACCESS *)0;
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
	    for (pRC = pRCUniq; (REMOTE *)0 != pRC; pRC = pRC->pRCuniq) {
		Verbose("peer server on `%s'", pRC->rhost);
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

    if (unifiedlog != (CONSFILE *)0)
	FileClose(&unifiedlog);

    DumpDataStructures();

    Msg("terminated");
    endpwent();
    if (fSyntaxOnly && fErrorPrinted)
	Bye(EX_DATAERR);
    else
	Bye(EX_OK);
    return EX_OK;		/* never gets here clears the compiler warning */
}
