/*@Header@*/
/*
 *	ident_client.c
 *
 * Identifies the remote user of a given connection.
 *
 * Written 940112 by Luke Mewburn <lm@rmit.edu.au>
 *
 * Copyright (C) 1994 by Luke Mewburn.
 * This code may be used freely by anyone as long as this copyright remains.
 *
 * $Compile(*): ${cc-cc} ${cc_debug--g} -DTEST %f -o %F -lsocket -lnls
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "identd.h"

#define IDENT_PORT	113


/*@Explode cli@*/
/*									(lm)
 * ident_client
 *	- user interface to identd
 *
 * Args:
 *	peeraddr	sockaddr_in struct of peer end, from getpeername(...)
 *	ouraddr		sockaddr_in struct of local end, from getsockname(...)
 *
 * Returns:
 *	NULL on failure to identify (for whatever reason), or pointer to
 *	static character string with the identity.
 */
char *
ident_client(peeraddr, ouraddr, identifier)
	struct sockaddr_in	peeraddr, ouraddr;
	char		*identifier/*[1024]*/; 
{
	struct sockaddr_in	authcon;
	int			authfd, authlen;
	struct servent		*identserv;
	int			identport;

	FILE			*authfpin, *authfpout;
	char			buffer[8192];	/* XXX: argh! magic numbers */
	char			reply_type[81]; 
	char			opsys_or_err[81]; 
	int			rport, lport;


	authfd = socket(AF_INET, SOCK_STREAM, 0);
	if (authfd == -1)
		return NULL;

	identserv = getservbyname("ident", "tcp");
	if (identserv)
		identport = identserv->s_port;
	else
		identport = ntohs(IDENT_PORT);

	memset(&authcon, 0, sizeof(authcon));
	authcon.sin_family = AF_INET;
	authcon.sin_addr.s_addr = peeraddr.sin_addr.s_addr;
	authcon.sin_port = identport;

	authlen = sizeof(authcon);
	if (connect(authfd, (struct sockaddr *)&authcon, authlen) < 0)
		return NULL;

	authfpin  = fdopen(authfd, "r");
	authfpout = fdopen(authfd, "w");
	if (!authfpin || !authfpout)
		return NULL;

	fprintf(authfpout, "%d , %d\n", peeraddr.sin_port, ouraddr.sin_port);
	fflush(authfpout);

	if (fgets(buffer, sizeof(buffer)-1, authfpin) == NULL)
		return NULL;

	shutdown(authfd, 1);

	authlen = sscanf(buffer, "%d , %d : %[^ \t\n\r:] : %[^ \t\n\r:] : %[^\n\r]",
		    &lport, &rport, reply_type, opsys_or_err, identifier);
	if (authlen < 3)
		return NULL;

	if (0 == strcasecmp(reply_type, "ERROR")) {
		printf("error %s\n", buffer);
		return NULL;
	}
	if (0 != strcasecmp(reply_type, "USERID")) {
		printf("no-user %s\n", buffer);
		return NULL;
	}

	return identifier;
} /* ident_client */

/*@Remove@*/
#if defined(TEST)

/*@Explode main@*/
extern int errno;
extern char *sys_errlist[];
#define strerror(Me) (sys_errlist[Me])

static struct sockaddr_in master_port, response_port;

char *progname = "identd-test";

/* test driver for the identd client module				(ksb)
 * bind to a port, wait for telnets and tell them who they are
 */
int
main(argc, argv, envp)
int argc;
char **argv, **envp;
{
	auto struct sockaddr_in hisaddr, ouraddr;
	register int mfd, cfd;
	auto int true = 1, length, so;
	auto char them[1024];

	(void)memset((void *)&master_port, 0, sizeof(master_port));
	master_port.sin_family = AF_INET;
	*(u_long *)&master_port.sin_addr = INADDR_ANY;
	master_port.sin_port = htons(7098);

	if (-1 == (mfd = socket(AF_INET, SOCK_STREAM, 0))) {
		fprintf(stderr, "%s: socket: %s\n", progname, strerror(errno));
		exit(1);
	}
#if defined(SO_REUSEADDR) && defined(SOL_SOCKET)
	if (setsockopt(mfd, SOL_SOCKET, SO_REUSEADDR, (char *)&true, sizeof(true)) < 0) {
		fprintf(stderr, "%s: setsockopt: %s\n", progname, strerror(errno));
		exit(1);
	}
#endif
	if (bind(mfd, (struct sockaddr *)&master_port, sizeof(master_port))<0) {
		fprintf(stderr, "%s: bind: %s\n", progname, strerror(errno));
		exit(1);
	}

	if (listen(mfd, SOMAXCONN) < 0) {
		fprintf(stderr, "%s: listen: %s\n", progname, strerror(errno));
		exit(1);
	}

	length = sizeof(ouraddr);
	if (getsockname(mfd, (struct sockaddr *)&ouraddr, &length) < 0) {
		fprintf(stderr, "%s: getsockname: %d: %s\n", progname, mfd, strerror(errno));

	}

	while (so = sizeof(response_port), -1 != (cfd = accept(mfd, (struct sockaddr *)&response_port, &so))) {
		printf("%d\n", cfd);
		length = sizeof(hisaddr);
		if (getpeername(cfd, (struct sockaddr *)&hisaddr, &length) < 0) {
			write(cfd, "can't get your addrees?\n", 24);
		} else if ((char *)0 != ident_client(hisaddr, ouraddr, them)) {
			write(cfd, them, strlen(them));
			write(cfd, "\n", 1);
		} else {
			write(cfd, "no identd?\n", 11);
		}
		close(cfd);
		printf("closed\n");
	}

	exit(0);
}
/*@Remove@*/
#endif /* test driver */
