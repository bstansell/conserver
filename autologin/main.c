/*
 * machine generated cmd line parser
 * built by mkcmd version 7.6 Gamma
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>

extern int errno;
extern char *malloc(), *calloc(), *realloc();

#define ENVOPT 0
#define GETARG 0
#define GETOPT 1
/* from std_help.m */
/* from std_version.m */
/* from autologin.m */
/* $Id: T.c,v 7.2 94/07/11 00:42:06 ksb Exp $
 * literal text included from a tempate
 * based on Keith Bostic's getopt in comp.sources.unix volume1
 * modified for mkcmd use.... by ksb@cc.purdue.edu (Kevin Braunsdorf)
 */

#if GETOPT || GETARG
/* IBMR2 (AIX in the real world) defines
 * optind and optarg in <stdlib.h> and confuses the hell out
 * of the C compiler.  So we use those externs.  I guess we will
 * have to stop using the old names. -- ksb
 */
#ifdef _AIX
#include <stdlib.h>
#else
static int
	optind = 1;		/* index into parent argv vector	*/
static char
	*optarg;		/* argument associated with option	*/
#endif
#endif /* only if we use them */

#if ENVOPT
/* breakargs - break a string into a string vector for execv.
 *
 * Note, when done with the vector, merely "free" the vector.
 * Written by Stephen Uitti, PUCC, Nov '85 for the new version
 * of "popen" - "nshpopen", that doesn't use a shell.
 * (used here for the as filters, a newer option).
 *
 * breakargs is copyright (C) Purdue University, 1985
 *
 * Permission is hereby given for its free reproduction and
 * modification for All purposes.
 * This notice and all embedded copyright notices be retained.
 */

/* this trys to emulate shell quoting, but I doubt it does a good job	(ksb)
 * [[ but not substitution -- that would be silly ]]
 */
static char *
u_mynext(u_pcScan, u_pcDest)
register char *u_pcScan, *u_pcDest;
{
	register int u_fQuote;

	for (u_fQuote = 0; *u_pcScan != '\000' && (u_fQuote||(*u_pcScan != ' ' && *u_pcScan != '\t')); ++u_pcScan) {
		switch (u_fQuote) {
		default:
		case 0:
			if ('"' == *u_pcScan) {
				u_fQuote = 1;
				continue;
			} else if ('\'' == *u_pcScan) {
				u_fQuote = 2;
				continue;
			}
			break;
		case 1:
			if ('"' == *u_pcScan) {
				u_fQuote = 0;
				continue;
			}
			break;
		case 2:
			if ('\'' == *u_pcScan) {
				u_fQuote = 0;
				continue;
			}
			break;
		}
		if ((char*)0 != u_pcDest) {
			*u_pcDest++ = *u_pcScan;
		}
	}
	if ((char*)0 != u_pcDest) {
		*u_pcDest = '\000';
	}
	return u_pcScan;
}

/* given an envirionment variable insert it in the option list		(ksb)
 * (exploded with the above routine)
 */
static int
u_envopt(cmd, pargc, pargv)
char *cmd, *(**pargv);
int *pargc;
{
	register char *p;		/* tmp				*/
	register char **v;		/* vector of commands returned	*/
	register unsigned sum;		/* bytes for malloc		*/
	register int i, j;		/* number of args		*/
	register char *s;		/* save old position		*/

	while (*cmd == ' ' || *cmd == '\t')
		cmd++;
	p = cmd;			/* no leading spaces		*/
	i = 1 + *pargc;
	sum = sizeof(char *) * i;
	while (*p != '\000') {		/* space for argv[];		*/
		++i;
		s = p;
		p = u_mynext(p, (char *)0);
		sum += sizeof(char *) + 1 + (unsigned)(p - s);
		while (*p == ' ' || *p == '\t')
			p++;
	}
	++i;
	/* vector starts at v, copy of string follows NULL pointer
         * the extra 7 bytes on the end allow use to be alligned
         */
        v = (char **)malloc(sum+sizeof(char *)+7);
	if (v == NULL)
		return 0;
	p = (char *)v + i * sizeof(char *); /* after NULL pointer */
	i = 0;				/* word count, vector index */
	v[i++] = (*pargv)[0];
	while (*cmd != '\000') {
		v[i++] = p;
		cmd = u_mynext(cmd, p);
		p += strlen(p)+1;
		while (*cmd == ' ' || *cmd == '\t')
			++cmd;
	}
	for (j = 1; j < *pargc; ++j)
		v[i++] = (*pargv)[j];
	v[i] = NULL;
	*pargv = v;
	*pargc = i;
	return i;
}
#endif /* u_envopt called */

#if GETARG
/*
 * return each non-option argument one at a time, EOF for end of list
 */
static int
u_getarg(nargc, nargv)
int nargc;
char **nargv;
{
	if (nargc <= optind) {
		optarg = (char *) 0;
		return EOF;
	}
	optarg = nargv[optind++];
	return 0;
}
#endif /* u_getarg called */


#if GETOPT
static int
	optopt;			/* character checked for validity	*/

/* get option letter from argument vector, also does -number correctly
 * for nice, xargs, and stuff (these extras by ksb)
 * does +arg if you give a last argument of "+", else give (char *)0
 */
static int
u_getopt(nargc, nargv, ostr, estr)
int nargc;
char **nargv, *ostr, *estr;
{
	register char	*oli;		/* option letter list index	*/
	static char	EMSG[] = "";	/* just a null place		*/
	static char	*place = EMSG;	/* option letter processing	*/

	if ('\000' == *place) {		/* update scanning pointer */
		if (optind >= nargc)
			return EOF;
		if (nargv[optind][0] != '-') {
			register int iLen;
			if ((char *)0 != estr && 0 == strncmp(estr, nargv[optind], iLen = strlen(estr))) {
				optarg = nargv[optind++]+iLen;
				return '+';
			}
			return EOF;
		}
		place = nargv[optind];
		if ('\000' == *++place)	/* "-" (stdin)		*/
			return EOF;
		if (*place == '-' && '\000' == place[1]) {
			/* found "--"		*/
			++optind;
			return EOF;
		}
	}				/* option letter okay? */
	/* if we find the letter, (not a `:')
	 * or a digit to match a # in the list
	 */
	if ((optopt = *place++) == ':' ||
	 ((char *)0 == (oli = strchr(ostr,optopt)) &&
	  (!(isdigit(optopt)||'-'==optopt) || (char *)0 == (oli = strchr(ostr, '#'))))) {
		if(!*place) ++optind;
		return('?');
	}
	if ('#' == *oli) {		/* accept as -digits */
		optarg = place -1;
		++optind;
		place = EMSG;
		return '#';
	}
	if (*++oli != ':') {		/* don't need argument */
		optarg = NULL;
		if ('\000' == *place)
			++optind;
	} else {				/* need an argument */
		if (*place) {			/* no white space */
			optarg = place;
		} else if (nargc <= ++optind) {	/* no arg!! */
			place = EMSG;
			return '*';
		} else {
			optarg = nargv[optind];	/* white space */
		}
		place = EMSG;
		++optind;
	}
	return optopt;			/* dump back option letter */
}
#endif /* u_getopt called */
#undef ENVOPT
#undef GETARG
#undef GETOPT

char
	*progname = "$Id$",
	*au_terse[] = {
		" [-u] [-c cmd] [-e env=value] [-g group] [-l login] [-t tty]",
		" -h",
		" -V",
		(char *)0
	},
	*u_help[] = {
		"c cmd       command to run",
		"e env=value environment variable to set",
		"g group     initial group",
		"h           print this help message",
		"l login     login name",
		"t tty       attach to this terminal",
		"u           do no make utmp entry",
		"V           show version information",
		(char *)0
	},
	*pcCommand = (char *)0,
	*pcGroup = (char *)0,
	*pcLogin = (char *)0,
	*pcTty = (char *)0;
int
	fMakeUtmp = 1,
	iErrs = 0;

#ifndef u_terse
#define u_terse	(au_terse[0])
#endif
/* from std_help.m */
/* from std_version.m */
/* from autologin.m */

static char *rcsid =
	"$Id: autologin.m,v 1.2 92/07/28 13:18:34 ksb Exp $";

/*
 * parser
 */
int
main(argc, argv)
int argc;
char **argv;
{
	static char
		sbOpt[] = "c:e:g:hl:t:uV",
		*u_pch = (char *)0;
	static int
		u_loop = 0;
	register int u_curopt;
	extern int atoi();

	progname = strrchr(argv[0], '/');
	if ((char *)0 == progname)
		progname = argv[0];
	else
		++progname;
	while (EOF != (u_curopt = u_getopt(argc, argv, sbOpt, (char *)0))) {
		switch (u_curopt) {
		case '*':
			fprintf(stderr, "%s: option `-%c\' needs a parameter\n", progname, optopt);
			exit(1);
		case '?':
			fprintf(stderr, "%s: unknown option `-%c\', use `-h\' for help\n", progname, optopt);
			exit(1);
		case 'c':
			pcCommand = optarg;
			continue;
		case 'e':
			if (putenv(optarg) != 0) {
				 (void) fprintf(stderr, "%s: putenv(\"%s\"): failed\n", progname, optarg);
				exit(1);
			}
			continue;
		case 'g':
			pcGroup = optarg;
			continue;
		case 'h':
			for (u_loop = 0; (char *)0 != (u_pch = au_terse[u_loop]); ++u_loop) {
				if ('\000' == *u_pch) {
					fprintf(stdout, "%s: with no parameters\n", progname);
					continue;
				}
				fprintf(stdout, "%s: usage%s\n", progname, u_pch);
			}
			for (u_loop = 0; (char *)0 != (u_pch = u_help[u_loop]); ++u_loop) {
				fprintf(stdout, "%s\n", u_pch);
			}
			exit(0);
		case 'l':
			pcLogin = optarg;
			continue;
		case 't':
			pcTty = optarg;
			continue;
		case 'u':
			fMakeUtmp = 0;
			continue;
		case 'V':
			printf("%s: %s\n", progname, rcsid);
			exit(0);
		}
		break;
	}
	Process();
	exit(iErrs);
}
