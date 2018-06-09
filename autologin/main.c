/*
 * machine generated cmd line parser
 * built by mkcmd version 7.6 Gamma
 */

#include <config.h>

#include <stdio.h>
#include <ctype.h>

#include <compat.h>

#include "main.h"

#ifndef HAVE_GETOPT
static int
  optopt;			/* character checked for validity       */

/* get option letter from argument vector, also does -number correctly
 * for nice, xargs, and stuff (these extras by ksb)
 * does +arg if you give a last argument of "+", else give NULL
 */
static int
getopt(int nargc, char **nargv, char *ostr)
{
    register char *oli;		/* option letter list index     */
    static char EMSG[] = "";	/* just a null place            */
    static char *place = EMSG;	/* option letter processing     */

    if ('\000' == *place) {	/* update scanning pointer */
	if (optind >= nargc)
	    return EOF;
	if (nargv[optind][0] != '-') {
	    register int iLen;
	    return EOF;
	}
	place = nargv[optind];
	if ('\000' == *++place)	/* "-" (stdin)              */
	    return EOF;
	if (*place == '-' && '\000' == place[1]) {
	    /* found "--"           */
	    ++optind;
	    return EOF;
	}
    }
    /* option letter okay? */
    /* if we find the letter, (not a `:')
     * or a digit to match a # in the list
     */
    if ((optopt = *place++) == ':' ||
	(NULL == (oli = strchr(ostr, optopt)) &&
	 (!(isdigit(optopt) || '-' == optopt) ||
	  NULL == (oli = strchr(ostr, '#'))))) {
	if (!*place)
	    ++optind;
	return ('?');
    }
    if ('#' == *oli) {		/* accept as -digits */
	optarg = place - 1;
	++optind;
	place = EMSG;
	return '#';
    }
    if (*++oli != ':') {	/* don't need argument */
	optarg = NULL;
	if ('\000' == *place)
	    ++optind;
    } else {			/* need an argument */
	if (*place) {		/* no white space */
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
    return optopt;		/* dump back option letter */
}
#endif /* ! HAVE_GETOPT */

char
 *progname = "", *au_terse[] = {
    " [-u] [-c cmd] [-e env=value] [-g group] [-l login] [-t tty]",
    " -h",
    " -V",
    NULL
}, *u_help[] = {
"c cmd       command to run",
	"e env=value environment variable to set",
	"g group     initial group",
	"h           print this help message",
	"l login     login name",
	"t tty       attach to this terminal",
	"u           do no make utmp entry",
	"V           show version information", NULL}, *pcCommand =
    NULL, *pcGroup = NULL, *pcLogin = NULL, *pcTty =
    NULL;
int
  fMakeUtmp = 1, iErrs = 0;

#ifndef u_terse
# define u_terse	(au_terse[0])
#endif

/*
 * parser
 */
int
main(int argc, char **argv)
{
    static char
      sbOpt[] = "c:e:g:hl:t:uV", *u_pch = NULL;
    static int
      u_loop = 0;
    register int u_curopt;

    progname = strrchr(argv[0], '/');
    if (NULL == progname)
	progname = argv[0];
    else
	++progname;
    while (EOF != (u_curopt = getopt(argc, argv, sbOpt))) {
	switch (u_curopt) {
	    case '*':
		fprintf(stderr, "%s: option `-%c\' needs a parameter\n",
			progname, optopt);
		exit(1);
	    case '?':
		fprintf(stderr,
			"%s: unknown option `-%c\', use `-h\' for help\n",
			progname, optopt);
		exit(1);
	    case 'c':
		pcCommand = optarg;
		continue;
	    case 'e':
		if (putenv(optarg) != 0) {
		    (void)fprintf(stderr, "%s: putenv(\"%s\"): failed\n",
				  progname, optarg);
		    exit(1);
		}
		continue;
	    case 'g':
		pcGroup = optarg;
		continue;
	    case 'h':
		for (u_loop = 0; NULL != (u_pch = au_terse[u_loop]);
		     ++u_loop) {
		    if ('\000' == *u_pch) {
			fprintf(stdout, "%s: with no parameters\n",
				progname);
			continue;
		    }
		    fprintf(stdout, "%s: usage%s\n", progname, u_pch);
		}
		for (u_loop = 0; NULL != (u_pch = u_help[u_loop]);
		     ++u_loop) {
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
		printf("%s\n", progname);
		exit(0);
	}
	break;
    }
    Process();
    exit(iErrs);
}
