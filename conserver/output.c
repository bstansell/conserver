/*
 *  $Id: output.c,v 1.6 2001-07-05 00:09:39-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000-2001
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#include <stdio.h>
#include <varargs.h>
#include <output.h>

int outputPid = 0;
char *progname = "conserver package";
int thepid = 0;
int fDebug = 0;

void Debug(fmt, va_alist)
char *fmt;
va_dcl
{
    va_list ap;
    va_start(ap);
    if (!fDebug) return;
    if (outputPid)
	fprintf(stderr, "%s (%d): DEBUG: ", progname, thepid);
    else
	fprintf(stderr, "%s: DEBUG: ", progname);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n" );
    va_end(ap);
}

void Error(fmt, va_alist)
char *fmt;
va_dcl
{
    va_list ap;
    va_start(ap);
    if (outputPid)
	fprintf(stderr, "%s (%d): ", progname, thepid);
    else
	fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n" );
    va_end(ap);
}

void Info(fmt, va_alist)
char *fmt;
va_dcl
{
    va_list ap;
    va_start(ap);
    if (outputPid)
	fprintf(stdout, "%s (%d): ", progname, thepid);
    else
	fprintf(stdout, "%s: ", progname);
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n" );
    va_end(ap);
}
