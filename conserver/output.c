/*
 *  $Id: output.c,v 1.5 2001-06-15 07:16:51-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000-2001
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#include <stdio.h>
#include <varargs.h>
#include <main.h>
#include <output.h>

void Debug(fmt, va_alist)
char *fmt;
va_dcl
{
    va_list ap;
    va_start(ap);
    if (!fDebug) return;
    fprintf(stderr, "%s (%d): DEBUG: ", progname, thepid );
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
    fprintf(stderr, "%s (%d): ", progname, thepid );
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
    fprintf(stdout, "%s (%d): ", progname, thepid );
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n" );
    va_end(ap);
}
