/*
 *  $Id: convert.c,v 1.7 2003/08/15 21:24:39 bryan Exp $
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
/*
 * Network console modifications by Robert Olson, olson@mcs.anl.gov.
 */

#include <compat.h>

#include <util.h>
#include <consent.h>
#include <client.h>
#include <group.h>
#include <access.h>
#include <readcfg.h>
#include <master.h>
#include <main.h>


void
DestroyDataStructures()
{
}

char *
#if PROTOTYPES
ReadLine2(FILE *fp, STRING *save, int *iLine)
#else
ReadLine2(fp, save, iLine)
    FILE *fp;
    STRING *save;
    int *iLine;
#endif
{
    static char buf[1024];
    char *wholeline = (char *)0;
    char *ret = (char *)0;
    int i, buflen, peek, commentCheck = 1, comment = 0;
    static STRING *bufstr = (STRING *)0;
    static STRING *wholestr = (STRING *)0;

    if (bufstr == (STRING *)0)
	bufstr = AllocString();
    if (wholestr == (STRING *)0)
	wholestr = AllocString();
    peek = 0;
    wholeline = (char *)0;
    BuildString((char *)0, bufstr);
    BuildString((char *)0, wholestr);
    while (save->used || ((ret = fgets(buf, sizeof(buf), fp)) != (char *)0)
	   || peek) {
	/* If we have a previously saved line, use it instead */
	if (save->used) {
	    strcpy(buf, save->string);
	    BuildString((char *)0, save);
	}

	if (peek) {
	    /* End of file?  Never mind. */
	    if (ret == (char *)0)
		break;

	    /* If we don't have a line continuation and we've seen
	     * some worthy data
	     */
	    if (!isspace((int)buf[0]) && (wholeline != (char *)0)) {
		BuildString((char *)0, save);
		BuildString(buf, save);
		break;
	    }

	    peek = 0;
	}

	if (commentCheck) {
	    for (i = 0; buf[i] != '\000'; i++)
		if (!isspace((int)buf[i]))
		    break;
	    if (buf[i] == '#') {
		comment = 1;
		commentCheck = 0;
	    } else if (buf[i] != '\000') {
		commentCheck = 0;
	    }
	}

	/* Check for EOL */
	buflen = strlen(buf);
	if ((buflen >= 1) && (buf[buflen - 1] == '\n')) {
	    (*iLine)++;		/* Finally have a whole line */
/*	    if (comment == 0 && commentCheck == 0) { */
	    /* Finish off the chunk without the \n */
	    buf[buflen - 1] = '\000';
	    BuildString(buf, bufstr);
	    wholeline = BuildString(bufstr->string, wholestr);
/*	    }*/
	    peek = 1;
	    comment = 0;
	    commentCheck = 1;
	    BuildString((char *)0, bufstr);
	} else {
	    /* Save off the partial chunk */
	    BuildString(buf, bufstr);
	}
    }

    /* If we hit the EOF and weren't peeking ahead
     * and it's not a comment
     */
    /*
       if (!peek && (ret == (char *)0) && (comment == 0) &&
       (commentCheck == 0)) {
     */
    if (!peek && (ret == (char *)0)) {
	(*iLine)++;
	wholeline = BuildString(bufstr->string, wholestr);
	if (wholeline[0] == '\000')
	    wholeline = (char *)0;
    }

    CONDDEBUG((1, "ReadLine2(): returning <%s>",
	       (wholeline != (char *)0) ? wholeline : "<NULL>"));
    return wholeline;
}

/* read in the configuration file, fill in all the structs we use	(ksb)
 * to manage the consoles
 */
void
#if PROTOTYPES
ReadCfg(char *pcFile, FILE *fp)
#else
ReadCfg(pcFile, fp)
    char *pcFile;
    FILE *fp;
#endif
{
    int iLine;
    unsigned char *acIn;
    static STRING *acInSave = (STRING *)0;
    char *acStart;
    static STRING *logDirectory = (STRING *)0;
    static STRING *defMark = (STRING *)0;
    int sawACL = 0;
    int printedFull = 0;

    if (defMark == (STRING *)0)
	defMark = AllocString();
    if (logDirectory == (STRING *)0)
	logDirectory = AllocString();
    if (acInSave == (STRING *)0)
	acInSave = AllocString();
    BuildString((char *)0, defMark);
    BuildString((char *)0, acInSave);
    BuildString((char *)0, logDirectory);

    iLine = 0;
    while ((acIn =
	    (unsigned char *)ReadLine2(fp, acInSave,
				       &iLine)) != (unsigned char *)0) {
	char *pcLine, *pcMode, *pcLog, *pcRem, *pcStart, *pcMark, *pcBreak;
	char *pcColon;

	acStart = PruneSpace((char *)acIn);
	if (acStart[0] == '#') {
	    printf("%s\n", acStart);
	    continue;
	}
	if (printedFull == 0) {
	    printf("default full {\n\trw *;\n}\n");
	    printedFull = 1;
	}

	if ('%' == acStart[0] && '%' == acStart[1] && '\000' == acStart[2]) {
	    break;
	}
	if ((char *)0 != (pcLine = strchr(acStart, '=')) &&
	    ((char *)0 == (pcColon = strchr(acStart, ':')) ||
	     pcColon > pcLine)) {
	    *pcLine++ = '\000';
	    acStart = PruneSpace(acStart);
	    pcLine = PruneSpace(pcLine);
	    if (0 == strcmp(acStart, "LOGDIR")) {
		BuildString((char *)0, logDirectory);
		BuildString(pcLine, logDirectory);
		printf("default * {\n");
		if (logDirectory->used > 1)
		    printf("\tlogfile %s/&;\n", logDirectory->string);
		else
		    printf("\tlogfile \"\";\n");
		if (defMark->used > 1)
		    printf("\ttimestamp %s;\n", defMark->string);
		else
		    printf("\ttimestamp \"\";\n");
		printf("\tinclude full;\n}\n");
	    } else if (0 == strcmp(acStart, "TIMESTAMP")) {
		BuildString((char *)0, defMark);
		BuildString(pcLine, defMark);
		printf("default * {\n");
		if (logDirectory->used > 1)
		    printf("\tlogfile %s/&;\n", logDirectory->string);
		else
		    printf("\tlogfile \"\";\n");
		if (defMark->used > 1)
		    printf("\ttimestamp %s;\n", defMark->string);
		else
		    printf("\ttimestamp \"\";\n");
		printf("\tinclude full;\n}\n");
	    } else if (0 == strcmp(acStart, "DOMAINHACK")) {
	    } else if (0 == strncmp(acStart, "BREAK", 5) &&
		       acStart[5] >= '1' && acStart[5] <= '9' &&
		       acStart[6] == '\000') {
		CONDDEBUG((1, "ReadCfg(): BREAK%c found with `%s'",
			   acStart[5], pcLine));
		if (pcLine[0] == '\000') {
		    printf("break %c {\n\tstring \"\";\n}\n", acStart[5]);
		} else {
		    char *q, *p;
		    p = pcLine;
		    BuildTmpString((char *)0);
		    while ((q = strchr(p, '"')) != (char *)0) {
			*q = '\000';
			BuildTmpString(p);
			BuildTmpString("\\\"");
			p = q + 1;
			*q = '"';
		    }
		    q = BuildTmpString(p);
		    printf("break %c {\n\tstring \"%s\";\n}\n", acStart[5],
			   q);
		}
	    } else {
		Error("%s(%d) unknown variable `%s'", pcFile, iLine,
		      acStart);
	    }
	    continue;
	}
	if ((char *)0 == (pcLine = strchr(acStart, ':')) ||
	    (char *)0 == (pcMode = strchr(pcLine + 1, ':')) ||
	    (char *)0 == (pcLog = strchr(pcMode + 1, ':'))) {
	    Error("%s(%d) bad config line `%s'", pcFile, iLine, acIn);
	    continue;
	}
	*pcLine++ = '\000';
	*pcMode++ = '\000';
	*pcLog++ = '\000';

	acStart = PruneSpace(acStart);
	pcLine = PruneSpace(pcLine);
	pcMode = PruneSpace(pcMode);
	pcLog = PruneSpace(pcLog);

	if ((char *)0 != (pcMark = strchr(pcLog, ':'))) {
	    *pcMark++ = '\000';
	    pcLog = PruneSpace(pcLog);
	    pcMark = PruneSpace(pcMark);
	    /* Skip null intervals */
	    if (pcMark[0] == '\000')
		pcMark = (char *)0;
	}

	if ((char *)0 == pcMark) {
	    pcBreak = (char *)0;
	} else {
	    if ((char *)0 != (pcBreak = strchr(pcMark, ':'))) {
		*pcBreak++ = '\000';
		pcMark = PruneSpace(pcMark);
		pcBreak = PruneSpace(pcBreak);
		/* Ignore null specs */
		if (pcMark[0] == '\000')
		    pcMark = (char *)0;
		if (pcBreak[0] == '\000')
		    pcBreak = (char *)0;
	    }
	}

	if ((char *)0 != (pcRem = strchr(pcLine, '@'))) {
	    *pcRem++ = '\000';
	    pcLine = PruneSpace(pcLine);
	    pcRem = PruneSpace(pcRem);
	}

	printf("console %s {\n", acStart);
	if (pcRem == (char *)0) {
	    printf("\tmaster localhost;\n");
	} else {
	    printf("\tmaster %s;\n", pcRem);
	}

	/*
	 *  Here we substitute the console name for any '&' character in the
	 *  logfile name.  That way you can just have something like
	 *  "/var/console/&" for each of the conserver.cf entries.
	 */
	if (pcLog[0] == '&' && pcLog[1] == '\000' &&
	    logDirectory->used > 1) {
	    /* special case where logfile name is '&' and the LOGDIR was
	     * seen above.  in this case we just allow inheritance to
	     * work it's magic.
	     */
	} else if (pcLog[0] == '\000') {
	    printf("\tlogfile \"\";\n");
	} else {
	    STRING *lfile;
	    lfile = AllocString();
	    BuildString((char *)0, lfile);
	    pcStart = pcLog;
	    BuildString(pcStart, lfile);
	    if (logDirectory->used > 1 && lfile->used > 1 &&
		lfile->string[0] != '/') {
		char *p;
		BuildTmpString((char *)0);
		p = BuildTmpString(lfile->string);
		BuildString((char *)0, lfile);
		BuildString(logDirectory->string, lfile);
		BuildStringChar('/', lfile);
		BuildString(p, lfile);
		BuildTmpString((char *)0);
	    }
	    printf("\tlogfile %s;\n", lfile->string);
	    DestroyString(lfile);
	}

	if (pcMark) {
	    printf("\ttimestamp %s;\n", pcMark);
	}

	if (pcBreak) {
	    int bt;
	    bt = atoi(pcBreak);
	    if (bt > 9 || bt < 0) {
		Error("%s(%d) bad break spec `%d'", pcFile, iLine, bt);
	    } else {
		printf("\tbreak %d;\n", bt);
	    }
	}

	if (pcLine[0] == '!') {
	    pcLine = PruneSpace(pcLine + 1);
	    printf("\ttype host;\n");
	    printf("\thost %s;\n", pcLine);
	    printf("\tport %s;\n", pcMode);
	} else if ('|' == pcLine[0]) {
	    pcLine = PruneSpace(pcLine + 1);
	    printf("\ttype exec;\n");
	    if (pcLine == (char *)0 || pcLine[0] == '\000')
		printf("\texec \"\";\n");
	    else
		printf("\texec %s;\n", pcLine);
	} else {
	    char p, *t;
	    printf("\ttype device;\n");
	    printf("\tdevice %s;\n", pcLine);
	    t = pcMode;
	    while (isdigit((int)(*t))) {
		++t;
	    }
	    p = *t;
	    *t = '\000';
	    printf("\tbaud %s;\n", pcMode);
	    switch (p) {
		case 'E':
		case 'e':
		    t = "even";
		    break;
		case 'M':
		case 'm':
		    t = "mark";
		    break;
		case 'N':
		case 'n':
		case 'P':
		case 'p':
		    t = "none";
		    break;
		case 'O':
		case 'o':
		    t = "odd";
		    break;
		case 'S':
		case 's':
		    t = "space";
		    break;
		default:
		    Error
			("%s(%d) unknown parity type `%c' - assuming `none'",
			 pcFile, iLine, p);
		    t = "none";
		    break;
	    }
	    printf("\tparity %s;\n", t);
	}
	printf("}\n");
    }

    while ((acIn =
	    (unsigned char *)ReadLine2(fp, acInSave,
				       &iLine)) != (unsigned char *)0) {
	char *pcNext;
	char cType;

	acStart = PruneSpace((char *)acIn);
	if (acStart[0] == '#') {
	    printf("%s\n", acStart);
	    continue;
	}

	if ('%' == acStart[0] && '%' == acStart[1] && '\000' == acStart[2]) {
	    break;
	}
	if ((char *)0 == (pcNext = strchr(acStart, ':'))) {
	    Error("%s(%d) missing colon?", pcFile, iLine);
	    continue;
	}

	do {
	    *pcNext++ = '\000';
	} while (isspace((int)(*pcNext)));

	switch (acStart[0]) {
	    case 'a':		/* allowed, allow, allows       */
	    case 'A':
		if (!sawACL) {
		    sawACL = 1;
		    printf("access * {\n");
		}
		printf("\tallowed %s;\n", pcNext);
		break;
	    case 'r':		/* rejected, refused, refuse    */
	    case 'R':
		if (!sawACL) {
		    sawACL = 1;
		    printf("access * {\n");
		}
		printf("\trejected %s;\n", pcNext);
		break;
	    case 't':		/* trust, trusted, trusts       */
	    case 'T':
		if (!sawACL) {
		    sawACL = 1;
		    printf("access * {\n");
		}
		printf("\ttrusted %s;\n", pcNext);
		break;
	    default:
		cType = ' ';
		Error("%s(%d) unknown access key `%s'", pcFile, iLine,
		      acStart);
		break;
	}
    }
    if (sawACL) {
	printf("}\n");
    }
}

int
#if PROTOTYPES
main(int argc, char **argv)
#else
main(argc, argv)
    int argc;
    char **argv;
#endif
{
    char *pcFile;
    FILE *fp;

    progname = "convert";
    fDebug = 0;


    if (argc != 2) {
	Error("Usage: convert old-conserver.cf");
	return 1;
    }

    pcFile = argv[1];
    if ((fp = fopen(pcFile, "r")) == (FILE *)0) {
	Error("fopen(%s): %s", pcFile, strerror(errno));
	return 1;
    }

    ReadCfg(pcFile, fp);
    return 0;
}
