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
/*
 * Network console modifications by Robert Olson, olson@mcs.anl.gov.
 */

#include <compat.h>

#include "cutil.h"
#include "consent.h"
#include "client.h"
#include "group.h"
#include "access.h"
#include "readcfg.h"
#include "master.h"
#include "main.h"

#if defined(USE_LIBWRAP)
/* we don't use it...but we link to it */
int allow_severity;
int deny_severity;
#endif


SECTION sections[] = {
    {NULL, NULL, NULL, NULL, NULL}
};

void
DestroyDataStructures(void)
{
}

char *
ReadLine2(FILE *fp, STRING *save, int *iLine)
{
    static char buf[1024];
    char *wholeline = NULL;
    char *ret = NULL;
    int i, buflen, peek, commentCheck = 1;
    static STRING *bufstr = NULL;
    static STRING *wholestr = NULL;

    if (bufstr == NULL)
	bufstr = AllocString();
    if (wholestr == NULL)
	wholestr = AllocString();
    peek = 0;
    wholeline = NULL;
    BuildString(NULL, bufstr);
    BuildString(NULL, wholestr);
    while (save->used || ((ret = fgets(buf, sizeof(buf), fp)) != NULL)
	   || peek) {
	/* If we have a previously saved line, use it instead */
	if (save->used) {
	    StrCpy(buf, save->string, sizeof(buf));
	    BuildString(NULL, save);
	}

	if (peek) {
	    /* End of file?  Never mind. */
	    if (ret == NULL)
		break;

	    /* If we don't have a line continuation and we've seen
	     * some worthy data
	     */
	    if (!isspace((int)buf[0]) && (wholeline != NULL)) {
		BuildString(NULL, save);
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
		commentCheck = 0;
	    } else if (buf[i] != '\000') {
		commentCheck = 0;
	    }
	}

	/* Check for EOL */
	buflen = strlen(buf);
	if ((buflen >= 1) && (buf[buflen - 1] == '\n')) {
	    (*iLine)++;		/* Finally have a whole line */
	    /* Finish off the chunk without the \n */
	    buf[buflen - 1] = '\000';
	    BuildString(buf, bufstr);
	    wholeline = BuildString(bufstr->string, wholestr);
	    peek = 1;
	    commentCheck = 1;
	    BuildString(NULL, bufstr);
	} else {
	    /* Save off the partial chunk */
	    BuildString(buf, bufstr);
	}
    }

    /* If we hit the EOF and weren't peeking ahead
     * and it's not a comment
     */
    if (!peek && (ret == NULL)) {
	(*iLine)++;
	wholeline = BuildString(bufstr->string, wholestr);
	if (wholeline != NULL && wholeline[0] == '\000')
	    wholeline = NULL;
    }

    CONDDEBUG((1, "ReadLine2(): returning <%s>",
	       (wholeline != NULL) ? wholeline : "<NULL>"));
    return wholeline;
}

/* read in the configuration file, fill in all the structs we use	(ksb)
 * to manage the consoles
 */
void
ReadCfg(char *pcFile, FILE *fp)
{
    int iLine;
    unsigned char *acIn;
    static STRING *acInSave = NULL;
    char *acStart;
    static STRING *logDirectory = NULL;
    static STRING *defMark = NULL;
    int sawACL = 0;
    int printedFull = 0;

    if (defMark == NULL)
	defMark = AllocString();
    if (logDirectory == NULL)
	logDirectory = AllocString();
    if (acInSave == NULL)
	acInSave = AllocString();
    BuildString(NULL, defMark);
    BuildString(NULL, acInSave);
    BuildString(NULL, logDirectory);

    iLine = 0;
    while ((acIn =
	    (unsigned char *)ReadLine2(fp, acInSave,
				       &iLine)) != NULL) {
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
	if (NULL != (pcLine = strchr(acStart, '=')) &&
	    (NULL == (pcColon = strchr(acStart, ':')) ||
	     pcColon > pcLine)) {
	    *pcLine++ = '\000';
	    acStart = PruneSpace(acStart);
	    pcLine = PruneSpace(pcLine);
	    if (0 == strcmp(acStart, "LOGDIR")) {
		BuildString(NULL, logDirectory);
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
		BuildString(NULL, defMark);
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
		    BuildTmpString(NULL);
		    while ((q = strchr(p, '"')) != NULL) {
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
	if (NULL == (pcLine = strchr(acStart, ':')) ||
	    NULL == (pcMode = strchr(pcLine + 1, ':')) ||
	    NULL == (pcLog = strchr(pcMode + 1, ':'))) {
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

	if (NULL != (pcMark = strchr(pcLog, ':'))) {
	    *pcMark++ = '\000';
	    pcLog = PruneSpace(pcLog);
	    pcMark = PruneSpace(pcMark);
	    /* Skip null intervals */
	    if (pcMark[0] == '\000')
		pcMark = NULL;
	}

	if (NULL == pcMark) {
	    pcBreak = NULL;
	} else {
	    if (NULL != (pcBreak = strchr(pcMark, ':'))) {
		*pcBreak++ = '\000';
		pcMark = PruneSpace(pcMark);
		pcBreak = PruneSpace(pcBreak);
		/* Ignore null specs */
		if (pcMark[0] == '\000')
		    pcMark = NULL;
		if (pcBreak[0] == '\000')
		    pcBreak = NULL;
	    }
	}

	if (NULL != (pcRem = strchr(pcLine, '@'))) {
	    *pcRem++ = '\000';
	    pcLine = PruneSpace(pcLine);
	    pcRem = PruneSpace(pcRem);
	}

	printf("console %s {\n", acStart);
	if (pcRem == NULL) {
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
	    BuildString(NULL, lfile);
	    pcStart = pcLog;
	    BuildString(pcStart, lfile);
	    if (logDirectory->used > 1 && lfile->used > 1 &&
		lfile->string[0] != '/') {
		char *p;
		BuildTmpString(NULL);
		p = BuildTmpString(lfile->string);
		BuildString(NULL, lfile);
		BuildString(logDirectory->string, lfile);
		BuildStringChar('/', lfile);
		BuildString(p, lfile);
		BuildTmpString(NULL);
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
	    if (pcLine == NULL || pcLine[0] == '\000')
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
				       &iLine)) != NULL) {
	char *pcNext;

	acStart = PruneSpace((char *)acIn);
	if (acStart[0] == '#') {
	    printf("%s\n", acStart);
	    continue;
	}

	if ('%' == acStart[0] && '%' == acStart[1] && '\000' == acStart[2]) {
	    break;
	}
	if (NULL == (pcNext = strchr(acStart, ':'))) {
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
main(int argc, char **argv)
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
    if ((fp = fopen(pcFile, "r")) == NULL) {
	Error("fopen(%s): %s", pcFile, strerror(errno));
	return 1;
    }

    ReadCfg(pcFile, fp);
    return 0;
}
