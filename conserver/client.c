/*
 *  $Id: client.c,v 5.80 2004/03/10 02:55:45 bryan Exp $
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

#include <compat.h>

#include <cutil.h>
#include <consent.h>
#include <access.h>
#include <client.h>
#include <group.h>

#if defined(USE_LIBWRAP)
#include <syslog.h>
#include <tcpd.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif


/* find the next guy who wants to write on the console			(ksb)
 */
void
#if PROTOTYPES
FindWrite(CONSENT *pCE)
#else
FindWrite(pCE)
    CONSENT *pCE;
#endif
{
    CONSCLIENT *pCL;

    /* make the first guy to have the `want write' bit set the writer
     * (tell him of the promotion, too)  we could look for the
     * most recent or some such... I guess it doesn't matter that
     * much.
     */
    if (pCE->pCLwr != (CONSCLIENT *)0 || pCE->fronly ||
	!(pCE->fup && pCE->ioState == ISNORMAL &&
	  pCE->initfile == (CONSFILE *)0))
	return;

    for (pCL = pCE->pCLon; (CONSCLIENT *)0 != pCL; pCL = pCL->pCLnext) {
	if (!pCL->fwantwr || pCL->fro)
	    continue;
	pCL->fwantwr = 0;
	pCL->fwr = 1;
	if (pCE->nolog) {
	    FileWrite(pCL->fd, FLAGFALSE, "\r\n[attached (nologging)]\r\n",
		      -1);
	} else {
	    FileWrite(pCL->fd, FLAGFALSE, "\r\n[attached]\r\n", -1);
	}
	TagLogfileAct(pCE, "%s attached", pCL->acid->string);
	pCE->pCLwr = pCL;
	return;
    }
}

/* replay last iBack lines of the log file upon connect to console	(ksb)
 *
 * NB: we know the console might be spewing when the replay happens,
 * we want to just output what is in the log file and get out,
 * so we don't drop chars...
 */
void
#if PROTOTYPES
Replay(CONSENT *pCE, CONSFILE *fdOut, int iBack)
#else
Replay(pCE, fdOut, iBack)
    CONSENT *pCE;
    CONSFILE *fdOut;
    int iBack;
#endif
{
    CONSFILE *fdLog = (CONSFILE *)0;
    off_t file_pos;
    off_t buf_pos;
    char *buf;
    char *bp = (char *)0;
    char *s;
    int r;
    int ch;
    struct stat stLog;
    struct lines {
	int is_mark;
	STRING *line;
	STRING *mark_end;
    } *lines;
    int n_lines;
    int ln;
    int i;
    int j;
    int u;
    int is_mark;
    char dummy[4];
#if HAVE_DMALLOC && DMALLOC_MARK_REPLAY
    unsigned long dmallocMarkReplay = 0;
#endif

    if (pCE != (CONSENT *)0) {
	fdLog = pCE->fdlog;

	/* no logfile and down and logfile defined?  try and open it */
	if (fdLog == (CONSFILE *)0 && !pCE->fup &&
	    pCE->logfile != (char *)0)
	    fdLog = FileOpen(pCE->logfile, O_RDONLY, 0644);
    }

    if (fdLog == (CONSFILE *)0) {
	FileWrite(fdOut, FLAGFALSE, "[no log file on this console]\r\n",
		  -1);
	return;
    }

    /* find the size of the file
     */
    if (0 != FileStat(fdLog, &stLog)) {
	return;
    }
#if HAVE_DMALLOC && DMALLOC_MARK_REPLAY
    dmallocMarkReplay = dmalloc_mark();
#endif

    file_pos = stLog.st_size - 1;
    buf_pos = file_pos + 1;

    /* get space for the line information and initialize it
     *
     * we allocate room for one more line than requested to be able to
     * do the mark ranges
     */
    if ((char *)0 == (buf = malloc(BUFSIZ))) {
	OutOfMem();
    }
    n_lines = iBack + 1;
    lines = (struct lines *)calloc(n_lines, sizeof(*lines));
    if ((struct lines *)0 == lines) {
	OutOfMem();
    }
    for (i = 0; i < n_lines; i++) {
	lines[i].mark_end = AllocString();
	lines[i].line = AllocString();
    }
    ln = -1;

    /* loop as long as there is data in the file or we have not found
     * the requested number of lines
     */
    while (file_pos >= 0) {
	if (file_pos < buf_pos) {

	    /* read one buffer worth of data a buffer boundary
	     *
	     * the first read will probably not get a full buffer but
	     * the rest (as we work our way back in the file) should be
	     */
	    buf_pos = (file_pos / BUFSIZ) * BUFSIZ;
	    if (FileSeek(fdLog, buf_pos, SEEK_SET) < 0) {
		goto common_exit;
	    }
	    if ((r = FileRead(fdLog, buf, BUFSIZ)) < 0) {
		goto common_exit;
	    }
	    bp = buf + r;
	}

	/* process the next character
	 */
	--file_pos;
	if ((ch = *--bp) == '\n') {
	    if (ln >= 0) {

		/* reverse the text to put it in forward order
		 */
		u = lines[ln].line->used - 1;
		for (i = 0; i < u / 2; i++) {
		    int temp;

		    temp = lines[ln].line->string[i];
		    lines[ln].line->string[i]
			= lines[ln].line->string[u - i - 1];
		    lines[ln].line->string[u - i - 1] = temp;
		}

		/* see if this line is a MARK
		 */
		if (lines[ln].line->used > 0 &&
		    lines[ln].line->string[0] == '[') {
		    i = sscanf(lines[ln].line->string + 1,
			       "-- MARK -- %3c %3c %d %d:%d:%d %d]\r\n",
			       dummy, dummy, &j, &j, &j, &j, &j);
		    is_mark = (i == 7);
		} else {
		    is_mark = 0;
		}

		/* process this line
		 */
		if (is_mark && ln > 0 && lines[ln - 1].is_mark) {
		    /* this is a mark and the previous line is also
		     * a mark, so make (or continue) that range
		     */
		    if (0 == lines[ln - 1].mark_end->allocated) {
			/* this is a new range - shuffle pointers
			 *
			 * remember that we are moving backward
			 */
			*(lines[ln - 1].mark_end) = *(lines[ln - 1].line);
			InitString(lines[ln - 1].line);
		    }
		    /* if unallocated, cheat and shuffle pointers */
		    if (0 == lines[ln - 1].line->allocated) {
			*(lines[ln - 1].line) = *(lines[ln].line);
			InitString(lines[ln].line);
		    } else {
			BuildString((char *)0, lines[ln - 1].line);
			BuildStringN(lines[ln].line->string,
				     lines[ln].line->used - 1,
				     lines[ln - 1].line);
			BuildString((char *)0, lines[ln].line);
		    }
		    ln--;
		}
		lines[ln].is_mark = is_mark;
	    }

	    /* advance to the next line and break if we have enough
	     */
	    ln++;
	    if (ln >= n_lines - 1) {
		break;
	    }
	}

	/* if we have a character but no lines yet, the last text in the
	 * file does not end with a newline, so start the first line anyway
	 */
	if (ln < 0) {
	    ln = 0;
	}
	BuildStringChar(ch, lines[ln].line);

	/* if we've processed "a lot" of data for a line, then bail
	 * why?  there must be some very long non-newline terminated
	 * strings and if we just keep going back, we could spew lots
	 * of data and chew up lots of memory
	 */
	if (lines[ln].line->used > MAXREPLAYLINELEN) {
	    break;
	}
    }
    free(buf);
    buf = (char *)0;

    /* if we got back to beginning of file but saw some data, include it
     */
    if (ln >= 0 && lines[ln].line->used > 0) {

	/* reverse the text to put it in forward order
	 */
	u = lines[ln].line->used - 1;
	for (i = 0; i < u / 2; i++) {
	    int temp;

	    temp = lines[ln].line->string[i];
	    lines[ln].line->string[i]
		= lines[ln].line->string[u - i - 1];
	    lines[ln].line->string[u - i - 1] = temp;
	}
	ln++;
    }

    /* copy the lines into the buffer and put them in order
     */
    for (i = ln - 1; i >= 0; i--) {
	if (lines[i].is_mark && 0 != lines[i].mark_end->used) {
	    int mark_len;

	    /* output the start of the range, stopping at the ']'
	     */
	    s = strrchr(lines[i].line->string, ']');
	    if ((char *)0 != s) {
		*s = '\000';
	    }
	    FileWrite(fdOut, FLAGTRUE, lines[i].line->string,
		      lines[i].line->used - 1);
	    FileWrite(fdOut, FLAGTRUE, " .. ", 4);

	    /* build the end string by removing the leading "[-- MARK -- "
	     * and replacing "]\r\n" on the end with " -- MARK --]\r\n"
	     */
	    mark_len = sizeof("[-- MARK -- ") - 1;

	    s = strrchr(lines[i].mark_end->string + mark_len, ']');
	    if ((char *)0 != s) {
		*s = '\000';
	    }
	    FileWrite(fdOut, FLAGTRUE,
		      lines[i].mark_end->string + mark_len, -1);
	    FileWrite(fdOut, FLAGFALSE, " -- MARK --]\r\n", -1);
	    u = lines[i].mark_end->used;
	    s = lines[i].mark_end->string;
	} else
	    FileWrite(fdOut, FLAGFALSE, lines[i].line->string,
		      lines[i].line->used - 1);
    }

  common_exit:

    /* if we opened the logfile, close it */
    if (fdLog != pCE->fdlog)
	FileClose(&fdLog);

    if ((struct lines *)0 != lines) {
	for (i = 0; i < n_lines; i++) {
	    DestroyString(lines[i].mark_end);
	    DestroyString(lines[i].line);
	}
	free(lines);
	lines = (struct lines *)0;
    }
    if ((char *)0 != buf) {
	free(buf);
	buf = (char *)0;
    }
#if HAVE_DMALLOC && DMALLOC_MARK_REPLAY
    CONDDEBUG((1, "Replay(): dmalloc / MarkReplay"));
    dmalloc_log_changed(dmallocMarkReplay, 1, 0, 1);
#endif
}


/* these bit tell us which parts of the Truth to tell the client	(ksb)
 */
#define WHEN_SPY	0x01
#define WHEN_ATTACH	0x02
#define WHEN_EXPERT	0x04	/* ZZZ no way to set his yet    */
#define WHEN_ALWAYS	0x40

#define HALFLINE	40

typedef struct HLnode {
    int iwhen;
    char *actext;
} HELP;

static HELP aHLTable[] = {
    {WHEN_ALWAYS, ".    disconnect"},
    {WHEN_ALWAYS, ";    switch to another console"},
    {WHEN_ALWAYS, "a    attach read/write"},
    {WHEN_ALWAYS, "b    send broadcast message"},
    {WHEN_ATTACH, "c    toggle flow control"},
    {WHEN_ATTACH, "d    down a console"},
    {WHEN_ALWAYS, "e    change escape sequence"},
    {WHEN_ALWAYS, "f    force attach read/write"},
    {WHEN_ALWAYS, "g    group info"},
    {WHEN_ALWAYS, "i    information dump"},
    {WHEN_ATTACH, "L    toggle logging on/off"},
    {WHEN_ATTACH, "l?   break sequence list"},
    {WHEN_ATTACH, "l0   send break per config file"},
    {WHEN_ATTACH, "l1-9 send specific break sequence"},
    {WHEN_ALWAYS, "m    display the message of the day"},
    {WHEN_ALWAYS, "o    (re)open the tty and log file"},
    {WHEN_ALWAYS, "p    replay the last 60 lines"},
    {WHEN_ALWAYS, "r    replay the last 20 lines"},
    {WHEN_ATTACH, "s    spy read only"},
    {WHEN_ALWAYS, "u    show host status"},
    {WHEN_ALWAYS, "v    show version info"},
    {WHEN_ALWAYS, "w    who is on this console"},
    {WHEN_ALWAYS, "x    show console baud info"},
    {WHEN_ALWAYS, "z    suspend the connection"},
    {WHEN_ATTACH, "|    attach local command"},
    {WHEN_ALWAYS, "?    print this message"},
    {WHEN_ALWAYS, "<cr> ignore/abort command"},
    {WHEN_ALWAYS, "^R   replay the last line"},
    {WHEN_ATTACH, "\\ooo send character by octal code"},
    {WHEN_EXPERT, "^I   toggle tab expansion"},
    {WHEN_EXPERT, "+(-) do (not) drop line"},
};

/* list the commands we know for the user				(ksb)
 */
void
#if PROTOTYPES
HelpUser(CONSCLIENT *pCL)
#else
HelpUser(pCL)
    CONSCLIENT *pCL;
#endif
{
    int i, j, iCmp;
    static char
      acH1[] = "help]\r\n", acH2[] = "help spy mode]\r\n", acEoln[] =
	"\r\n";
    static STRING *acLine = (STRING *)0;

    if (acLine == (STRING *)0)
	acLine = AllocString();

    iCmp = WHEN_ALWAYS | WHEN_SPY;
    if (pCL->fwr) {
	FileWrite(pCL->fd, FLAGTRUE, acH1, sizeof(acH1) - 1);
	iCmp |= WHEN_ATTACH;
    } else {
	FileWrite(pCL->fd, FLAGTRUE, acH2, sizeof(acH2) - 1);
    }

    BuildString((char *)0, acLine);
    for (i = 0; i < sizeof(aHLTable) / sizeof(HELP); ++i) {
	if (0 == (aHLTable[i].iwhen & iCmp)) {
	    continue;
	}
	if (acLine->used != 0) {	/* second part of line */
	    if (strlen(aHLTable[i].actext) < HALFLINE) {
		for (j = acLine->used; j <= HALFLINE; ++j) {
		    BuildStringChar(' ', acLine);
		}
		BuildString(aHLTable[i].actext, acLine);
		BuildString(acEoln, acLine);
		FileWrite(pCL->fd, FLAGTRUE, acLine->string,
			  acLine->used - 1);
		BuildString((char *)0, acLine);
		continue;
	    } else {
		BuildString(acEoln, acLine);
		FileWrite(pCL->fd, FLAGTRUE, acLine->string,
			  acLine->used - 1);
		BuildString((char *)0, acLine);
	    }
	}
	if (acLine->used == 0) {	/* at new line */
	    BuildStringChar(' ', acLine);
	    BuildString(aHLTable[i].actext, acLine);
	    if (acLine->used > HALFLINE) {
		BuildString(acEoln, acLine);
		FileWrite(pCL->fd, FLAGTRUE, acLine->string,
			  acLine->used - 1);
		BuildString((char *)0, acLine);
	    }
	}
    }
    if (acLine->used != 0) {
	BuildString(acEoln, acLine);
	FileWrite(pCL->fd, FLAGTRUE, acLine->string, acLine->used - 1);
    }
    FileWrite(pCL->fd, FLAGFALSE, (char *)0, 0);
}

int
#if PROTOTYPES
ClientAccessOk(CONSCLIENT *pCL)
#else
ClientAccessOk(pCL)
    CONSCLIENT *pCL;
#endif
{
    char *peername = (char *)0;
    socklen_t so;
    int cfd;
    struct sockaddr_in in_port;
    int retval = 1;
    int getpeer = -1;

    cfd = FileFDNum(pCL->fd);
    pCL->caccess = 'r';
#if defined(USE_LIBWRAP)
    {
	struct request_info request;
	request_init(&request, RQ_DAEMON, progname, RQ_FILE, cfd, 0);
	fromhost(&request);
	if (!hosts_access(&request)) {
	    FileWrite(pCL->fd, FLAGFALSE,
		      "access from your host refused\r\n", -1);
	    retval = 0;
	    goto setpeer;
	}
    }
#endif

    so = sizeof(in_port);
    if (-1 ==
	(getpeer = getpeername(cfd, (struct sockaddr *)&in_port, &so))) {
	FileWrite(pCL->fd, FLAGFALSE, "getpeername failed\r\n", -1);
	retval = 0;
	goto setpeer;
    }
    pCL->caccess = AccType(&in_port.sin_addr, &peername);
    if (pCL->caccess == 'r') {
	FileWrite(pCL->fd, FLAGFALSE, "access from your host refused\r\n",
		  -1);
	retval = 0;
    }

  setpeer:
    if (pCL->peername != (STRING *)0) {
	BuildString((char *)0, pCL->peername);
	if (peername != (char *)0)
	    BuildString(peername, pCL->peername);
	else if (getpeer != -1)
	    BuildString(inet_ntoa(in_port.sin_addr), pCL->peername);
	else
	    BuildString("<unknown>", pCL->peername);
    }
    if (peername != (char *)0)
	free(peername);
    return retval;
}
