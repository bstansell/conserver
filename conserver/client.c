/*
 *  $Id: client.c,v 5.40 2002-01-21 02:48:33-08 bryan Exp $
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

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>

#include <compat.h>
#include <port.h>
#include <util.h>

#include <consent.h>
#include <client.h>
#include <group.h>


/* find the next guy who wants to write on the console			(ksb)
 */
CONSCLIENT *
FindWrite(pCL)
    CONSCLIENT *pCL;
{
    /* return the first guy to have the `want write' bit set
     * (tell him of the promotion, too)  we could look for the
     * most recent or some such... I guess it doesn't matter that
     * much.
     */
    for ( /*passed in */ ; (CONSCLIENT *) 0 != pCL; pCL = pCL->pCLnext) {
	if (!pCL->fwantwr)
	    continue;
	if (!pCL->pCEto->fup || pCL->pCEto->fronly)
	    break;
	pCL->fwantwr = 0;
	pCL->fwr = 1;
	if (pCL->pCEto->nolog) {
	    fileWrite(pCL->fd, "\r\n[attached (nologging)]\r\n", -1);
	} else {
	    fileWrite(pCL->fd, "\r\n[attached]\r\n", -1);
	}
	tagLogfile(pCL->pCEto, "%s attached", pCL->acid);
	return pCL;
    }
    return (CONSCLIENT *) 0;
}

/* show a character as a string so the user cannot mistake it for	(ksb)
 * another
 * 
 * must pass us at least 16 characters to put fill with text
 */
char *
FmtCtl(ci, pcIn)
    int ci;
    char *pcIn;
{
    char *pcOut = pcIn;
    unsigned char c;

    c = ci & 0xff;
    if (c > 127) {
	c -= 128;
	*pcOut++ = 'M';
	*pcOut++ = '-';
    }

    if (c < ' ' || c == '\177') {
	*pcOut++ = '^';
	*pcOut++ = c ^ 0100;
	*pcOut = '\000';
    } else if (c == ' ') {
	(void)strcpy(pcOut, "<space>");
    } else if (c == '^') {
	(void)strcpy(pcOut, "<circumflex>");
    } else if (c == '\\') {
	(void)strcpy(pcOut, "<backslash>");
    } else {
	*pcOut++ = c;
	*pcOut = '\000';
    }
    return pcIn;
}

/* replay last iBack lines of the log file upon connect to console	(ksb)
 *
 * NB: we know the console might be spewing when the replay happens,
 * we want to just output what is in the log file and get out,
 * so we don't drop chars...
 */
void
Replay(fdLog, fdOut, iBack)
    CONSFILE *fdLog;
    CONSFILE *fdOut;
    int iBack;
{

    off_t file_pos;
    off_t buf_pos;
    char *buf;
    char *bp;
    char *s;
    int r;
    int ch;
    struct stat stLog;
    struct lines {
	int is_mark;
	STRING line;
	STRING mark_end;
    } *lines;
    int n_lines;
    int ln;
    int i;
    int j;
    int u;
    int is_mark;
    char dummy[4];

    if ((CONSFILE *) 0 == fdLog) {
	fileWrite(fdOut, "[no log file on this console]\r\n", -1);
	return;
    }

    /* find the size of the file
     */
    if (0 != fileStat(fdLog, &stLog)) {
	return;
    }
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
#if defined(SEEK_SET)
	    /* PTX and maybe other Posix systems
	     */
	    if (fileSeek(fdLog, buf_pos, SEEK_SET) < 0) {
		goto common_exit;
	    }
#else
	    if (fileSeek(fdLog, buf_pos, L_SET) < 0) {
		goto common_exit;
	    }
#endif
	    if ((r = fileRead(fdLog, buf, BUFSIZ)) <= 0) {
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
		u = lines[ln].line.used - 1;
		for (i = 0; i < u / 2; i++) {
		    int temp;

		    temp = lines[ln].line.string[i];
		    lines[ln].line.string[i]
			= lines[ln].line.string[u - i - 1];
		    lines[ln].line.string[u - i - 1] = temp;
		}

		/* see if this line is a MARK
		 */
		if (lines[ln].line.used > 0 &&
		    lines[ln].line.string[0] == '[') {
		    i = sscanf(lines[ln].line.string + 1,
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
		    if (0 == lines[ln - 1].mark_end.allocated) {
			/* this is a new range - shuffle pointers
			 *
			 * remember that we are moving backward
			 */
			lines[ln - 1].mark_end = lines[ln - 1].line;
			lines[ln - 1].line.string = (char *)0;
			lines[ln - 1].line.used = 0;
			lines[ln - 1].line.allocated = 0;
		    }
		    /* if unallocated, cheat and shuffle pointers */
		    if (0 == lines[ln - 1].line.allocated) {
			lines[ln - 1].line = lines[ln].line;
			lines[ln].line.string = (char *)0;
			lines[ln].line.used = 0;
			lines[ln].line.allocated = 0;
		    } else {
			buildMyString((char *)0, &lines[ln - 1].line);
			buildMyString(lines[ln].line.string,
				      &lines[ln - 1].line);
			buildMyString((char *)0, &lines[ln].line);
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
	(void)buildMyStringChar(ch, &lines[ln].line);

	/* if we've processed "a lot" of data for a line, then bail
	 * why?  there must be some very long non-newline terminated
	 * strings and if we just keep going back, we could spew lots
	 * of data and chew up lots of memory
	 */
	if (lines[ln].line.used > MAXREPLAYLINELEN) {
	    break;
	}
    }
    free(buf);
    buf = (char *)0;

    /* if we got back to beginning of file but saw some data, include it
     */
    if (ln >= 0 && lines[ln].line.used > 0) {

	/* reverse the text to put it in forward order
	 */
	u = lines[ln].line.used - 1;
	for (i = 0; i < u / 2; i++) {
	    int temp;

	    temp = lines[ln].line.string[i];
	    lines[ln].line.string[i]
		= lines[ln].line.string[u - i - 1];
	    lines[ln].line.string[u - i - 1] = temp;
	}
	ln++;
    }

    /* copy the lines into the buffer and put them in order
     */
    for (i = ln - 1; i >= 0; i--) {
	if (lines[i].is_mark && 0 != lines[i].mark_end.used) {
	    int mark_len;

	    /* output the start of the range, stopping at the ']'
	     */
	    s = strrchr(lines[i].line.string, ']');
	    if ((char *)0 != s) {
		*s = '\000';
	    }
	    (void)fileWrite(fdOut, lines[i].line.string, -1);
	    (void)fileWrite(fdOut, " .. ", -1);

	    /* build the end string by removing the leading "[-- MARK -- "
	     * and replacing "]\r\n" on the end with " -- MARK --]\r\n"
	     */
	    mark_len = sizeof("[-- MARK -- ") - 1;

	    s = strrchr(lines[i].mark_end.string + mark_len, ']');
	    if ((char *)0 != s) {
		*s = '\000';
	    }
	    (void)fileWrite(fdOut, lines[i].mark_end.string + mark_len,
			    -1);
	    (void)fileWrite(fdOut, " -- MARK --]\r\n", -1);
	    u = lines[i].mark_end.used;
	    s = lines[i].mark_end.string;
	} else
	    (void)fileWrite(fdOut, lines[i].line.string, -1);
    }

  common_exit:

    if ((struct lines *)0 != lines) {
	for (i = 0; i < n_lines; i++) {
	    if ((char *)0 != lines[i].mark_end.string) {
		free(lines[i].mark_end.string);
		lines[i].mark_end.string = (char *)0;
		lines[i].mark_end.used = 0;
		lines[i].mark_end.allocated = 0;
	    }
	    if ((char *)0 != lines[i].line.string) {
		free(lines[i].line.string);
		lines[i].line.string = (char *)0;
		lines[i].line.used = 0;
		lines[i].line.allocated = 0;
	    }
	}
	free(lines);
	lines = (struct lines *)0;
    }
    if ((char *)0 != buf) {
	free(buf);
	buf = (char *)0;
    }
}


/* these bit tell us which parts of the Truth to tell the client	(ksb)
 */
#define WHEN_SPY	0x01
#define WHEN_ATTACH	0x02
#define WHEN_VT100	0x04
#define WHEN_EXPERT	0x08	/* ZZZ no way to set his yet    */
#define WHEN_ALWAYS	0x40

#define HALFLINE	40
typedef struct HLnode {
    int iwhen;
    char actext[HALFLINE];
} HELP;

static HELP aHLTable[] = {
    {WHEN_ALWAYS, ".    disconnect"},
    {WHEN_ALWAYS, "a    attach read/write"},
    {WHEN_ATTACH, "c    toggle flow control"},
    {WHEN_ATTACH, "d    down a console"},
    {WHEN_ALWAYS, "e    change escape sequence"},
    {WHEN_ALWAYS, "f    force attach read/write"},
    {WHEN_ALWAYS, "g    group info"},
    {WHEN_ATTACH, "L    toggle logging on/off"},
    {WHEN_ATTACH, "l?   break sequence list"},
    {WHEN_ATTACH, "l0   send break per config file"},
    {WHEN_ATTACH, "l1-9 send specific break sequence"},
    {WHEN_ALWAYS, "o    (re)open the tty and log file"},
    {WHEN_ALWAYS, "p    replay the last 60 lines"},
    {WHEN_ALWAYS, "r    replay the last 20 lines"},
    {WHEN_ATTACH, "s    spy read only"},
    {WHEN_ALWAYS, "u    show host status"},
    {WHEN_ALWAYS, "v    show version info"},
    {WHEN_ALWAYS, "w    who is on this console"},
    {WHEN_ALWAYS, "x    show console baud info"},
    {WHEN_ALWAYS, "z    suspend the connection"},
    {WHEN_ALWAYS, "<cr> ignore/abort command"},
    {WHEN_ALWAYS, "?    print this message"},
    {WHEN_ALWAYS, "^R   short replay"},
    {WHEN_ATTACH, "\\ooo send character by octal code"},
    {WHEN_EXPERT, "^I   toggle tab expansion"},
    {WHEN_EXPERT, ";    change to another console"},
    {WHEN_EXPERT, "+(-) do (not) drop line"},
    {WHEN_VT100, "PF1  print this message"},
    {WHEN_VT100, "PF2  disconnect"},
    {WHEN_VT100, "PF3  replay the last 20 lines"},
    {WHEN_VT100, "PF4  spy read only"}
};

/* list the commands we know for the user				(ksb)
 */
void
HelpUser(pCL)
    CONSCLIENT *pCL;
{
    int i, j, iCmp;
    static char
      acH1[] = "help]\r\n", acH2[] = "help spy mode]\r\n", acEoln[] =
	"\r\n";
    char acLine[HALFLINE * 2 + 3];

    iCmp = WHEN_ALWAYS | WHEN_SPY;
    if (pCL->fwr) {
	(void)fileWrite(pCL->fd, acH1, sizeof(acH1) - 1);
	iCmp |= WHEN_ATTACH;
    } else {
	(void)fileWrite(pCL->fd, acH2, sizeof(acH2) - 1);
    }
    if ('\033' == pCL->ic[0] && 'O' == pCL->ic[1]) {
	iCmp |= WHEN_VT100;
    }

    acLine[0] = '\000';
    for (i = 0; i < sizeof(aHLTable) / sizeof(HELP); ++i) {
	if (0 == (aHLTable[i].iwhen & iCmp)) {
	    continue;
	}
	if ('\000' == acLine[0]) {
	    acLine[0] = ' ';
	    (void)strcpy(acLine + 1, aHLTable[i].actext);
	    continue;
	}
	for (j = strlen(acLine); j < HALFLINE + 1; ++j) {
	    acLine[j] = ' ';
	}
	(void)strcpy(acLine + j, aHLTable[i].actext);
	(void)strcat(acLine + j, acEoln);
	(void)fileWrite(pCL->fd, acLine, -1);
	acLine[0] = '\000';
    }
    if ('\000' != acLine[0]) {
	(void)strcat(acLine, acEoln);
	(void)fileWrite(pCL->fd, acLine, -1);
    }
}
