/*
 *  $Id: client.c,v 5.91 2007/04/02 18:18:58 bryan Exp $
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
#include <readcfg.h>

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
    if (pCE->pCLwr != (CONSCLIENT *)0 || pCE->fronly)
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

void
#if PROTOTYPES
BumpClient(CONSENT *pCE, char *message)
#else
BumpClient(pCE, message)
    CONSENT *pCE;
    char *message;
#endif
{
    if ((CONSCLIENT *)0 == pCE->pCLwr)
	return;

    if ((char *)0 != message)
	FileWrite(pCE->pCLwr->fd, FLAGFALSE, message, -1);
    pCE->pCLwr->fwantwr = 0;
    pCE->pCLwr->fwr = 0;
    pCE->pCLwr = (CONSCLIENT *)0;
}

/* replay last 'back' lines of the log file upon connect to console	(ksb)
 *
 * NB: we know the console might be spewing when the replay happens,
 * we want to just output what is in the log file and get out,
 * so we don't drop chars...
 */
#define REPLAYBUFFER 4096

void
#if PROTOTYPES
Replay(CONSENT *pCE, CONSFILE *fdOut, unsigned short back)
#else
Replay(pCE, fdOut, back)
    CONSENT *pCE;
    CONSFILE *fdOut;
    unsigned short back;
#endif
{
    CONSFILE *fdLog = (CONSFILE *)0;
    STRING *line = (STRING *)0;
    off_t file_pos;
    off_t buf_pos;
    char *buf;
    char *bp = (char *)0;
    int ch;
    struct stat stLog;
    int ln;
    int was_mark = 0;
#if HAVE_DMALLOC && DMALLOC_MARK_REPLAY
    unsigned long dmallocMarkReplay = 0;
#endif

    if (pCE != (CONSENT *)0 && pCE->logfile != (char *)0)
	fdLog = FileOpen(pCE->logfile, O_RDONLY, 0644);

    if (fdLog == (CONSFILE *)0) {
	FileWrite(fdOut, FLAGFALSE, "[no log file on this console]\r\n",
		  -1);
	return;
    }
#if HAVE_DMALLOC && DMALLOC_MARK_REPLAY
    dmallocMarkReplay = dmalloc_mark();
#endif

    /* find the size of the file
     */
    if (0 != FileStat(fdLog, &stLog))
	goto common_exit;

    file_pos = stLog.st_size - 1;	/* point at last byte */
    buf_pos = file_pos + 1;

    if ((char *)0 == (buf = malloc(REPLAYBUFFER)))
	OutOfMem();
    bp = buf + 1;		/* just give it something - it resets below */

    line = AllocString();

    /* loop as long as there is data in the file or we have not found
     * the requested number of lines
     */
    ln = -1;
    for (; file_pos >= 0; file_pos--, bp--) {
	if (file_pos < buf_pos) {
	    int r;

	    /* read one buffer worth of data a buffer boundary
	     *
	     * the first read will probably not get a full buffer but
	     * the rest (as we work our way back in the file) should be
	     */
	    buf_pos = (file_pos / REPLAYBUFFER) * REPLAYBUFFER;
	    if (FileSeek(fdLog, buf_pos, SEEK_SET) < 0) {
		goto common_exit;
	    }
	    if ((r = FileRead(fdLog, buf, REPLAYBUFFER)) < 0) {
		goto common_exit;
	    }
	    bp = buf + r - 1;
	}

	/* process the next character
	 */
	if ((ch = *bp) == '\n') {
	    if (ln >= 0) {
		int i;
		int u;
		int is_mark = 0;

		/* reverse the text to put it in forward order
		 */
		u = line->used - 1;
		for (i = 0; i < u / 2; i++) {
		    int temp;

		    temp = line->string[i];
		    line->string[i] = line->string[u - i - 1];
		    line->string[u - i - 1] = temp;
		}

		/* see if this line is a MARK
		 */
		if (line->used > 0 && line->string[0] == '[') {
		    char dummy[4];
		    int j;
		    i = sscanf(line->string + 1,
			       "-- MARK -- %3c %3c %d %d:%d:%d %d]\r\n",
			       dummy, dummy, &j, &j, &j, &j, &j);
		    is_mark = (i == 7);
		}

		/* process this line
		 */
		if (is_mark && was_mark) {
		    /* this is a mark and the previous line is also
		     * a mark, so reduce the line count 'cause it'll
		     * go up by one and we're joining them on output.
		     */
		    ln--;
		}
		was_mark = is_mark;
	    }

	    /* advance to the next line and break if we have enough
	     */
	    ln++;
	    BuildString((char *)0, line);
	    if (ln >= back) {
		break;
	    }
	}

	/* if we have a character but no lines yet, the last text in the
	 * file does not end with a newline, so start the first line anyway
	 */
	if (ln < 0) {
	    ln = 0;
	}
	BuildStringChar(ch, line);

	/* if we've processed "a lot" of data for a line, then bail
	 * why?  there must be some very long non-newline terminated
	 * strings and if we just keep going back, we could spew lots
	 * of data and chew up lots of memory
	 */
	if (line->used > MAXREPLAYLINELEN) {
	    break;
	}
    }

    /* move forward.  either we hit the beginning of the file and we
     * move to the first byte, or we hit a \n and we move past it
     */
    file_pos++;

    /* Now output the lines, starting from where we stopped */
    if (FileSeek(fdLog, file_pos, SEEK_SET) >= 0) {
	int eof = 0;
	int i = 0;
	int r = 0;
	STRING *mark_beg = (STRING *)0;
	STRING *mark_end = (STRING *)0;

	mark_beg = AllocString();
	mark_end = AllocString();

	ln = 0;			/* number of lines output */
	BuildString((char *)0, line);

	while (ln < back && !eof) {
	    if (r <= 0) {
		if ((r = FileRead(fdLog, buf, REPLAYBUFFER)) < 0)
		    eof = 1;
		i = 0;
	    }

	    if (!eof)
		BuildStringChar(buf[i], line);

	    if (buf[i] == '\n' || eof) {
		int is_mark = 0;
		if (line->used > 0 && line->string[0] == '[') {
		    char dummy[4];
		    int j;
		    int i;
		    i = sscanf(line->string + 1,
			       "-- MARK -- %3c %3c %d %d:%d:%d %d]\r\n",
			       dummy, dummy, &j, &j, &j, &j, &j);
		    is_mark = (i == 7);
		}
		if (is_mark) {
		    if (mark_beg->used > 1) {
			BuildString((char *)0, mark_end);
			BuildString(line->string, mark_end);
		    } else
			BuildString(line->string, mark_beg);
		} else {
		    if (mark_beg->used > 1) {
			if (mark_end->used > 1) {
			    char *s;

			    /* output the start of the range, stopping at the ']' */
			    s = strrchr(mark_beg->string, ']');
			    if ((char *)0 != s)
				*s = '\000';
			    FileWrite(fdOut, FLAGTRUE, mark_beg->string,
				      -1);
			    FileWrite(fdOut, FLAGTRUE, " .. ", 4);

			    /* build the end string by removing the leading "[-- MARK -- "
			     * and replacing "]\r\n" on the end with " -- MARK --]\r\n"
			     */
			    s = strrchr(mark_end->string, ']');
			    if ((char *)0 != s)
				*s = '\000';
			    FileWrite(fdOut, FLAGTRUE,
				      mark_end->string +
				      sizeof("[-- MARK -- ") - 1, -1);
			    FileWrite(fdOut, FLAGFALSE, " -- MARK --]\r\n",
				      -1);
			} else {
			    FileWrite(fdOut, FLAGFALSE, mark_beg->string,
				      mark_beg->used - 1);
			}
			BuildString((char *)0, mark_beg);
			BuildString((char *)0, mark_end);
			ln++;
			if (ln >= back)
			    break;
		    }
		    FileWrite(fdOut, FLAGFALSE, line->string,
			      line->used - 1);
		    ln++;
		}
		BuildString((char *)0, line);
	    }

	    /* move the counters */
	    i++;
	    r--;
	}
	DestroyString(mark_end);
	DestroyString(mark_beg);
    }

  common_exit:

    if (line != (STRING *)0)
	DestroyString(line);
    if (buf != (char *)0)
	free(buf);
    if (fdLog != (CONSFILE *)0)
	FileClose(&fdLog);

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
#define IS_LIMITED	0x100

#define HALFLINE	40

typedef struct HLnode {
    int iwhen;
    char *actext;
} HELP;

static HELP aHLTable[] = {
    {WHEN_ALWAYS, ".    disconnect"},
    {WHEN_ALWAYS | IS_LIMITED, ";    move to another console"},
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
    {WHEN_ALWAYS, "n    write a note to the logfile"},
    {WHEN_ALWAYS, "o    (re)open the tty and log file"},
    {WHEN_ALWAYS, "p    playback the last %hu lines"},
    {WHEN_ALWAYS, "P    set number of playback lines"},
    {WHEN_ALWAYS, "r    replay the last %hu lines"},
    {WHEN_ALWAYS, "R    set number of replay lines"},
    {WHEN_ATTACH, "s    spy mode (read only)"},
    {WHEN_ALWAYS, "u    show host status"},
    {WHEN_ALWAYS, "v    show version info"},
    {WHEN_ALWAYS, "w    who is on this console"},
    {WHEN_ALWAYS, "x    show console baud info"},
    {WHEN_ALWAYS | IS_LIMITED, "z    suspend the connection"},
    {WHEN_ATTACH | IS_LIMITED, "|    attach local command"},
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
HelpUser(pCL, pCE)
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
	char *text;

	if (aHLTable[i].iwhen & IS_LIMITED &&
	    ConsentUserOk(pLUList, pCL->username->string) == 1)
	    continue;

	if (0 == (aHLTable[i].iwhen & iCmp))
	    continue;

	text = aHLTable[i].actext;
	if (text[0] == 'p') {
	    BuildTmpString((char *)0);
	    text = BuildTmpStringPrint(text, pCL->playback);
	} else if (text[0] == 'r') {
	    BuildTmpString((char *)0);
	    text = BuildTmpStringPrint(text, pCL->replay);
	}

	if (acLine->used != 0) {	/* second part of line */
	    if (strlen(text) < HALFLINE) {
		for (j = acLine->used; j <= HALFLINE; ++j) {
		    BuildStringChar(' ', acLine);
		}
		BuildString(text, acLine);
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
	    BuildString(text, acLine);
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
    int retval = 1;

#if USE_UNIX_DOMAIN_SOCKETS
    struct in_addr addr;

# if HAVE_INET_ATON
    inet_aton("127.0.0.1", &addr);
# else
    addr.s_addr = inet_addr("127.0.0.1");
# endif
    pCL->caccess = AccType(&addr, &peername);
    if (pCL->caccess == 'r') {
	FileWrite(pCL->fd, FLAGFALSE, "access from your host refused\r\n",
		  -1);
	retval = 0;
    }
#else
    socklen_t so;
    int cfd;
    struct sockaddr_in in_port;
    int getpeer = -1;

    cfd = FileFDNum(pCL->fd);
    pCL->caccess = 'r';
# if defined(USE_LIBWRAP)
    {
	struct request_info request;
	CONDDEBUG((1, "ClientAccessOk(): doing tcpwrappers check"));
	request_init(&request, RQ_DAEMON, progname, RQ_FILE, cfd, 0);
	fromhost(&request);
	if (!hosts_access(&request)) {
	    FileWrite(pCL->fd, FLAGFALSE,
		      "access from your host refused\r\n", -1);
	    retval = 0;
	    goto setpeer;
	}
    }
# endif

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
#endif

    if (pCL->peername != (STRING *)0) {
	BuildString((char *)0, pCL->peername);
	if (peername != (char *)0)
	    BuildString(peername, pCL->peername);
#if USE_UNIX_DOMAIN_SOCKETS
	else
	    BuildString("127.0.0.1", pCL->peername);
#else
	else if (getpeer != -1)
	    BuildString(inet_ntoa(in_port.sin_addr), pCL->peername);
	else
	    BuildString("<unknown>", pCL->peername);
#endif
    }
    if (peername != (char *)0)
	free(peername);
    return retval;
}
