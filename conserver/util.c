/*
 *  $Id: util.c,v 1.105 2003/11/15 16:31:51 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#include <compat.h>

#include <util.h>

#if HAVE_OPENSSL
#include <openssl/ssl.h>
#endif


int fVerbose = 0, fErrorPrinted = 0;
int isMultiProc = 0;
char *progname = "conserver package";
pid_t thepid = 0;
int fDebug = 0;
STRING *allStrings = (STRING *)0;
int stringCount = 0;		/* count of allStrings list */
struct in_addr *myAddrs = (struct in_addr *)0;
char myHostname[MAXHOSTNAME];	/* staff.cc.purdue.edu                  */
fd_set rinit;
fd_set winit;
int maxfd = 0;
int debugLineNo = 0;
char *debugFileName = (char *)0;

/* in the routines below (the init code) we can bomb if malloc fails	(ksb)
 */
void
#if PROTOTYPES
OutOfMem()
#else
OutOfMem()
#endif
{
    static char acNoMem[] = ": out of memory\n";

    write(2, progname, strlen(progname));
    write(2, acNoMem, sizeof(acNoMem) - 1);
    exit(EX_UNAVAILABLE);
}

/* do a general cleanup and exit */
void
#if PROTOTYPES
Bye(int status)
#else
Bye(status)
    int status;
#endif
{
    DestroyDataStructures();
#if HAVE_OPENSSL
    ERR_free_strings();
#endif
    exit(status);
}

/* This returns a string with the current time in ascii form.
 * (same as ctime() but without the \n)
 * optionally returns the time in time_t form (pass in NULL if you don't care).
 * It's overwritten each time, so use it and forget it.
 */
const char *
#if PROTOTYPES
StrTime(time_t *ltime)
#else
StrTime(ltime)
    time_t *ltime;
#endif
{
    static char curtime[40];	/* just in case ctime() varies */
    time_t tyme;

    tyme = time((time_t *)0);
    strcpy(curtime, ctime(&tyme));
    curtime[24] = '\000';	/* might need to adjust this at some point */
    if (ltime != NULL)
	*ltime = tyme;
    return (const char *)curtime;
}

#define STRING_ALLOC_SIZE 64

char *
#if PROTOTYPES
BuildStringChar(const char ch, STRING *msg)
#else
BuildStringChar(ch, msg)
    const char ch;
    STRING *msg;
#endif
{
    if (msg->used + 1 >= msg->allocated) {
	if (0 == msg->allocated) {
	    msg->allocated = STRING_ALLOC_SIZE * sizeof(char);
	    msg->string = (char *)calloc(1, msg->allocated);
	} else {
	    msg->allocated += STRING_ALLOC_SIZE * sizeof(char);
	    msg->string = (char *)realloc(msg->string, msg->allocated);
	}
	CONDDEBUG((3,
		   "BuildStringChar(): 0x%lx tried allocating %lu bytes",
		   (void *)msg, msg->allocated));
	if (msg->string == (char *)0)
	    OutOfMem();
    }
    if (msg->used) {
	msg->string[msg->used - 1] = ch;	/* overwrite NULL and */
	msg->string[msg->used++] = '\000';	/* increment by one */
	CONDDEBUG((3, "BuildStringChar(): 0x%lx added 1 char (%d/%d now)",
		   (void *)msg, msg->used, msg->allocated));
    } else {
	msg->string[msg->used++] = ch;	/* no NULL, so store stuff */
	msg->string[msg->used++] = '\000';	/* and increment by two */
	CONDDEBUG((3, "BuildStringChar(): 0x%lx added 2 chars (%d/%d now)",
		   (void *)msg, msg->used, msg->allocated));
    }
    return msg->string;
}

char *
#if PROTOTYPES
BuildString(const char *str, STRING *msg)
#else
BuildString(str, msg)
    const char *str;
    STRING *msg;
#endif
{
    int len;

    if ((char *)0 == str) {
	msg->used = 0;
	if (msg->string != (char *)0)
	    msg->string[0] = '\000';
	CONDDEBUG((3, "BuildString(): 0x%lx reset", (void *)msg));
	return msg->string;
    }
    if (msg->used)		/* string or string + null? */
	len = strlen(str);
    else
	len = strlen(str) + 1;
    if (msg->used + len >= msg->allocated) {
	if (0 == msg->allocated) {
	    msg->allocated =
		(len / STRING_ALLOC_SIZE +
		 1) * STRING_ALLOC_SIZE * sizeof(char);
	    msg->string = (char *)calloc(1, msg->allocated);
	} else {
	    msg->allocated +=
		((msg->used + len - msg->allocated) / STRING_ALLOC_SIZE +
		 1) * STRING_ALLOC_SIZE * sizeof(char);
	    msg->string = (char *)realloc(msg->string, msg->allocated);
	}
	CONDDEBUG((3, "BuildString(): 0x%lx tried allocating %lu bytes",
		   (void *)msg, msg->allocated));
	if (msg->string == (char *)0)
	    OutOfMem();
    }
    /* if msg->used, then len = strlen(), so we need to copy len + 1 to
     * get the NULL which we overwrote with the copy */
#if HAVE_MEMCPY
    if (msg->used)
	memcpy(msg->string + msg->used - 1, str, len + 1);
    else
	memcpy(msg->string, str, len);
#else
    if (msg->used)
	bcopy(str, msg->string + msg->used - 1, len + 1);
    else
	bcopy(str, msg->string, len);
#endif
    msg->used += len;
    CONDDEBUG((3, "BuildString(): 0x%lx added %d chars (%d/%d now)",
	       (void *)msg, len, msg->used, msg->allocated));
    return msg->string;
}

char *
#if PROTOTYPES
BuildStringN(const char *str, int n, STRING *msg)
#else
BuildStringN(str, n, msg)
    const char *str;
    int n;
    STRING *msg;
#endif
{
    int len;

    if ((char *)0 == str) {
	msg->used = 0;
	if (msg->string != (char *)0)
	    msg->string[0] = '\000';
	CONDDEBUG((3, "BuildStringN(): 0x%lx reset", (void *)msg));
	return msg->string;
    }
    if (n <= 0)
	return msg->string;
    if (msg->used)
	len = n;
    else
	len = n + 1;
    if (msg->used + len >= msg->allocated) {
	if (0 == msg->allocated) {
	    msg->allocated =
		(len / STRING_ALLOC_SIZE +
		 1) * STRING_ALLOC_SIZE * sizeof(char);
	    msg->string = (char *)calloc(1, msg->allocated);
	} else {
	    msg->allocated +=
		((msg->used + len - msg->allocated) / STRING_ALLOC_SIZE +
		 1) * STRING_ALLOC_SIZE * sizeof(char);
	    msg->string = (char *)realloc(msg->string, msg->allocated);
	}
	CONDDEBUG((3, "BuildStringN(): 0x%lx tried allocating %lu bytes",
		   (void *)msg, msg->allocated));
	if (msg->string == (char *)0)
	    OutOfMem();
    }
#if HAVE_MEMCPY
    memcpy(msg->string + (msg->used ? msg->used - 1 : 0), str, n);
#else
    bcopy(str, msg->string + (msg->used ? msg->used - 1 : 0), n);
#endif
    /* add a NULL */
    msg->string[(msg->used ? msg->used - 1 : 0) + n] = '\000';
    msg->used += len;
    CONDDEBUG((3, "BuildStringN(): 0x%lx added %d chars (%d/%d now)",
	       (void *)msg, len, msg->used, msg->allocated));
    return msg->string;
}

char *
#if PROTOTYPES
ShiftString(STRING *msg, int n)
#else
ShiftString(msg, n)
    STRING *msg;
    int n;
#endif
{
    if (msg == (STRING *)0 || n <= 0 || n > msg->used - 1)
	return (char *)0;

#if HAVE_MEMMOVE
    memmove(msg->string, msg->string + n, msg->used - n);
#else
    {
	char *s, *e;
	int len;
	for (s = msg->string, e = s + n, len = msg->used - n; len > 0;
	     len--)
	    *s++ = *e++;
    }
#endif
    msg->used -= n;
    return msg->string;
}

void
#if PROTOTYPES
InitString(STRING *msg)
#else
InitString(msg)
    STRING *msg;
#endif
{
    msg->string = (char *)0;
    msg->used = msg->allocated = 0;
}

void
#if PROTOTYPES
DestroyString(STRING *msg)
#else
DestroyString(msg)
    STRING *msg;
#endif
{
    if (msg->prev == (STRING *)0 && msg->next == (STRING *)0 &&
	allStrings != msg) {
	CONDDEBUG((1, "DestroyString(): 0x%lx non-pooled string destroyed",
		   (void *)msg, stringCount));
    } else {
	if (msg->prev != (STRING *)0)
	    msg->prev->next = msg->next;
	if (msg->next != (STRING *)0)
	    msg->next->prev = msg->prev;
	if (msg == allStrings) {
	    allStrings = msg->next;
	}
	stringCount--;
	CONDDEBUG((1,
		   "DestroyString(): 0x%lx string destroyed (count==%d)",
		   (void *)msg, stringCount));
    }
    if (msg->allocated)
	free(msg->string);
    free(msg);
}

STRING *
#if PROTOTYPES
AllocString(void)
#else
AllocString()
#endif
{
    STRING *s;
    if ((s = (STRING *)calloc(1, sizeof(STRING)))
	== (STRING *)0)
	OutOfMem();
    if (allStrings != (STRING *)0) {
	allStrings->prev = s;
	s->next = allStrings;
    }
    allStrings = s;
    InitString(s);
    stringCount++;
    CONDDEBUG((1, "AllocString(): 0x%lx created string #%d", (void *)s,
	       stringCount));
    return s;
}

void
#if PROTOTYPES
DestroyStrings(void)
#else
DestroyStrings()
#endif
{
    while (allStrings != (STRING *)0) {
	DestroyString(allStrings);
    }
}

static STRING *mymsg = (STRING *)0;

char *
#if PROTOTYPES
BuildTmpString(const char *str)
#else
BuildTmpString(str)
    const char *str;
#endif
{
    if (mymsg == (STRING *)0)
	mymsg = AllocString();
    return BuildString(str, mymsg);
}

char *
#if PROTOTYPES
BuildTmpStringChar(const char c)
#else
BuildTmpStringChar(c)
    const char c;
#endif
{
    if (mymsg == (STRING *)0)
	mymsg = AllocString();
    return BuildStringChar(c, mymsg);
}

char *
#if PROTOTYPES
ReadLine(FILE *fp, STRING *save, int *iLine)
#else
ReadLine(fp, save, iLine)
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
	    if (comment == 0 && commentCheck == 0) {
		/* Finish off the chunk without the \n */
		buf[buflen - 1] = '\000';
		BuildString(buf, bufstr);
		wholeline = BuildString(bufstr->string, wholestr);
	    }
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
    if (!peek && (ret == (char *)0) && (comment == 0) &&
	(commentCheck == 0)) {
	(*iLine)++;
	wholeline = BuildString(bufstr->string, wholestr);
    }

    CONDDEBUG((1, "ReadLine(): returning <%s>",
	       (wholeline != (char *)0) ? wholeline : "<NULL>"));
    return wholeline;
}

/* show a character as a string so the user cannot mistake it for	(ksb)
 * another
 */
char *
#if PROTOTYPES
FmtCtl(int ci, STRING *pcIn)
#else
FmtCtl(ci, pcIn)
    int ci;
    STRING *pcIn;
#endif
{
    unsigned char c;

    BuildString((char *)0, pcIn);
    c = ci & 0xff;
    if (c > 127) {
	c -= 128;
	BuildString("M-", pcIn);
    }

    if (c < ' ' || c == '\177') {
	BuildStringChar('^', pcIn);
	BuildStringChar(c ^ 0100, pcIn);
    } else if (c == ' ') {
	BuildString("<space>", pcIn);
    } else if (c == '^') {
	BuildString("<circumflex>", pcIn);
    } else if (c == '\\') {
	BuildString("<backslash>", pcIn);
    } else {
	BuildStringChar(c, pcIn);
    }
    return pcIn->string;
}

void
#if PROTOTYPES
FmtCtlStr(char *pcIn, int len, STRING *pcOut)
#else
FmtCtlStr(pcIn, len, pcOut)
    char *pcIn;
    int len;
    STRING *pcOut;
#endif
{
    unsigned char c;

    if (len < 0)
	len = strlen(pcIn);

    BuildString((char *)0, pcOut);
    for (; len; len--, pcIn++) {
	c = *pcIn & 0xff;
	if (c > 127) {
	    c -= 128;
	    BuildString("M-", pcOut);
	}

	if (c < ' ' || c == '\177') {
	    BuildStringChar('^', pcOut);
	    BuildStringChar(c ^ 0100, pcOut);
	} else {
	    BuildStringChar(c, pcOut);
	}
    }
}

void
#if PROTOTYPES
Debug(int level, char *fmt, ...)
#else
Debug(level, fmt, va_alist)
    int level;
    char *fmt;
    va_dcl
#endif
{
    va_list ap;

    if (fDebug < level)
	return;
#if PROTOTYPES
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    if (isMultiProc)
	fprintf(stderr, "[%s] %s (%lu): DEBUG: [%s:%d] ",
		StrTime((time_t *)0), progname, (unsigned long)thepid,
		debugFileName, debugLineNo);
    else
	fprintf(stderr, "%s: DEBUG: [%s:%d] ", progname, debugFileName,
		debugLineNo);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void
#if PROTOTYPES
Error(char *fmt, ...)
#else
Error(fmt, va_alist)
    char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if PROTOTYPES
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    if (isMultiProc)
	fprintf(stderr, "[%s] %s (%lu): ERROR: ", StrTime((time_t *)0),
		progname, (unsigned long)thepid);
    else
	fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    fErrorPrinted = 1;
}

void
#if PROTOTYPES
Msg(char *fmt, ...)
#else
Msg(fmt, va_alist)
    char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if PROTOTYPES
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    if (isMultiProc)
	fprintf(stdout, "[%s] %s (%lu): ", StrTime((time_t *)0), progname,
		(unsigned long)thepid);
    else
	fprintf(stdout, "%s: ", progname);
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

void
#if PROTOTYPES
Verbose(char *fmt, ...)
#else
Verbose(fmt, va_alist)
    char *fmt;
    va_dcl
#endif
{
    va_list ap;

    if (!fVerbose)
	return;

#if PROTOTYPES
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    if (isMultiProc)
	fprintf(stdout, "[%s] %s (%lu): INFO: ", StrTime((time_t *)0),
		progname, (unsigned long)thepid);
    else
	fprintf(stdout, "%s: ", progname);
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

void
#if PROTOTYPES
SimpleSignal(int sig, RETSIGTYPE(*disp) (int))
#else
SimpleSignal(sig, disp)
    int sig;
RETSIGTYPE(*disp) (int);
#endif
{
#if HAVE_SIGACTION
    struct sigaction sa;

    sa.sa_handler = disp;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
#else
    signal(sig, disp);
#endif
}

int
#if PROTOTYPES
GetMaxFiles()
#else
GetMaxFiles()
#endif
{
    int mf;
#if HAVE_SYSCONF
    mf = sysconf(_SC_OPEN_MAX);
#else
# if HAVE_GETRLIMIT
    struct rlimit rl;

    getrlimit(RLIMIT_NOFILE, &rl);
    mf = rl.rlim_cur;
# else
#  if HAVE_GETDTABLESIZE
    mf = getdtablesize();
#  else
#   ifndef OPEN_MAX
#    define OPEN_MAX 64
#   endif /* !OPEN_MAX */
    mf = OPEN_MAX;
#  endif /* HAVE_GETDTABLESIZE */
# endif	/* HAVE_GETRLIMIT */
#endif /* HAVE_SYSCONF */
#ifdef FD_SETSIZE
    if (FD_SETSIZE <= mf) {
	mf = (FD_SETSIZE - 1);
    }
#endif
    CONDDEBUG((1, "GetMaxFiles(): maxfiles=%d", mf));
    return mf;
}

/* Routines for the generic I/O stuff for conserver.  This will handle
 * all open(), close(), read(), and write() calls.
 */

/* This encapsulates a regular file descriptor in a CONSFILE
 * object.  Returns a CONSFILE pointer to that object.
 */
CONSFILE *
#if PROTOTYPES
FileOpenFD(int fd, enum consFileType type)
#else
FileOpenFD(fd, type)
    int fd;
    enum consFileType type;
#endif
{
    CONSFILE *cfp;

    if ((cfp = (CONSFILE *)calloc(1, sizeof(CONSFILE)))
	== (CONSFILE *)0)
	OutOfMem();
    cfp->ftype = type;
    cfp->fd = fd;
    cfp->wbuf = AllocString();
#if HAVE_OPENSSL
    cfp->ssl = (SSL *)0;
    cfp->waitForRead = cfp->waitForWrite = FLAGFALSE;
#endif

    CONDDEBUG((2, "FileOpenFD(): encapsulated fd %d type %d", fd, type));
    return cfp;
}

/* This encapsulates a pipe pair in a CONSFILE
 * object.  Returns a CONSFILE pointer to that object.
 */
CONSFILE *
#if PROTOTYPES
FileOpenPipe(int fd, int fdout)
#else
FileOpenPipe(fd, fdout)
    int fd;
    int fdout;
#endif
{
    CONSFILE *cfp;

    if ((cfp = (CONSFILE *)calloc(1, sizeof(CONSFILE)))
	== (CONSFILE *)0)
	OutOfMem();
    cfp->ftype = simplePipe;
    cfp->fd = fd;
    cfp->fdout = fdout;
    cfp->wbuf = AllocString();
#if HAVE_OPENSSL
    cfp->ssl = (SSL *)0;
    cfp->waitForRead = cfp->waitForWrite = FLAGFALSE;
#endif

    CONDDEBUG((2, "FileOpenPipe(): encapsulated pipe pair fd %d and fd %d",
	       fd, fdout));
    return cfp;
}

/* This is to "unencapsulate" the file descriptor */
int
#if PROTOTYPES
FileUnopen(CONSFILE *cfp)
#else
FileUnopen(cfp)
    CONSFILE *cfp;
#endif
{
    int retval = 0;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = cfp->fd;
	    break;
	case simplePipe:
	    retval = cfp->fd;
	    break;
	case simpleSocket:
	    retval = cfp->fd;
	    break;
#if HAVE_OPENSSL
	case SSLSocket:
	    retval = -1;
	    break;
#endif
	default:
	    retval = -1;
	    break;
    }
    CONDDEBUG((2, "FileUnopen(): unopened fd %d", cfp->fd));
    DestroyString(cfp->wbuf);
    free(cfp);

    return retval;
}

/* This opens a file like open(2).  Returns a CONSFILE pointer
 * or a (CONSFILE *)0 on error
 */
CONSFILE *
#if PROTOTYPES
FileOpen(const char *path, int flag, int mode)
#else
FileOpen(path, flag, mode)
    const char *path;
    int flag;
    int mode;
#endif
{
    CONSFILE *cfp;
    int fd;

    if (-1 == (fd = open(path, flag, mode))) {
	CONDDEBUG((2, "FileOpen(): failed to open `%s'", path));
	return (CONSFILE *)0;
    }
    if ((cfp = (CONSFILE *)calloc(1, sizeof(CONSFILE)))
	== (CONSFILE *)0)
	OutOfMem();
    cfp->ftype = simpleFile;
    cfp->fd = fd;
    cfp->wbuf = AllocString();
#if HAVE_OPENSSL
    cfp->ssl = (SSL *)0;
    cfp->waitForRead = cfp->waitForWrite = FLAGFALSE;
#endif

    CONDDEBUG((2, "FileOpen(): opened `%s' as fd %d", path, fd));
    return cfp;
}

/* Unless otherwise stated, returns the same values as close(2).
 * The CONSFILE object passed in *CANNOT* be used once calling
 * this function - even if there was an error.
 */
int
#if PROTOTYPES
FileClose(CONSFILE **pcfp)
#else
FileClose(pcfp)
    CONSFILE **pcfp;
#endif
{
    CONSFILE *cfp;
    int retval = 0;
#if defined(__CYGWIN__)
    struct linger lingeropt;
#endif

    cfp = *pcfp;
    if (cfp == (CONSFILE *)0)
	return 0;

    switch (cfp->ftype) {
	case simpleFile:
	    do {
		retval = close(cfp->fd);
	    } while (retval == -1 && errno == EINTR);
	    break;
	case simplePipe:
	    do {
		retval = close(cfp->fd);
	    } while (retval == -1 && errno == EINTR);
	    do {
		retval = close(cfp->fdout);
	    } while (retval == -1 && errno == EINTR);
	    break;
	case simpleSocket:
#if defined(__CYGWIN__)
	    /* flush out the client socket - set it to blocking,
	     * then write to it
	     */
	    SetFlags(cfp->fd, 0, O_NONBLOCK)

		/* sent it a byte - guaranteed to block - ensure delivery
		 * of prior data yeah - this is a bit paranoid - try
		 * without this at first
		 */
		/* write(cfp->fd, "\n", 1); */
		/* this is the guts of the workaround for Winsock close bug */
		shutdown(cfp->fd, 1);

	    /* enable lingering */
	    lingeropt.l_onoff = 1;
	    lingeropt.l_linger = 15;
	    setsockopt(cfp->fd, SOL_SOCKET, SO_LINGER, &lingeropt,
		       sizeof(lingeropt));
#endif
	    do {
		retval = close(cfp->fd);
	    } while (retval == -1 && errno == EINTR);

	    break;
#if HAVE_OPENSSL
	case SSLSocket:
	    CONDDEBUG((2,
		       "FileClose(): performing a SSL_shutdown() on fd %d",
		       cfp->fd));
	    SSL_shutdown(cfp->ssl);
	    CONDDEBUG((2, "FileClose(): performing a SSL_free() on fd %d",
		       cfp->fd));
	    SSL_free(cfp->ssl);
	    /* set the sucker back to a simpleSocket and recall so we
	     * do all that special stuff we oh so love...and make sure
	     * we return so we don't try and free(0).  -bryan
	     */
	    cfp->ftype = simpleSocket;
	    return FileClose(pcfp);
#endif
	default:
	    retval = -1;
	    break;
    }

    CONDDEBUG((2, "FileClose(): closed fd %d", cfp->fd));
    DestroyString(cfp->wbuf);
    free(cfp);
    *pcfp = (CONSFILE *)0;

    return retval;
}

/* returns: -1 on error or eof, >= 0 for valid reads */
int
#if PROTOTYPES
FileRead(CONSFILE *cfp, void *buf, int len)
#else
FileRead(cfp, buf, len)
    CONSFILE *cfp;
    void *buf;
    int len;
#endif
{
    int retval = -1;

    switch (cfp->ftype) {
	case simpleFile:
	case simplePipe:
	case simpleSocket:
	    while (retval < 0) {
		if ((retval = read(cfp->fd, buf, len)) <= 0) {
		    if (retval == 0) {
			retval = -1;
			break;
		    }
		    if (errno == EINTR)
			continue;
		    if (errno == EAGAIN) {
			/* must be non-blocking - so stop */
			retval = 0;
			break;
		    }
		    Error("FileRead(): fd %d: %s", cfp->fd,
			  strerror(errno));
		    retval = -1;
		    break;
		}
	    }
	    break;
#if HAVE_OPENSSL
	case SSLSocket:
	    if (cfp->waitForWrite == FLAGTRUE) {
		cfp->waitForWrite = FLAGFALSE;
		if (cfp->wbuf->used <= 1)
		    FD_CLR(cfp->fd, &winit);
	    }
	    retval = SSL_read(cfp->ssl, buf, len);
	    switch (SSL_get_error(cfp->ssl, retval)) {
		case SSL_ERROR_NONE:
		    break;
		case SSL_ERROR_WANT_READ:
		    retval = 0;
		    break;
		case SSL_ERROR_WANT_WRITE:
		    cfp->waitForWrite = FLAGTRUE;
		    FD_SET(cfp->fd, &winit);
		    retval = 0;
		    break;
		default:
		    Error("FileRead(): SSL error on fd %d", cfp->fd);
		    /* fall through */
		case SSL_ERROR_ZERO_RETURN:
		    retval = -1;
		    CONDDEBUG((2,
			       "FileRead(): performing a SSL_shutdown() on fd %d",
			       cfp->fd));
		    SSL_shutdown(cfp->ssl);
		    CONDDEBUG((2,
			       "FileRead(): performing a SSL_free() on fd %d",
			       cfp->fd));
		    SSL_free(cfp->ssl);
		    cfp->ssl = (SSL *)0;
		    cfp->ftype = simpleSocket;
		    break;
	    }
	    break;
#endif
	default:
	    retval = -1;
	    break;
    }

    if (retval >= 0) {
	CONDDEBUG((2, "FileRead(): read %d byte%s from fd %d", retval,
		   (retval == 1) ? "" : "s", cfp->fd));
	if (fDebug && buf != (char *)0) {
	    static STRING *tmpString = (STRING *)0;
	    if (tmpString == (STRING *)0)
		tmpString = AllocString();
	    BuildString((char *)0, tmpString);
	    if (retval > 30) {
		FmtCtlStr(buf, 30, tmpString);
		CONDDEBUG((2, "FileRead(): read `%s'... from fd %d",
			   tmpString->string, cfp->fd));
	    } else {
		FmtCtlStr(buf, retval, tmpString);
		CONDDEBUG((2, "FileRead(): read `%s' from fd %d",
			   tmpString->string, cfp->fd));
	    }
	}
    } else {
	CONDDEBUG((2,
		   "FileRead(): failed attempted read of %d byte%s from fd %d",
		   len, (len == 1) ? "" : "s", cfp->fd));
    }
    return retval;
}

/* returns: -1 on error or eof, >= 0 for valid reads */
int
#if PROTOTYPES
FileWrite(CONSFILE *cfp, FLAG bufferonly, char *buf, int len)
#else
FileWrite(cfp, bufferonly, buf, len)
    CONSFILE *cfp;
    FLAG bufferonly;
    char *buf;
    int len;
#endif
{
    int len_orig = len;
    int len_out = 0;
    int retval = 0;
    int fdout = 0;

    if (len < 0 && buf != (char *)0)
	len = strlen(buf);

    if (cfp->ftype == simplePipe)
	fdout = cfp->fdout;
    else
	fdout = cfp->fd;

    if (fDebug && len > 0 && buf != (char *)0) {
	static STRING *tmpString = (STRING *)0;
	if (tmpString == (STRING *)0)
	    tmpString = AllocString();
	BuildString((char *)0, tmpString);
	if (len > 30) {
	    FmtCtlStr(buf, 30, tmpString);
	    CONDDEBUG((2, "FileWrite(): sending `%s'... to fd %d",
		       tmpString->string, fdout));
	} else {
	    FmtCtlStr(buf, len, tmpString);
	    CONDDEBUG((2, "FileWrite(): sending `%s' to fd %d",
		       tmpString->string, fdout));
	}
    }
    /* save the data */
    if (len > 0 && buf != (char *)0)
	BuildStringN(buf, len, cfp->wbuf);

    if (bufferonly == FLAGTRUE)
	return 0;

    /* point at the local data */
    buf = cfp->wbuf->string;
    len = cfp->wbuf->used - 1;

    /* if we don't have any, forget it */
    if (buf == (char *)0 || len <= 0)
	return 0;

    /* so, we could be blocking or non-blocking.  since we may be able
     * to block, we'll just keep trying to write while we have data and
     * stop when we hit an error or flush all the data.
     */
    switch (cfp->ftype) {
	case simplePipe:
	case simpleFile:
	case simpleSocket:
	    while (len > 0) {
		if ((retval = write(fdout, buf, len)) < 0) {
		    if (errno == EINTR)
			continue;
		    if (errno == EAGAIN) {
			/* must be non-blocking - so stop */
			retval = 0;
			break;
		    }
		    retval = -1;
		    if (errno == EPIPE)
			break;
		    Error("FileWrite(): fd %d: %s", fdout,
			  strerror(errno));
		    break;
		}
		buf += retval;
		len -= retval;
		len_out += retval;
	    }
	    break;
#if HAVE_OPENSSL
	case SSLSocket:
	    if (cfp->waitForRead == FLAGTRUE)
		cfp->waitForRead = FLAGFALSE;
	    while (len > 0) {
		/* in theory, SSL_write always returns 'len' on success
		 * so the while() loop is a noop.  but, just in case i
		 * read something wrong, we treat SSL_write like write().
		 */
		retval = SSL_write(cfp->ssl, buf, len);
		switch (SSL_get_error(cfp->ssl, retval)) {
		    case SSL_ERROR_NONE:
			break;
		    case SSL_ERROR_WANT_READ:
			cfp->waitForRead = FLAGTRUE;
			retval = len_out = 0;
			break;
		    case SSL_ERROR_WANT_WRITE:
			retval = len_out = 0;
			break;
		    default:
			Error("FileWrite(): SSL error on fd %d", cfp->fd);
			/* fall through */
		    case SSL_ERROR_ZERO_RETURN:
			retval = -1;
			CONDDEBUG((2,
				   "FileWrite(): performing a SSL_shutdown() on fd %d",
				   cfp->fd));
			SSL_shutdown(cfp->ssl);
			CONDDEBUG((2,
				   "FileWrite(): performing a SSL_free() on fd %d",
				   cfp->fd));
			SSL_free(cfp->ssl);
			cfp->ssl = (SSL *)0;
			cfp->ftype = simpleSocket;
			break;
		}
		if (retval <= 0)
		    break;
		buf += retval;
		len -= retval;
		len_out += retval;
	    }
	    break;
#endif
	default:
	    len_out = -1;
	    break;
    }

    /* so, if we saw an error, just bail...all is done anyway */
    if (retval < 0)
	len_out = retval;

    if (len_out > 0) {
	/* save the rest for later */
	if (len > 0) {
	    ShiftString(cfp->wbuf, len_out);
	} else {
	    BuildString((char *)0, cfp->wbuf);
	}
    }
    if (cfp->wbuf->used <= 1)
	FD_CLR(fdout, &winit);
    else {
	FD_SET(fdout, &winit);
	CONDDEBUG((2, "FileWrite(): buffered %d byte%s for fd %d",
		   (cfp->wbuf->used <= 1) ? 0 : cfp->wbuf->used,
		   (cfp->wbuf->used <= 1) ? "" : "s", fdout));
    }

    if (len_out >= 0) {
	CONDDEBUG((2, "FileWrite(): wrote %d byte%s to fd %d", len_out,
		   (len_out == 1) ? "" : "s", fdout));
    } else {
	CONDDEBUG((2, "FileWrite(): write of %d byte%s to fd %d: %s",
		   len_orig, (len_out == -1) ? "" : "s", fdout,
		   strerror(errno)));
    }
    return len_out;
}

int
#if PROTOTYPES
FileCanRead(CONSFILE *cfp, fd_set *prfd, fd_set *pwfd)
#else
FileCanRead(cfp, prfd, pwfd)
    CONSFILE *cfp;
    fd_set *prfd;
    fd_set *pwfd;
#endif
{
    int fdout;

    if (cfp == (CONSFILE *)0)
	return 0;

    if (cfp->ftype == simplePipe)
	fdout = cfp->fdout;
    else
	fdout = cfp->fd;

    return ((FD_ISSET(cfp->fd, prfd)
#if HAVE_OPENSSL
	     && cfp->waitForRead != FLAGTRUE) || (FD_ISSET(fdout, pwfd)
						  && cfp->waitForWrite ==
						  FLAGTRUE
#endif
	    ));
}

int
#if PROTOTYPES
FileCanWrite(CONSFILE *cfp, fd_set *prfd, fd_set *pwfd)
#else
FileCanWrite(cfp, prfd, pwfd)
    CONSFILE *cfp;
    fd_set *prfd;
    fd_set *pwfd;
#endif
{
    int fdout;

    if (cfp == (CONSFILE *)0)
	return 0;

    if (cfp->ftype == simplePipe)
	fdout = cfp->fdout;
    else
	fdout = cfp->fd;

    return ((FD_ISSET(fdout, pwfd)
#if HAVE_OPENSSL
	     && cfp->waitForWrite != FLAGTRUE) || (FD_ISSET(cfp->fd, prfd)
						   && cfp->waitForRead ==
						   FLAGTRUE
#endif
	    ));
}

int
#if PROTOTYPES
FileBufEmpty(CONSFILE *cfp)
#else
FileBufEmpty(cfp)
    CONSFILE *cfp;
#endif
{
    if (cfp == (CONSFILE *)0)
	return 1;
    return (cfp->wbuf->used <= 1);
}

void
#if PROTOTYPES
VWrite(CONSFILE *cfp, FLAG bufferonly, STRING *str, char *fmt, va_list ap)
#else
VWrite(cfp, bufferonly, str, fmt, ap)
    CONSFILE *cfp;
    FLAG bufferonly;
    STRING *str;
    char *fmt;
    va_list ap;
#endif
{
    int s, l, e;
    char c;
    int fmtlen = 0;
    int fmtpre = 0;
    short padzero = 0;
    short sawdot = 0;
    static STRING *msg = (STRING *)0;
    static STRING *output = (STRING *)0;
    short flong = 0, fneg = 0, fminus = 0;

    if (fmt == (char *)0 || (cfp == (CONSFILE *)0 && str == (STRING *)0))
	return;

    if (msg == (STRING *)0)
	msg = AllocString();
    if (output == (STRING *)0)
	output = AllocString();

    BuildString((char *)0, output);

    for (e = s = l = 0; (c = fmt[s + l]) != '\000'; l++) {
	if (e == 0 && c == '%') {
	    e = 1;
	    BuildStringN(fmt + s, l, output);
	    s += l;
	    l = 0;
	    continue;
	}
	if (e) {
	    unsigned long i;
	    int u;
	    char *p;
	    char cc;
	    if (c >= '0' && c <= '9') {
		if (sawdot == 0) {
		    if (c == '0' && fmtlen == 0)
			padzero = 1;
		    fmtlen = fmtlen * 10 + (c - '0');
		} else {
		    fmtpre = fmtpre * 10 + (c - '0');
		}
	    } else {
		switch (c) {
		    case '.':
			sawdot = 1;
			continue;
		    case '-':
			fminus = 1;
			continue;
		    case 'h':
			/* noop since shorts are promoted to int in va_arg */
			continue;
		    case 'l':
			flong = 1;
			continue;
		    case '%':
			BuildStringChar('%', output);
			break;
		    case 'c':
			cc = (char)va_arg(ap, int);
			BuildStringChar(cc, output);
			break;
		    case 's':
			p = va_arg(ap, char *);
			{
			    int l = strlen(p);
			    int c;
			    if (fmtpre > 0 && fmtpre < l)
				l = fmtpre;
			    if (fminus != 0)
				BuildStringN(p, l, output);
			    for (c = l; c < fmtlen; c++)
				BuildStringChar(' ', output);
			    if (fminus == 0)
				BuildStringN(p, l, output);
			}
			break;
		    case 'd':
			i = (flong ? va_arg(ap, long) : (long)
			     va_arg(ap, int));
			if ((long)i < 0) {
			    fneg = 1;
			    i = -i;
			}
			goto number;
		    case 'u':
			i = (flong ? va_arg(ap, unsigned long)
			     : (unsigned long)va_arg(ap, unsigned int));
		      number:
			BuildString((char *)0, msg);
			while (i >= 10) {
			    BuildStringChar((i % 10) + '0', msg);
			    i /= 10;
			}
			BuildStringChar(i + '0', msg);
			if (fneg)
			    BuildStringChar('-', msg);

			if (fmtpre > 0) {
			    padzero = 0;
			    if (fmtpre > fmtlen)
				fmtlen = fmtpre;
			    while (msg->used - 1 < fmtpre)
				BuildStringChar('0', msg);
			}

			/* reverse the text to put it in forward order
			 */
			u = msg->used - 1;
			for (i = 0; i < u / 2; i++) {
			    char temp;

			    temp = msg->string[i];
			    msg->string[i]
				= msg->string[u - i - 1];
			    msg->string[u - i - 1] = temp;
			}

			{
			    int l = msg->used - 1;
			    if (fminus != 0)
				BuildString(msg->string, output);
			    for (; l < fmtlen; l++) {
				if (padzero == 0 || fminus != 0)
				    BuildStringChar(' ', output);
				else
				    BuildStringChar('0', output);
			    }
			    if (fminus == 0)
				BuildString(msg->string, output);
			}
			break;
		    case 'X':
		    case 'x':
			i = (flong ? va_arg(ap, unsigned long)
			     : (unsigned long)va_arg(ap, unsigned int));
			BuildString((char *)0, msg);
			while (i >= 16) {
			    if (i % 16 >= 10)
				BuildStringChar((i % 16) - 10 +
						(c == 'x' ? 'a' : 'A'),
						msg);
			    else
				BuildStringChar((i % 16) + '0', msg);
			    i /= 16;
			}
			if (i >= 10)
			    BuildStringChar(i - 10 +
					    (c == 'x' ? 'a' : 'A'), msg);
			else
			    BuildStringChar(i + '0', msg);

			if (fmtpre > 0) {
			    padzero = 0;
			    if (fmtpre > fmtlen)
				fmtlen = fmtpre;
			    while (msg->used - 1 < fmtpre)
				BuildStringChar('0', msg);
			}

			/* reverse the text to put it in forward order
			 */
			u = msg->used - 1;
			for (i = 0; i < u / 2; i++) {
			    char temp;

			    temp = msg->string[i];
			    msg->string[i]
				= msg->string[u - i - 1];
			    msg->string[u - i - 1] = temp;
			}

			{
			    int l = msg->used - 1;
			    if (fminus != 0)
				BuildString(msg->string, output);
			    for (; l < fmtlen; l++) {
				if (padzero == 0 || fminus != 0)
				    BuildStringChar(' ', output);
				else
				    BuildStringChar('0', output);
			    }
			    if (fminus == 0)
				BuildString(msg->string, output);
			}
			break;
		    default:
			Error
			    ("VWrite(): unknown conversion character `%c' in `%s'",
			     c, fmt);
			break;
		}
		s += l + 1;
		l = -1;
		e = flong = fneg = fminus = 0;
		fmtlen = fmtpre = sawdot = padzero = 0;
	    }
	}
    }
    if (l)
	BuildStringN(fmt + s, l, output);

    if (str != (STRING *)0)
	BuildString((char *)0, str);

    if (output->used > 1) {
	if (str != (STRING *)0)
	    BuildStringN(output->string, output->used - 1, str);
	if (cfp != (CONSFILE *)0)
	    FileWrite(cfp, bufferonly, output->string, output->used - 1);
    }
}

char *
#if PROTOTYPES
BuildStringPrint(STRING *str, char *fmt, ...)
#else
BuildStringPrint(str, fmt, va_alist)
    STRING *str;
    char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if PROTOTYPES
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    VWrite((CONSFILE *)0, FLAGFALSE, str, fmt, ap);
    va_end(ap);
    if (str == (STRING *)0)
	return (char *)0;
    else
	return str->string;
}

char *
#if PROTOTYPES
BuildTmpStringPrint(char *fmt, ...)
#else
BuildTmpStringPrint(fmt, va_alist)
    char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if PROTOTYPES
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    if (mymsg == (STRING *)0)
	mymsg = AllocString();
    VWrite((CONSFILE *)0, FLAGFALSE, mymsg, fmt, ap);
    va_end(ap);
    return mymsg->string;
}

void
#if PROTOTYPES
FileVWrite(CONSFILE *cfp, FLAG bufferonly, char *fmt, va_list ap)
#else
FileVWrite(cfp, bufferonly, fmt, ap)
    CONSFILE *cfp;
    FLAG bufferonly;
    char *fmt;
    va_list ap;
#endif
{
    VWrite(cfp, bufferonly, (STRING *)0, fmt, ap);
}

void
#if PROTOTYPES
FilePrint(CONSFILE *cfp, FLAG bufferonly, char *fmt, ...)
#else
FilePrint(cfp, bufferonly, fmt, va_alist)
    CONSFILE *cfp;
    FLAG bufferonly;
    char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if PROTOTYPES
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    FileVWrite(cfp, bufferonly, fmt, ap);
    va_end(ap);
}

/* Unless otherwise stated, returns the same values as fstat(2) */
int
#if PROTOTYPES
FileStat(CONSFILE *cfp, struct stat *buf)
#else
FileStat(cfp, buf)
    CONSFILE *cfp;
    struct stat *buf;
#endif
{
    int retval = 0;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = fstat(cfp->fd, buf);
	    break;
	case simplePipe:
	    retval = -1;
	    break;
	case simpleSocket:
	    retval = fstat(cfp->fd, buf);
	    break;
#if HAVE_OPENSSL
	case SSLSocket:
	    retval = -1;
	    break;
#endif
	default:
	    retval = -1;
	    break;
    }

    return retval;
}

/* Unless otherwise stated, returns the same values as lseek(2) */
int
#if PROTOTYPES
FileSeek(CONSFILE *cfp, off_t offset, int whence)
#else
FileSeek(cfp, offset, whence)
    CONSFILE *cfp;
    off_t offset;
    int whence;
#endif
{
    int retval = 0;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = lseek(cfp->fd, offset, whence);
	    break;
	case simplePipe:
	    retval = -1;
	    break;
	case simpleSocket:
	    retval = lseek(cfp->fd, offset, whence);
	    break;
#if HAVE_OPENSSL
	case SSLSocket:
	    retval = -1;
	    break;
#endif
	default:
	    retval = -1;
	    break;
    }

    return retval;
}

/* Returns the file descriptor number of the underlying file */
int
#if PROTOTYPES
FileFDNum(CONSFILE *cfp)
#else
FileFDNum(cfp)
    CONSFILE *cfp;
#endif
{
    int retval = 0;

    if (cfp == (CONSFILE *)0)
	return -1;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = cfp->fd;
	    break;
	case simplePipe:
	    retval = cfp->fd;
	    break;
	case simpleSocket:
	    retval = cfp->fd;
	    break;
#if HAVE_OPENSSL
	case SSLSocket:
	    retval = cfp->fd;
	    break;
#endif
	default:
	    retval = cfp->fd;
	    break;
    }

    return retval;
}

/* Returns the file descriptor number of the underlying file */
int
#if PROTOTYPES
FileFDOutNum(CONSFILE *cfp)
#else
FileFDOutNum(cfp)
    CONSFILE *cfp;
#endif
{
    if (cfp == (CONSFILE *)0 || cfp->ftype != simplePipe)
	return -1;

    return cfp->fdout;
}

/* Returns the file type */
enum consFileType
#if PROTOTYPES
FileGetType(CONSFILE *cfp)
#else
FileGetType(cfp)
    CONSFILE *cfp;
#endif
{
    switch (cfp->ftype) {
	case simpleFile:
	    return simpleFile;
	case simplePipe:
	    return simplePipe;
	case simpleSocket:
	    return simpleSocket;
#if HAVE_OPENSSL
	case SSLSocket:
	    return SSLSocket;
#endif
	default:
	    return nothing;
    }
}

/* Sets the file type */
void
#if PROTOTYPES
FileSetType(CONSFILE *cfp, enum consFileType type)
#else
FileSetType(cfp, type)
    CONSFILE *cfp;
    enum consFileType type;
#endif
{
    cfp->ftype = type;
}

#if HAVE_OPENSSL
/* Get the SSL instance */
SSL *
#if PROTOTYPES
FileGetSSL(CONSFILE *cfp)
#else
FileGetSSL(cfp)
    CONSFILE *cfp;
#endif
{
    return cfp->ssl;
}

/* Sets the SSL instance */
void
#if PROTOTYPES
FileSetSSL(CONSFILE *cfp, SSL *ssl)
#else
FileSetSSL(cfp, ssl)
    CONSFILE *cfp;
    SSL *ssl;
#endif
{
    cfp->ssl = ssl;
}

/* return -1 on error, 0 for "wait" state, 1 for success */
int
#if PROTOTYPES
FileCanSSLAccept(CONSFILE *cfp, fd_set *prfd, fd_set *pwfd)
#else
FileCanSSLAccept(cfp)
    CONSFILE *cfp;
    fd_set *prfd;
    fd_set *pwfd;
#endif
{
    if (cfp == (CONSFILE *)0)
	return 0;

    return ((FD_ISSET(cfp->fd, prfd) && cfp->waitForRead == FLAGTRUE) ||
	    (FD_ISSET(cfp->fd, pwfd) && cfp->waitForWrite == FLAGTRUE) ||
	    (cfp->waitForRead != FLAGTRUE &&
	     cfp->waitForWrite != FLAGTRUE));
}

/* return -1 on error, 0 for "wait" state, 1 for success */
int
#if PROTOTYPES
FileSSLAccept(CONSFILE *cfp)
#else
FileSSLAccept(cfp)
    CONSFILE *cfp;
#endif
{
    int retval;
    if (cfp->waitForWrite == FLAGTRUE) {
	cfp->waitForWrite = FLAGFALSE;
	if (cfp->wbuf->used <= 1)
	    FD_CLR(cfp->fd, &winit);
    }
    cfp->waitForRead = FLAGFALSE;

    CONDDEBUG((1, "FileSSLAccept(): about to SSL_accept() for fd %d",
	       cfp->fd));
    retval = SSL_accept(cfp->ssl);
    switch (SSL_get_error(cfp->ssl, retval)) {
	case SSL_ERROR_NONE:
	    break;
	case SSL_ERROR_WANT_READ:
	    cfp->waitForRead = FLAGTRUE;
	    return 0;
	case SSL_ERROR_WANT_WRITE:
	    cfp->waitForWrite = FLAGTRUE;
	    FD_SET(cfp->fd, &winit);
	    return 0;
	default:
	    Error("FileSSLAccept(): SSL error on fd %d", cfp->fd);
	    /* fall through */
	case SSL_ERROR_ZERO_RETURN:
	    SSL_free(cfp->ssl);
	    cfp->ssl = (SSL *)0;
	    cfp->ftype = simpleSocket;
	    return -1;
    }
    cfp->ftype = SSLSocket;
    CONDDEBUG((1, "FileSSLAccept(): SSL Connection: %s :: %s",
	       SSL_get_cipher_version(cfp->ssl),
	       SSL_get_cipher_name(cfp->ssl)));
    return 1;
}
#endif

/* Unless otherwise stated, returns the same values as send(2) */
int
#if PROTOTYPES
FileSend(CONSFILE *cfp, const void *msg, size_t len, int flags)
#else
FileSend(cfp, msg, len, flags)
    CONSFILE *cfp;
    const void *msg;
    size_t len;
    int flags;
#endif
{
    int retval = 0;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = send(cfp->fd, msg, len, flags);
	    break;
	case simplePipe:
	    retval = send(cfp->fdout, msg, len, flags);
	    break;
	case simpleSocket:
	    retval = send(cfp->fd, msg, len, flags);
	    break;
#if HAVE_OPENSSL
	case SSLSocket:
	    retval = send(cfp->fd, msg, len, flags);
	    break;
#endif
	default:
	    retval = -1;
	    break;
    }

    return retval;
}

/* replace trailing space with '\000' in a string and return
 * a pointer to the start of the non-space part
 */
char *
#if PROTOTYPES
PruneSpace(char *string)
#else
PruneSpace(string)
    char *string;
#endif
{
    char *p;
    char *head = (char *)0;
    char *tail = (char *)0;

    /* Don't do much if it's crap */
    if (string == (char *)0 || *string == '\000')
	return string;

    /* Now for the tricky part - search the string */
    for (p = string; *p != '\000'; p++) {
	if (isspace((int)(*p))) {
	    if (tail == (char *)0)
		tail = p;	/* possible end of string */
	} else {
	    if (head == (char *)0)
		head = p;	/* found the start */
	    tail = (char *)0;	/* reset tail */
	}
    }

    if (tail != (char *)0)
	*tail = '\000';

    if (head != (char *)0)
	return head;
    else
	return string;
}

int
#if PROTOTYPES
IsMe(char *id)
#else
IsMe(id)
    char *id;
#endif
{
    int j, i;
    struct hostent *he;
    in_addr_t addr;
#if HAVE_INET_ATON
    struct in_addr inetaddr;
#endif

    /* check for ip address match */
#if HAVE_INET_ATON
    if (inet_aton(id, &inetaddr) != 0) {
	addr = inetaddr.s_addr;
#else
    addr = inet_addr(id);
    if (addr != (in_addr_t) (-1)) {
#endif
	for (i = 0;
	     myAddrs != (struct in_addr *)0 &&
	     myAddrs[i].s_addr != (in_addr_t) 0; i++) {
	    if (
#if HAVE_MEMCMP
		   memcmp(&(myAddrs[i].s_addr), &addr, sizeof(addr))
#else
		   bcmp(&(myAddrs[i].s_addr), &addr, sizeof(addr))
#endif
		   == 0)
		return 1;
	}
	return 0;
    }

    /* check for ip match of hostname */
    if ((struct hostent *)0 == (he = gethostbyname(id))) {
	Error("IsMe(): gethostbyname(%s): %s", id, hstrerror(h_errno));
	return 0;
    }
    if (4 != he->h_length || AF_INET != he->h_addrtype) {
	Error
	    ("IsMe(): gethostbyname(%s): wrong address size (4 != %d) or address family (%d != %d)",
	     id, he->h_length, AF_INET, he->h_addrtype);
	return 0;
    }

    for (j = 0; he->h_addr_list[j] != (char *)0; j++) {
	for (i = 0;
	     myAddrs != (struct in_addr *)0 &&
	     myAddrs[i].s_addr != (in_addr_t) 0; i++) {
	    if (
#if HAVE_MEMCMP
		   memcmp(&(myAddrs[i].s_addr), he->h_addr_list[j],
			  he->h_length)
#else
		   bcmp(&(myAddrs[i].s_addr), he->h_addr_list[j],
			he->h_length)
#endif
		   == 0)
		return 1;
	}
    }
    return 0;
}

#if HAVE_OPENSSL
/* Unless otherwise stated, returns the same values as send(2) */
int
#if PROTOTYPES
SSLVerifyCallback(int ok, X509_STORE_CTX *store)
#else
SSLVerifyCallback(ok, store)
    int ok;
    X509_STORE_CTX *store;
#endif
{
    char data[256];
    if (ok) {
	if (fDebug) {
	    X509 *cert = X509_STORE_CTX_get_current_cert(store);
	    int depth = X509_STORE_CTX_get_error_depth(store);

	    CONDDEBUG((1,
		       "SSLVerifyCallback(): info of certificate at depth: %d",
		       depth));
	    X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
	    CONDDEBUG((1, "SSLVerifyCallback():   issuer  = %s", data));
	    X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
	    CONDDEBUG((1, "SSLVerifyCallback():   subject = %s", data));
	}
    } else {
	X509 *cert = X509_STORE_CTX_get_current_cert(store);
	int depth = X509_STORE_CTX_get_error_depth(store);
	int err = X509_STORE_CTX_get_error(store);

	Error("SSLVerifyCallback(): error with certificate at depth: %d",
	      depth);
	X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
	Error("SSLVerifyCallback():  issuer  = %s", data);
	X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
	Error("SSLVerifyCallback():  subject = %s", data);
	Error("SSLVerifyCallback():  error #%d: %s", err,
	      X509_verify_cert_error_string(err));
    }
    return ok;
}
#endif

int
#if PROTOTYPES
SetFlags(int fd, int s, int c)
#else
SetFlags(fd, s, c)
    int fd, s, c;
#endif
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL)) >= 0) {
	flags |= s;
	flags &= ~c;
	if (fcntl(fd, F_SETFL, flags) < 0) {
	    Error("SetFlags(): fcntl(%u,F_SETFL): %s", fd,
		  strerror(errno));
	    return 0;
	}
    } else {
	Error("SetFlags(): fcntl(%u,F_GETFL): %s", fd, strerror(errno));
	return 0;
    }
    return 1;
}

char *
#if PROTOTYPES
StrDup(char *msg)
#else
StrDup(msg)
    char *msg;
#endif
{
    int len;
    char *buf;

    if (msg == (char *)0)
	return (char *)0;
    len = strlen(msg) + 1;
    buf = malloc(len);
    if (buf == (char *)0)
	return (char *)0;
#if HAVE_MEMCPY
    memcpy(buf, msg, len);
#else
    bcopy(msg, buf, len);
#endif
    return buf;
}
