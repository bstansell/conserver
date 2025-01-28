/*
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#include <compat.h>

#include <cutil.h>
#include <time.h>
#include <version.h>

#include <net/if.h>
#if USE_IPV6
# include <ifaddrs.h>
#endif
#if HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif
#if HAVE_OPENSSL
# include <openssl/ssl.h>
#endif


int fVerbose = 0, fErrorPrinted = 0;
int isMultiProc = 0;
char *progname = "conserver package";
pid_t thepid = 0;
int fDebug = 0;
STRING *allStrings = (STRING *)0;
int stringCount = 0;		/* count of allStrings list */
#if !USE_IPV6
struct in_addr *myAddrs = (struct in_addr *)0;
#endif
char myHostname[MAXHOSTNAME];	/* staff.cc.purdue.edu                  */
fd_set rinit;
fd_set winit;
int maxfd = 0;
int debugLineNo = 0;
char *debugFileName = (char *)0;
int isMaster = 1;

/* in the routines below (the init code) we can bomb if malloc fails	(ksb)
 */
void
OutOfMem(void)
{
    static char acNoMem[] = ": out of memory\n";

    write(2, progname, strlen(progname));
    write(2, acNoMem, sizeof(acNoMem) - 1);
    exit(EX_UNAVAILABLE);
}

/* do a general cleanup and exit */
void
Bye(int status)
{
    DestroyDataStructures();
#if HAVE_OPENSSL
# if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_free_strings();
# endif
#endif
    exit(status);
}

/* This returns a string with the current time in ascii form.
 * (same as ctime() but without the \n)
 * optionally returns the time in time_t form (pass in NULL if you don't care).
 * It's overwritten each time, so use it and forget it.
 */
const char *
StrTime(time_t *ltime)
{
    static char curtime[40];	/* just in case ctime() varies */
    time_t tyme;

    tyme = time((time_t *)0);
    StrCpy(curtime, ctime(&tyme), sizeof(curtime));
    curtime[24] = '\000';	/* might need to adjust this at some point */
    if (ltime != NULL)
	*ltime = tyme;
    return (const char *)curtime;
}

#define STRING_ALLOC_SIZE 64

char *
BuildStringChar(const char ch, STRING *msg)
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
BuildString(const char *str, STRING *msg)
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
BuildStringN(const char *str, int n, STRING *msg)
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

void *
MemMove(void *dest, void *src, size_t n)
{
#if HAVE_MEMMOVE
    return memmove(dest, src, n);
#else
    char *s = src;
    char *d = dest;

    if (s < d) {
	/* Moving from low mem to hi mem; start at end.  */
	for (s += n, d += n; n > 0; --n)
	    *--d = *--s;
    } else if (s != d) {
	/* Moving from hi mem to low mem; start at beginning.  */
	for (; n > 0; --n)
	    *d++ = *s++;
    }
    return dest;
#endif
}

char *
ShiftString(STRING *msg, int n)
{
    if (msg == (STRING *)0 || n <= 0 || n > msg->used - 1)
	return (char *)0;

    MemMove(msg->string, msg->string + n, msg->used - n);

    msg->used -= n;
    return msg->string;
}

void
InitString(STRING *msg)
{
    msg->string = (char *)0;
    msg->used = msg->allocated = 0;
}

void
DestroyString(STRING *msg)
{
    if (msg->prev == (STRING *)0 && msg->next == (STRING *)0 &&
	allStrings != msg) {
	CONDDEBUG((3, "DestroyString(): 0x%lx non-pooled string destroyed",
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
	CONDDEBUG((3,
		   "DestroyString(): 0x%lx string destroyed (count==%d)",
		   (void *)msg, stringCount));
    }
    if (msg->allocated)
	free(msg->string);
    free(msg);
}

STRING *
AllocString(void)
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
    CONDDEBUG((3, "AllocString(): 0x%lx created string #%d", (void *)s,
	       stringCount));
    return s;
}

void
DestroyStrings(void)
{
    while (allStrings != (STRING *)0) {
	DestroyString(allStrings);
    }
}

static STRING *mymsg = (STRING *)0;

char *
BuildTmpString(const char *str)
{
    if (mymsg == (STRING *)0)
	mymsg = AllocString();
    return BuildString(str, mymsg);
}

char *
BuildTmpStringChar(const char c)
{
    if (mymsg == (STRING *)0)
	mymsg = AllocString();
    return BuildStringChar(c, mymsg);
}

char *
ReadLine(FILE *fp, STRING *save, int *iLine)
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
	    StrCpy(buf, save->string, sizeof(buf));
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
FmtCtl(int ci, STRING *pcIn)
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
FmtCtlStr(char *pcIn, int len, STRING *pcOut)
{
    unsigned char c;

    BuildString((char *)0, pcOut);

    if (pcIn == (char *)0)
	return;

    if (len < 0)
	len = strlen(pcIn);

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
Debug(int level, char *fmt, ...)
{
    va_list ap;

    if (fDebug < level)
	return;
    va_start(ap, fmt);
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
Error(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
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
Msg(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
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
Verbose(char *fmt, ...)
{
    va_list ap;

    if (!fVerbose)
	return;

    va_start(ap, fmt);
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
SimpleSignal(int sig, void(*disp) (int))
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
GetMaxFiles(void)
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
#   endif
    /* !OPEN_MAX */
    mf = OPEN_MAX;
#  endif
    /* HAVE_GETDTABLESIZE */
# endif/* HAVE_GETRLIMIT */
#endif /* HAVE_SYSCONF */
#ifdef FD_SETSIZE
    if (FD_SETSIZE <= mf) {
	mf = (FD_SETSIZE - 1);
    }
#endif
    return mf;
}

/* Routines for the generic I/O stuff for conserver.  This will handle
 * all open(), close(), read(), and write() calls.
 */

/* This encapsulates a regular file descriptor in a CONSFILE
 * object.  Returns a CONSFILE pointer to that object.
 */
CONSFILE *
FileOpenFD(int fd, enum consFileType type)
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
#if DEBUG_CONSFILE_IO
    {
	char buf[1024];
	sprintf(buf, "CONSFILE-%s-%lu-%d.w", progname,
		(unsigned long)thepid, fd);
	if ((cfp->debugwfd =
	     open(buf, O_WRONLY | O_CREAT | O_APPEND, 0644)) != -1) {
	    sprintf(buf, "[---- STARTED - %s ----]\n",
		    StrTime((time_t *)0));
	    write(cfp->debugwfd, buf, strlen(buf));
	}
	sprintf(buf, "CONSFILE-%s-%lu-%d.r", progname,
		(unsigned long)thepid, fd);
	if ((cfp->debugrfd =
	     open(buf, O_WRONLY | O_CREAT | O_APPEND, 0644)) != -1) {
	    sprintf(buf, "[---- STARTED - %s ----]\n",
		    StrTime((time_t *)0));
	    write(cfp->debugrfd, buf, strlen(buf));
	}
    }
#endif

    CONDDEBUG((2, "FileOpenFD(): encapsulated fd %d type %d", fd, type));
    return cfp;
}

/* This encapsulates a pipe pair in a CONSFILE
 * object.  Returns a CONSFILE pointer to that object.
 */
CONSFILE *
FileOpenPipe(int fd, int fdout)
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
#if DEBUG_CONSFILE_IO
    {
	char buf[1024];
	sprintf(buf, "CONSFILE-%s-%lu-%d.w", progname,
		(unsigned long)thepid, fdout);
	if ((cfp->debugwfd =
	     open(buf, O_WRONLY | O_CREAT | O_APPEND, 0644)) != -1) {
	    sprintf(buf, "[---- STARTED - %s ----]\n",
		    StrTime((time_t *)0));
	    write(cfp->debugwfd, buf, strlen(buf));
	}
	sprintf(buf, "CONSFILE-%s-%lu-%d.r", progname,
		(unsigned long)thepid, fd);
	if ((cfp->debugrfd =
	     open(buf, O_WRONLY | O_CREAT | O_APPEND, 0644)) != -1) {
	    sprintf(buf, "[---- STARTED - %s ----]\n",
		    StrTime((time_t *)0));
	    write(cfp->debugrfd, buf, strlen(buf));
	}
    }
#endif

    CONDDEBUG((2, "FileOpenPipe(): encapsulated pipe pair fd %d and fd %d",
	       fd, fdout));
    return cfp;
}

/* This is to "unencapsulate" the file descriptor */
int
FileUnopen(CONSFILE *cfp)
{
    int retval = 0;

    if (cfp == (CONSFILE *)0)
	return 0;

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
	    retval = -1;
	    break;
    }
    CONDDEBUG((2, "FileUnopen(): unopened fd %d", cfp->fd));
    DestroyString(cfp->wbuf);
#if DEBUG_CONSFILE_IO
    if (cfp->debugwfd != -1)
	close(cfp->debugwfd);
    if (cfp->debugrfd != -1)
	close(cfp->debugrfd);
#endif
    free(cfp);

    return retval;
}

/* This opens a file like open(2).  Returns a CONSFILE pointer
 * or a (CONSFILE *)0 on error
 */
CONSFILE *
FileOpen(const char *path, int flag, int mode)
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
#if DEBUG_CONSFILE_IO
    {
	char buf[1024];
	sprintf(buf, "CONSFILE-%s-%lu-%d.w", progname,
		(unsigned long)thepid, fd);
	if ((cfp->debugwfd =
	     open(buf, O_WRONLY | O_CREAT | O_APPEND, 0644)) != -1) {
	    sprintf(buf, "[---- STARTED - %s ----]\n",
		    StrTime((time_t *)0));
	    write(cfp->debugwfd, buf, strlen(buf));
	}
	sprintf(buf, "CONSFILE-%s-%lu-%d.r", progname,
		(unsigned long)thepid, fd);
	if ((cfp->debugrfd =
	     open(buf, O_WRONLY | O_CREAT | O_APPEND, 0644)) != -1) {
	    sprintf(buf, "[---- STARTED - %s ----]\n",
		    StrTime((time_t *)0));
	    write(cfp->debugrfd, buf, strlen(buf));
	}
    }
#endif

    CONDDEBUG((2, "FileOpen(): opened `%s' as fd %d", path, fd));
    return cfp;
}

/* Unless otherwise stated, returns the same values as close(2).
 * The CONSFILE object passed in *CANNOT* be used once calling
 * this function - even if there was an error.
 */
int
FileClose(CONSFILE **pcfp)
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
	    SetFlags(cfp->fd, 0, O_NONBLOCK);

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

    if (cfp->ftype == simplePipe) {
	CONDDEBUG((2, "FileClose(): closed fd %d/%d", cfp->fd,
		   cfp->fdout));
    } else {
	CONDDEBUG((2, "FileClose(): closed fd %d", cfp->fd));
    }
    DestroyString(cfp->wbuf);
#if DEBUG_CONSFILE_IO
    if (cfp->debugwfd != -1)
	close(cfp->debugwfd);
    if (cfp->debugrfd != -1)
	close(cfp->debugrfd);
#endif
    free(cfp);
    *pcfp = (CONSFILE *)0;

    return retval;
}

/* returns: -1 on error or eof, >= 0 for valid reads */
int
FileRead(CONSFILE *cfp, void *buf, int len)
{
    int retval = -1;

    if (cfp->errored == FLAGTRUE)
	return -1;

    switch (cfp->ftype) {
	case simpleFile:
	case simplePipe:
	case simpleSocket:
	    while (retval < 0) {
		if ((retval = read(cfp->fd, buf, len)) <= 0) {
		    CONDDEBUG((2,
			       "FileRead(): read(): fd=%d, retval=%d, errno=%d",
			       cfp->fd, retval, errno));
		    if (retval == 0 || errno == EIO) {
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
#if DEBUG_CONSFILE_IO
		if (cfp->debugrfd != -1)
		    write(cfp->debugrfd, buf, retval);
#endif
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
# if DEBUG_CONSFILE_IO
	    if (cfp->debugrfd != -1)
		write(cfp->debugrfd, buf, retval);
# endif
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

    if (retval < 0)
	cfp->errored = FLAGTRUE;

    return retval;
}

/* returns: -1 on error or eof, >= 0 for valid reads */
int
FileWrite(CONSFILE *cfp, FLAG bufferonly, char *buf, int len)
{
    int len_orig = len;
    int len_out = 0;
    int retval = 0;
    int fdout = 0;

    if (cfp->ftype == simplePipe)
	fdout = cfp->fdout;
    else
	fdout = cfp->fd;

    if (cfp->errored == FLAGTRUE) {
	if (cfp->wbuf->used > 1)
	    BuildString((char *)0, cfp->wbuf);
	FD_CLR(fdout, &winit);
	return -1;
    }

    if (len < 0 && buf != (char *)0)
	len = strlen(buf);

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
    if (len > 0 && buf != (char *)0) {
	if (cfp->quoteiac == FLAGTRUE) {
	    int l, o;
	    for (o = l = 0; l < len; l++) {
		if (buf[l] == (char)OB_IAC) {
		    BuildStringN(buf + o, l + 1 - o, cfp->wbuf);
		    BuildStringChar((char)OB_IAC, cfp->wbuf);
		    o = l + 1;
		}
	    }
	    if (o < len)
		BuildStringN(buf + o, len - o, cfp->wbuf);
	} else
	    BuildStringN(buf, len, cfp->wbuf);
    }

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
		    CONDDEBUG((2,
			       "FileWrite(): write(): fd=%d, retval=%d, errno=%d, len=%d",
			       fdout, retval, errno, len));
		    if (errno == EINTR)
			continue;
		    if (errno == EAGAIN) {
			/* must be non-blocking - so stop */
			retval = 0;
			break;
		    }
		    retval = -1;
		    /* i believe, as of 8.0.8, we need to just ignore
		     * this and actually produce the error message
		     * below.  perhaps we'll have a lot of extra
		     * FileWrite() errors, perhaps not.  things shouldn't
		     * just close down and cause errors in normal cases,
		     * right?!?  -bryan
		     * maybe not right now, actually.  i'm going to check
		     * the return code of FileWrite() on the "important"
		     * things and let the others silently fail and have
		     * the FileRead() catch problems - like it has been
		     * doing.  i really should be checking all the return
		     * codes...and i'm sure i'll get there eventually.
		     */
		    if (errno == EPIPE)
			break;
		    Error("FileWrite(): fd %d: %s", fdout,
			  strerror(errno));
		    break;
		}
#if DEBUG_CONSFILE_IO
		if (cfp->debugwfd != -1)
		    write(cfp->debugwfd, buf, retval);
#endif
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
# if DEBUG_CONSFILE_IO
		if (cfp->debugwfd != -1)
		    write(cfp->debugwfd, buf, retval);
# endif
		buf += retval;
		len -= retval;
		len_out += retval;
	    }
	    break;
#endif
	default:
	    retval = -1;
	    break;
    }

    /* so, if we saw an error, just bail...all is done anyway */
    if (retval >= 0) {
	if (len_out > 0) {
	    /* save the rest for later */
	    if (len > 0) {
		ShiftString(cfp->wbuf, len_out);
	    } else {
		BuildString((char *)0, cfp->wbuf);
	    }
	}
	retval = len_out;
    }

    if (retval < 0) {
	if (cfp->wbuf->used > 1)
	    BuildString((char *)0, cfp->wbuf);
	cfp->errored = FLAGTRUE;
    }

    if (cfp->wbuf->used <= 1)
	FD_CLR(fdout, &winit);
    else {
	FD_SET(fdout, &winit);
	CONDDEBUG((2, "FileWrite(): buffered %d byte%s for fd %d",
		   (cfp->wbuf->used <= 1) ? 0 : cfp->wbuf->used,
		   (cfp->wbuf->used <= 1) ? "" : "s", fdout));
    }

    if (retval >= 0) {
	CONDDEBUG((2, "FileWrite(): wrote %d byte%s to fd %d", retval,
		   (retval == 1) ? "" : "s", fdout));
    } else {
	CONDDEBUG((2, "FileWrite(): write of %d byte%s to fd %d: %s",
		   len_orig, (retval == -1) ? "" : "s", fdout,
		   strerror(errno)));
    }

    return retval;
}

int
FileCanRead(CONSFILE *cfp, fd_set *prfd, fd_set *pwfd)
{
#if HAVE_OPENSSL
    int fdout;
#endif

    if (cfp == (CONSFILE *)0)
	return 0;

#if HAVE_OPENSSL
    if (cfp->ftype == simplePipe)
	fdout = cfp->fdout;
    else
	fdout = cfp->fd;
#endif

    return ((FD_ISSET(cfp->fd, prfd)
#if HAVE_OPENSSL
	     && cfp->waitForRead != FLAGTRUE) || (fdout >= 0 &&
						  FD_ISSET(fdout, pwfd)
						  && cfp->waitForWrite ==
						  FLAGTRUE
#endif
	    ));
}

int
FileCanWrite(CONSFILE *cfp, fd_set *prfd, fd_set *pwfd)
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
FileBufEmpty(CONSFILE *cfp)
{
    if (cfp == (CONSFILE *)0)
	return 1;
    return (cfp->wbuf->used <= 1);
}

void
VWrite(CONSFILE *cfp, FLAG bufferonly, STRING *str, char *fmt, va_list ap)
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
			if (p == (char *)0)
			    p = "(null)";
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
BuildStringPrint(STRING *str, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    VWrite((CONSFILE *)0, FLAGFALSE, str, fmt, ap);
    va_end(ap);
    if (str == (STRING *)0)
	return (char *)0;
    else
	return str->string;
}

char *
BuildTmpStringPrint(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (mymsg == (STRING *)0)
	mymsg = AllocString();
    VWrite((CONSFILE *)0, FLAGFALSE, mymsg, fmt, ap);
    va_end(ap);
    return mymsg->string;
}

void
FileVWrite(CONSFILE *cfp, FLAG bufferonly, char *fmt, va_list ap)
{
    VWrite(cfp, bufferonly, (STRING *)0, fmt, ap);
}

void
FilePrint(CONSFILE *cfp, FLAG bufferonly, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    FileVWrite(cfp, bufferonly, fmt, ap);
    va_end(ap);
}

/* Unless otherwise stated, returns the same values as fstat(2) */
int
FileStat(CONSFILE *cfp, struct stat *buf)
{
    int retval = 0;

    if (cfp->errored == FLAGTRUE)
	return -1;

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

    if (retval < 0)
	cfp->errored = FLAGTRUE;

    return retval;
}

/* Unless otherwise stated, returns the same values as lseek(2) */
int
FileSeek(CONSFILE *cfp, off_t offset, int whence)
{
    int retval = 0;

    if (cfp->errored == FLAGTRUE)
	return -1;

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

    if (retval < 0)
	cfp->errored = FLAGTRUE;

    return retval;
}

/* Returns the file descriptor number of the underlying file */
int
FileFDNum(CONSFILE *cfp)
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
FileFDOutNum(CONSFILE *cfp)
{
    if (cfp == (CONSFILE *)0 || cfp->ftype != simplePipe)
	return -1;

    return cfp->fdout;
}

/* Returns the file type */
enum consFileType
FileGetType(CONSFILE *cfp)
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
FileSetType(CONSFILE *cfp, enum consFileType type)
{
    cfp->ftype = type;
}

/* Sets the file quoting method */
void
FileSetQuoteIAC(CONSFILE *cfp, FLAG flag)
{
    cfp->quoteiac = flag;
}

FLAG
FileSawQuoteSusp(CONSFILE *cfp)
{
    FLAG r = cfp->sawiacsusp;
    cfp->sawiacsusp = FLAGFALSE;
    return r;
}

FLAG
FileSawQuoteExec(CONSFILE *cfp)
{
    FLAG r = cfp->sawiacexec;
    cfp->sawiacexec = FLAGFALSE;
    return r;
}

FLAG
FileSawQuoteAbrt(CONSFILE *cfp)
{
    FLAG r = cfp->sawiacabrt;
    cfp->sawiacabrt = FLAGFALSE;
    return r;
}

FLAG
FileSawQuoteGoto(CONSFILE *cfp)
{
    FLAG r = cfp->sawiacgoto;
    cfp->sawiacgoto = FLAGFALSE;
    return r;
}

#if HAVE_OPENSSL
/* Get the SSL instance */
SSL *
FileGetSSL(CONSFILE *cfp)
{
    return cfp->ssl;
}

/* Sets the SSL instance */
void
FileSetSSL(CONSFILE *cfp, SSL *ssl)
{
    cfp->ssl = ssl;
}

/* return -1 on error, 0 for "wait" state, 1 for success */
int
FileCanSSLAccept(CONSFILE *cfp, fd_set *prfd, fd_set *pwfd)
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
FileSSLAccept(CONSFILE *cfp)
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
FileSend(CONSFILE *cfp, const void *msg, size_t len, int flags)
{
    int retval = 0;
    int fdout;

    if (cfp->ftype == simplePipe)
	fdout = cfp->fdout;
    else
	fdout = cfp->fd;

    if (cfp->errored == FLAGTRUE) {
	FD_CLR(fdout, &winit);
	return -1;
    }

    switch (cfp->ftype) {
	case simpleFile:
	    retval = send(fdout, msg, len, flags);
	    break;
	case simplePipe:
	    retval = send(fdout, msg, len, flags);
	    break;
	case simpleSocket:
	    retval = send(fdout, msg, len, flags);
	    break;
#if HAVE_OPENSSL
	case SSLSocket:
	    retval = send(fdout, msg, len, flags);
	    break;
#endif
	default:
	    retval = -1;
	    break;
    }

    if (retval < 0) {
	cfp->errored = FLAGTRUE;
	FD_CLR(fdout, &winit);
    }

    return retval;
}

/* replace trailing space with '\000' in a string and return
 * a pointer to the start of the non-space part
 */
char *
PruneSpace(char *string)
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

#if !USE_IPV6
/* fills the myAddrs array with host interface addresses */
void
ProbeInterfaces(in_addr_t bindAddr)
{
# ifdef SIOCGIFCONF
    struct ifconf ifc;
    struct ifreq *ifr;
#  ifdef SIOCGIFFLAGS
    struct ifreq ifrcopy;
#  endif
#  ifdef SIOCGIFNUM
    int nifr;
#  endif
    int sock;
    int r = 0, m = 0;
    int bufsize = 2048;
    int count = 0;

    /* if we use -M, just fill the array with that interface */
    if (bindAddr != INADDR_ANY) {
	myAddrs = (struct in_addr *)calloc(2, sizeof(struct in_addr));
	if (myAddrs == (struct in_addr *)0)
	    OutOfMem();
#  if HAVE_MEMCPY
	memcpy(&(myAddrs[0].s_addr), &bindAddr, sizeof(in_addr_t));
#  else
	bcopy(&bindAddr, &(myAddrs[0].s_addr), sizeof(in_addr_t));
#  endif
	Verbose("interface address %s (-M option)", inet_ntoa(myAddrs[0]));
	return;
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	Error("ProbeInterfaces(): socket(): %s", strerror(errno));
	Bye(EX_OSERR);
    }
#  ifdef SIOCGIFNUM
    if (ioctl(sock, SIOCGIFNUM, &nifr) == 0)
	bufsize = nifr * sizeof(struct ifreq) + 512;
#  endif

    while (bufsize) {
	ifc.ifc_len = bufsize;
	ifc.ifc_req = (struct ifreq *)malloc(ifc.ifc_len);
	if (ifc.ifc_req == (struct ifreq *)0)
	    OutOfMem();
	if (ioctl(sock, SIOCGIFCONF, &ifc) != 0 && errno != EINVAL) {
	    free(ifc.ifc_req);
	    close(sock);
	    Error("ProbeInterfaces(): ioctl(SIOCGIFCONF): %s",
		  strerror(errno));
	    Bye(EX_OSERR);
	}
	/* if the return size plus a 512 byte "buffer zone" is less than
	 * the buffer we passed in (bufsize), we're done.  otherwise
	 * allocate a bigger buffer and try again.  with a too-small
	 * buffer, some implementations (freebsd) will fill the buffer
	 * best it can (leaving a gap - returning <=bufsize) and others
	 * (linux) will return a buffer length the same size as passed
	 * in (==bufsize).  so, we'll assume a 512 byte gap would have
	 * been big enough to put one more record and as long as we have
	 * that "buffer zone", we should have all the interfaces.
	 * so, solaris returns EINVAL if it's too small, so we catch that
	 * above and since if_len is bufsize, it'll loop again.
	 */
	if (ifc.ifc_len + 512 < bufsize)
	    break;
	free(ifc.ifc_req);
	bufsize += 2048;
    }

    /* this is probably way overkill, but better to kill a few bytes
     * than loop through looking for valid interfaces that are up
     * twice, huh?
     */
    count = ifc.ifc_len / sizeof(*ifr);
    CONDDEBUG((1, "ProbeInterfaces(): ifc_len==%d max_count==%d",
	       ifc.ifc_len, count));

    /* set up myAddrs array */
    if (myAddrs != (struct in_addr *)0)
	free(myAddrs);
    myAddrs = (struct in_addr *)0;
    if (count == 0) {
	free(ifc.ifc_req);
	close(sock);
	return;
    }
    myAddrs = (struct in_addr *)calloc(count + 1, sizeof(struct in_addr));
    if (myAddrs == (struct in_addr *)0)
	OutOfMem();

    for (m = r = 0; r < ifc.ifc_len;) {
	struct sockaddr *sa;
	ifr = (struct ifreq *)&ifc.ifc_buf[r];
	sa = (struct sockaddr *)&ifr->ifr_addr;
	/* don't use less than a ifreq sized chunk */
	if ((ifc.ifc_len - r) < sizeof(*ifr))
	    break;
#  ifdef HAVE_SA_LEN
#   ifdef __FreeBSD__
	if (sa->sa_len > sizeof(ifr->ifr_addr))
#   else
	if (sa->sa_len > sizeof(ifr->ifr_ifru))
#   endif
	    r += sizeof(ifr->ifr_name) + sa->sa_len;
	else
#  endif
	    r += sizeof(*ifr);

	if (sa->sa_family == AF_INET) {
	    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	    /* make sure the address isn't 0.0.0.0, which is how we
	     * signal the end of our list
	     */
	    if (
#  if HAVE_MEMCMP
		   memcmp(&(myAddrs[m]), &(sin->sin_addr),
			  sizeof(struct in_addr))
#  else
		   bcmp(&(myAddrs[m]), &(sin->sin_addr),
			sizeof(struct in_addr))
#  endif
		   == 0)
		continue;

#  ifdef SIOCGIFFLAGS
	    /* make sure the interface is up */
	    ifrcopy = *ifr;
	    if ((ioctl(sock, SIOCGIFFLAGS, &ifrcopy) == 0) &&
		((ifrcopy.ifr_flags & IFF_UP) == 0))
		continue;
#  endif

	    CONDDEBUG((1, "ProbeInterfaces(): name=%s addr=%s",
		       ifr->ifr_name, inet_ntoa(sin->sin_addr)));

#  if HAVE_MEMCPY
	    memcpy(&myAddrs[m], &(sin->sin_addr), sizeof(struct in_addr));
#  else
	    bcopy(&(sin->sin_addr), &myAddrs[m], sizeof(struct in_addr));
#  endif

	    Verbose("interface address %s (%s)", inet_ntoa(myAddrs[m]),
		    ifr->ifr_name);
	    m++;
	}
    }
    if (m == 0) {
	free(myAddrs);
	myAddrs = (struct in_addr *)0;
    }
    close(sock);
    free(ifc.ifc_req);
# else/* use the hostname like the old code did (but use all addresses!) */
    int count;
    struct hostent *he;

    /* if we use -M, just fill the array with that interface */
    if (bindAddr != INADDR_ANY) {
	myAddrs = (struct in_addr *)calloc(2, sizeof(struct in_addr));
	if (myAddrs == (struct in_addr *)0)
	    OutOfMem();
#  if HAVE_MEMCPY
	memcpy(&(myAddrs[0].s_addr), &bindAddr, sizeof(in_addr_t));
#  else
	bcopy(&bindAddr, &(myAddrs[0].s_addr), sizeof(in_addr_t));
#  endif
	Verbose("interface address %s (-M option)", inet_ntoa(myAddrs[0]));
	return;
    }

    Verbose("using hostname for interface addresses");
    if ((struct hostent *)0 == (he = gethostbyname(myHostname))) {
	Error("ProbeInterfaces(): gethostbyname(%s): %s", myHostname,
	      hstrerror(h_errno));
	return;
    }
    if (4 != he->h_length || AF_INET != he->h_addrtype) {
	Error
	    ("ProbeInterfaces(): gethostbyname(%s): wrong address size (4 != %d) or address family (%d != %d)",
	     myHostname, he->h_length, AF_INET, he->h_addrtype);
	return;
    }

    for (count = 0; he->h_addr_list[count] != (char *)0; count++);
    if (myAddrs != (struct in_addr *)0)
	free(myAddrs);
    myAddrs = (struct in_addr *)0;
    if (count == 0)
	return;
    myAddrs = (struct in_addr *)calloc(count + 1, sizeof(struct in_addr));
    if (myAddrs == (struct in_addr *)0)
	OutOfMem();
    for (count--; count >= 0; count--) {
#  if HAVE_MEMCPY
	memcpy(&(myAddrs[count].s_addr), he->h_addr_list[count],
	       he->h_length);
#  else
	bcopy(he->h_addr_list[count], &(myAddrs[count].s_addr),
	      he->h_length);
#  endif
	Verbose("interface address %s (hostname address)",
		inet_ntoa(myAddrs[count]));
    }
# endif
}
#endif /* USE_IPV6 */

int
IsMe(char *id)
{
#if USE_IPV6
    int ret = 0;
    int error;
    struct addrinfo hints;
    struct addrinfo *res, *rp;
    struct ifaddrs *myAddrs, *ifa;
    void *a, *b;
    size_t len;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;

    /* get IP based on hostname */
    error = getaddrinfo(id, NULL, &hints, &res);
    if (error) {
	perror(gai_strerror(error));
	return 0;
    }

    /* get list of all addresses on system */
    error = getifaddrs(&myAddrs);
    if (error) {
	perror("getifaddrs failed");
	return 0;
    }

    /* try to find a match */
    for (ifa = myAddrs; ifa != NULL; ifa = ifa->ifa_next) {
	/* skip interfaces without address or in down state */
	if (ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP))
	    continue;

	for (rp = res; rp != NULL; rp = rp->ai_next) {
	    if (ifa->ifa_addr->sa_family == rp->ai_addr->sa_family) {
		/* I really don't like to hardcode it but we have to */
		if (ifa->ifa_addr->sa_family == AF_INET) {	/* IPv4 */
		    a = &(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);
		    b = &(((struct sockaddr_in *)rp->ai_addr)->sin_addr);
		    len = sizeof(struct in_addr);
		} else {	/* IPv6 */
		    a = &(((struct sockaddr_in6 *)ifa->
			   ifa_addr)->sin6_addr);
		    b = &(((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr);
		    len = sizeof(struct in6_addr);
		}

		if (
# if HAVE_MEMCMP
		       memcmp(a, b, len)
# else
		       bcmp(a, b, len)
# endif
		       == 0) {
		    ret = 1;
		    goto done;
		}
	    }
	}
    }

  done:
    freeaddrinfo(res);
    freeifaddrs(myAddrs);
    CONDDEBUG((1, "IsMe: ret %d id %s", ret, id));
    return ret;
#else
    int j, i;
    struct hostent *he;
    in_addr_t addr;
# if HAVE_INET_ATON
    struct in_addr inetaddr;
# endif

    /* check for ip address match */
# if HAVE_INET_ATON
    if (inet_aton(id, &inetaddr) != 0) {
	addr = inetaddr.s_addr;
# else
    addr = inet_addr(id);
    if (addr != (in_addr_t) (-1)) {
# endif
	for (i = 0;
	     myAddrs != (struct in_addr *)0 &&
	     myAddrs[i].s_addr != (in_addr_t) 0; i++) {
	    if (
# if HAVE_MEMCMP
		   memcmp(&(myAddrs[i].s_addr), &addr, sizeof(addr))
# else
		   bcmp(&(myAddrs[i].s_addr), &addr, sizeof(addr))
# endif
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
# if HAVE_MEMCMP
		   memcmp(&(myAddrs[i].s_addr), he->h_addr_list[j],
			  he->h_length)
# else
		   bcmp(&(myAddrs[i].s_addr), he->h_addr_list[j],
			he->h_length)
# endif
		   == 0)
		return 1;
	}
    }
    return 0;
#endif /* USE_IPV6 */
}

#if HAVE_OPENSSL
/* Unless otherwise stated, returns the same values as send(2) */
int
SSLVerifyCallback(int ok, X509_STORE_CTX *store)
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
SetFlags(int fd, int s, int c)
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
StrDup(const char *msg)
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

char *
StringChar(STRING *msg, int offset, char c)
{
    int o;

    if (msg == (STRING *)0 || msg->used <= 1 || offset < 0 ||
	offset > msg->used)
	return (char *)0;

    for (o = offset; o != msg->used; o++) {
	if (msg->string[o] == c)
	    return &(msg->string[o]);
    }
    return (char *)0;
}

/* this takes a buffer, and returns the number of characters to use,
 * which goes up to the first OB_IAC character sequence (that isn't
 * OB_IAC/OB_IAC).  if it is an OB_IAC sequence, it sets the flag and
 * returns zero.  if it's invalid args, we return -1.
 * so <0 == no data, 0 == check flags, >0 number of chars to use
 * this *WILL* modify the buffer (OB_IAC sequences get extracted/shrunk)
 */
int
ParseIACBuf(CONSFILE *cfp, void *msg, int *len)
{
    int l = 0;
    unsigned char *b = msg;

    if (*len <= 0)
	return -1;

    if (cfp->quoteiac != FLAGTRUE)
	return *len;

    /* split OB_IAC/char pair OR OB_IAC at start */
    if (cfp->sawiac == FLAGTRUE || b[0] == OB_IAC) {
	int i = 1;

	if (cfp->sawiac == FLAGTRUE) {
	    i = 0;
	    cfp->sawiac = FLAGFALSE;
	}
	if (i == *len) {	/* only thing is OB_IAC */
	    cfp->sawiac = FLAGTRUE;
	    return -1;
	}

	if (b[i] == OB_SUSP)
	    cfp->sawiacsusp = FLAGTRUE;
	else if (b[i] == OB_EXEC)
	    cfp->sawiacexec = FLAGTRUE;
	else if (b[i] == OB_ABRT)
	    cfp->sawiacabrt = FLAGTRUE;
	else if (b[i] == OB_GOTO)
	    cfp->sawiacgoto = FLAGTRUE;
	else {
	    if (b[i] != OB_IAC)
		Error
		    ("ParseIACBuf(): fd %d: unrecognized quoted-OB_IAC char",
		     cfp->fd, strerror(errno));
	    l = 1;
	}
	*len = *len - i - 1 + l;
	MemMove(b, b + i + 1 - l, *len);
	if (l == 0)
	    return 0;
    }
    for (; l < *len; l++) {
	if (b[l] == OB_IAC) {
	    if (l + 1 == *len)
		return l;

	    if (b[l + 1] == OB_IAC) {
		--(*len);
		MemMove(b + l, b + l + 1, *len - l);
	    } else {
		return l;
	    }
	}
    }
    return l;
}

/* the format of the file should be as follows
 *
 * <section keyword> [section name] {
 *      <item keyword> [item value];
 *                   .
 *                   .
 * }
 *
 * whitespace gets retained in [section name], and [item value]
 * values.  for example,
 *
 *    users  bryan  todd ;
 *
 *  will give users the value of 'bryan  todd'.  the leading and
 *  trailing whitespace is nuked, but the middle stuff isn't.
 *
 *  a little note about the 'state' var...
 *      START = before <section keyword>
 *      NAME = before [section name]
 *      LEFTB = before left curly brace
 *      KEY = before <item keyword>
 *      VALUE = before [item value]
 *      SEMI = before semi-colon
 */

typedef enum states {
    START,
    NAME,
    LEFTB,
    KEY,
    VALUE,
    SEMI
} STATES;

typedef enum tokens {
    DONE,
    LEFTBRACE,
    RIGHTBRACE,
    SEMICOLON,
    WORD,
    INCLUDE
} TOKEN;

int line = 1;			/* current line number */
char *file = (char *)0;

TOKEN
GetWord(FILE *fp, int *line, short spaceok, STRING *word)
{
    int c;
    short backslash = 0;
    short quote = 0;
    short comment = 0;
    short sawQuote = 0;
    short quotedBackslash = 0;
    char *include = "include";
    short checkInc = -1;
    /* checkInc == -3, saw #include
     *          == -2, saw nothin'
     *          == -1, saw \n or start of file
     *          == 0, saw "\n#"
     */

    BuildString((char *)0, word);
    while ((c = fgetc(fp)) != EOF) {
	if (c == '\n') {
	    (*line)++;
	    if (checkInc == -2 || checkInc == 0)
		checkInc = -1;
	}
	if (comment) {
	    if (c == '\n')
		comment = 0;
	    if (checkInc >= 0) {
		if (include[checkInc] == '\000') {
		    if (isspace(c))
			checkInc = -3;
		} else if (c == include[checkInc])
		    checkInc++;
		else
		    checkInc = -2;
	    } else if (checkInc == -3) {
		static STRING *fname = (STRING *)0;
		if (fname == (STRING *)0)
		    fname = AllocString();
		if (fname->used != 0 || !isspace(c)) {
		    if (c == '\n') {
			if (fname->used > 0) {
			    while (fname->used > 1 && isspace((int)
							      (fname->
							       string
							       [fname->
								used -
								2])))
				fname->used--;
			    if (fname->used > 0)
				fname->string[fname->used - 1] = '\000';
			}
			checkInc = -2;
			if (fname->used > 0) {
			    BuildString((char *)0, word);
			    BuildString(fname->string, word);
			    BuildString((char *)0, fname);
			    return INCLUDE;
			}
		    } else
			BuildStringChar(c, fname);
		}
	    }
	    continue;
	}
	if (backslash) {
	    BuildStringChar(c, word);
	    backslash = 0;
	    continue;
	}
	if (quote) {
	    if (c == '"') {
		if (quotedBackslash) {
		    BuildStringChar(c, word);
		    quotedBackslash = 0;
		} else
		    quote = 0;
	    } else {
		if (quotedBackslash) {
		    BuildStringChar('\\', word);
		    quotedBackslash = 0;
		}
		if (c == '\\')
		    quotedBackslash = 1;
		else
		    BuildStringChar(c, word);
	    }
	    continue;
	}
	if (c == '\\') {
	    backslash = 1;
	} else if (c == '#') {
	    comment = 1;
	    if (checkInc == -1)
		checkInc = 0;
	} else if (c == '"') {
	    quote = 1;
	    sawQuote = 1;
	} else if (isspace(c)) {
	    if (word->used <= 1)
		continue;
	    if (spaceok) {
		BuildStringChar(c, word);
		continue;
	    }
	  gotword:
	    while (word->used > 1 &&
		   isspace((int)(word->string[word->used - 2])))
		word->used--;
	    if (word->used > 0)
		word->string[word->used - 1] = '\000';
	    return WORD;
	} else if (c == '{') {
	    if (word->used <= 1 && !sawQuote) {
		BuildStringChar(c, word);
		return LEFTBRACE;
	    } else {
		ungetc(c, fp);
		goto gotword;
	    }
	} else if (c == '}') {
	    if (word->used <= 1 && !sawQuote) {
		BuildStringChar(c, word);
		return RIGHTBRACE;
	    } else {
		ungetc(c, fp);
		goto gotword;
	    }
	} else if (c == ';') {
	    if (word->used <= 1 && !sawQuote) {
		BuildStringChar(c, word);
		return SEMICOLON;
	    } else {
		ungetc(c, fp);
		goto gotword;
	    }
	} else {
	    BuildStringChar(c, word);
	}
    }
    /* this should only happen in rare cases */
    if (quotedBackslash) {
	BuildStringChar('\\', word);
	quotedBackslash = 0;
    }
    /* if we saw "valid" data, it's a word */
    if (word->used > 1 || sawQuote)
	goto gotword;
    return DONE;
}

void
ParseFile(char *filename, FILE *fp, int level)
{
    /* things that should be used between recursions */
    static STATES state = START;
    static STRING *word = (STRING *)0;
    static short spaceok = 0;
    static int secIndex = 0;
    static int keyIndex = 0;

    /* other stuff that's local to each recursion */
    char *p;
    TOKEN token = DONE;
    int nextline = 1;		/* "next" line number */

    if (level >= 10) {
	if (isMaster)
	    Error("ParseFile(): nesting too deep, not parsing `%s'",
		  filename);
	return;
    }

    /* set some globals */
    line = 1;
    file = filename;

    /* if we're parsing the base file, set static vars */
    if (level == 0) {
	state = START;
	spaceok = 0;
	secIndex = 0;
	keyIndex = 0;
    }

    /* initialize local things */
    if (word == (STRING *)0)
	word = AllocString();

    while ((token = GetWord(fp, &nextline, spaceok, word)) != DONE) {
	if (token == INCLUDE) {
	    FILE *lfp;
	    if ((FILE *)0 == (lfp = fopen(word->string, "r"))) {
		if (isMaster)
		    Error("ParseFile(): fopen(%s): %s", word->string,
			  strerror(errno));
	    } else {
		char *fname;
		char *sfile;
		int sline;
		/* word gets destroyed, so save the name */
		fname = StrDup(word->string);
		sfile = file;
		sline = line;
		ParseFile(fname, lfp, level + 1);
		fclose(lfp);
		free(fname);
		file = sfile;
		line = sline;
	    }
	} else {
	    switch (state) {
		case START:
		    switch (token) {
			case WORD:
			    for (secIndex = 0;
				 (p = sections[secIndex].id) != (char *)0;
				 secIndex++) {
				if (strcasecmp(word->string, p) == 0) {
				    CONDDEBUG((1,
					       "ReadCfg(): got keyword '%s' [%s:%d]",
					       word->string, file, line));
				    state = NAME;
				    break;
				}
			    }
			    if (state == START) {
				if (isMaster)
				    Error("invalid keyword '%s' [%s:%d]",
					  word->string, file, line);
			    }
			    break;
			case LEFTBRACE:
			case RIGHTBRACE:
			case SEMICOLON:
			    if (isMaster)
				Error("invalid token '%s' [%s:%d]",
				      word->string, file, line);
			    break;
			case DONE:	/* just shutting up gcc */
			case INCLUDE:	/* just shutting up gcc */
			    break;
		    }
		    break;
		case NAME:
		    switch (token) {
			case WORD:
			    (*sections[secIndex].begin) (word->string);
			    state = LEFTB;
			    break;
			case RIGHTBRACE:
			    if (isMaster)
				Error("premature token '%s' [%s:%d]",
				      word->string, file, line);
			    state = START;
			    break;
			case LEFTBRACE:
			case SEMICOLON:
			    if (isMaster)
				Error("invalid token '%s' [%s:%d]",
				      word->string, file, line);
			    break;
			case DONE:	/* just shutting up gcc */
			case INCLUDE:	/* just shutting up gcc */
			    break;
		    }
		    break;
		case LEFTB:
		    switch (token) {
			case LEFTBRACE:
			    state = KEY;
			    break;
			case RIGHTBRACE:
			    if (isMaster)
				Error("premature token '%s' [%s:%d]",
				      word->string, file, line);
			    (*sections[secIndex].abort) ();
			    state = START;
			    break;
			case SEMICOLON:
			    if (isMaster)
				Error("invalid token '%s' [%s:%d]",
				      word->string, file, line);
			    break;
			case WORD:
			    if (isMaster)
				Error("invalid word '%s' [%s:%d]",
				      word->string, file, line);
			    break;
			case DONE:	/* just shutting up gcc */
			case INCLUDE:	/* just shutting up gcc */
			    break;
		    }
		    break;
		case KEY:
		    switch (token) {
			case WORD:
			    for (keyIndex = 0;
				 (p =
				  sections[secIndex].items[keyIndex].id) !=
				 (char *)0; keyIndex++) {
				if (strcasecmp(word->string, p) == 0) {
				    CONDDEBUG((1,
					       "got keyword '%s' [%s:%d]",
					       word->string, file, line));
				    state = VALUE;
				    break;
				}
			    }
			    if (state == KEY) {
				if (isMaster)
				    Error("invalid keyword '%s' [%s:%d]",
					  word->string, file, line);
			    }
			    break;
			case RIGHTBRACE:
			    (*sections[secIndex].end) ();
			    state = START;
			    break;
			case LEFTBRACE:
			    if (isMaster)
				Error("invalid token '%s' [%s:%d]",
				      word->string, file, line);
			    break;
			case SEMICOLON:
			    if (isMaster)
				Error("premature token '%s' [%s:%d]",
				      word->string, file, line);
			case DONE:	/* just shutting up gcc */
			case INCLUDE:	/* just shutting up gcc */
			    break;
		    }
		    break;
		case VALUE:
		    switch (token) {
			case WORD:
			    (*sections[secIndex].
			     items[keyIndex].reg) (word->string);
			    state = SEMI;
			    break;
			case SEMICOLON:
			    if (isMaster)
				Error("invalid token '%s' [%s:%d]",
				      word->string, file, line);
			    state = KEY;
			    break;
			case RIGHTBRACE:
			    if (isMaster)
				Error("premature token '%s' [%s:%d]",
				      word->string, file, line);
			    (*sections[secIndex].abort) ();
			    state = START;
			    break;
			case LEFTBRACE:
			    if (isMaster)
				Error("invalid token '%s' [%s:%d]",
				      word->string, file, line);
			    break;
			case DONE:	/* just shutting up gcc */
			case INCLUDE:	/* just shutting up gcc */
			    break;
		    }
		    break;
		case SEMI:
		    switch (token) {
			case SEMICOLON:
			    state = KEY;
			    break;
			case RIGHTBRACE:
			    if (isMaster)
				Error("premature token '%s' [%s:%d]",
				      word->string, file, line);
			    (*sections[secIndex].abort) ();
			    state = START;
			    break;
			case LEFTBRACE:
			    if (isMaster)
				Error("invalid token '%s' [%s:%d]",
				      word->string, file, line);
			    break;
			case WORD:
			    if (isMaster)
				Error("invalid word '%s' [%s:%d]",
				      word->string, file, line);
			    break;
			case DONE:	/* just shutting up gcc */
			case INCLUDE:	/* just shutting up gcc */
			    break;
		    }
		    break;
	    }
	    switch (state) {
		case NAME:
		case VALUE:
		    spaceok = 1;
		    break;
		case KEY:
		case LEFTB:
		case START:
		case SEMI:
		    spaceok = 0;
		    break;
	    }
	}
	line = nextline;
    }

    if (level == 0) {
	int i;

	/* check for proper ending of file and do any cleanup */
	switch (state) {
	    case START:
		break;
	    case KEY:
	    case LEFTB:
	    case VALUE:
	    case SEMI:
		(*sections[secIndex].abort) ();
		/* fall through */
	    case NAME:
		if (isMaster)
		    Error("premature EOF seen [%s:%d]", file, line);
		break;
	}

	/* now clean up all the temporary space used */
	for (i = 0; sections[i].id != (char *)0; i++) {
	    (*sections[i].destroy) ();
	}
    }
}

void
ProcessSubst(SUBST *s, char **repl, char **str, char *name, char *id)
{
    /*
     * (CONSENT *pCE) and (char **repl) are used when a replacement is to
     * actually happen...repl is the string to munch, pCE holds the data.
     *
     * (char **str) is used to store a copy of (char *id), if it passes
     * the format check.
     *
     * the idea is that this is first called when the config file is read,
     * putting the result in (char **str).  then we call it again, near
     * the end, permuting (char **repl) with values from (CONSENT *pCE) with
     * the saved string now coming in as (char *id).  got it?
     *
     * you could pass all arguments in...then both types of actions occur.
     */
    char *p;
    char *repfmt[256];
    unsigned short repnum;
    int i;

    enum repstate {
	REP_BEGIN,
	REP_LTR,
	REP_EQ,
	REP_INT,
	REP_END
    } state;

    if (s == (SUBST *)0) {
	Error("ProcessSubst(): WTF? No substitute support structure?!?!");
	Bye(EX_SOFTWARE);
    }

    if (str != (char **)0) {
	if (*str != (char *)0) {
	    free(*str);
	    *str = (char *)0;
	}
    }

    if ((id == (char *)0) || (*id == '\000'))
	return;

    repnum = 0;
    state = REP_BEGIN;

    for (i = 0; i < 256; i++)
	repfmt[i] = (char *)0;

    for (p = id; *p != '\000'; p++) {
	switch (state) {
	    case REP_BEGIN:
		/* must be printable */
		if (*p == ',' || !isgraph((int)(*p)))
		    goto subst_err;

		/* make sure we haven't seen this replacement char yet */
		repnum = (unsigned short)(*p);
		if (repfmt[repnum] != (char *)0) {
		    if (isMaster)
			Error
			    ("substitution characters of `%s' option are the same [%s:%d]",
			     name, file, line);
		    return;
		}
		state = REP_LTR;
		break;
	    case REP_LTR:
		if (*p != '=')
		    goto subst_err;
		state = REP_EQ;
		break;
	    case REP_EQ:
		repfmt[repnum] = p;
		if (s->token(*(repfmt[repnum])) != ISNOTHING)
		    state = REP_INT;
		else
		    goto subst_err;
		break;
	    case REP_INT:
		if (*p == 'd' || *p == 'x' || *p == 'X' || *p == 'a' ||
		    *p == 'A') {
		    if (s->token(*(repfmt[repnum])) != ISNUMBER)
			goto subst_err;
		    state = REP_END;
		} else if (*p == 's') {
		    if (s->token(*(repfmt[repnum])) != ISSTRING)
			goto subst_err;
		    state = REP_END;
		} else if (!isdigit((int)(*p)))
		    goto subst_err;
		break;
	    case REP_END:
		if (*p != ',')
		    goto subst_err;
		state = REP_BEGIN;
		break;
	}
    }

    if (state != REP_END) {
      subst_err:
	if (isMaster)
	    Error
		("invalid `%s' specification `%s' (char #%d: `%c') [%s:%d]",
		 name, id, (p - id) + 1, *p, file, line);
	return;
    }

    if (str != (char **)0) {
	if ((*str = StrDup(id)) == (char *)0)
	    OutOfMem();
    }

    if (s != (SUBST *)0 && repl != (char **)0 && *repl != (char *)0) {
	static STRING *result = (STRING *)0;

	if (result == (STRING *)0)
	    result = AllocString();
	BuildString((char *)0, result);

	for (p = *repl; *p != '\000'; p++) {
	    if (repfmt[(unsigned short)(*p)] != (char *)0) {
		char *r = repfmt[(unsigned short)(*p)];
		int plen = 0;
		char *c = (char *)0;
		int o = 0;

		if (s->token(*r) == ISSTRING) {
		    /* check the pattern for a length */
		    if (isdigit((int)(*(r + 1))))
			plen = atoi(r + 1);

		    /* this should never return zero, but just in case */
		    if ((*s->value) (*r, &c, (int *)0) == 0)
			c = "";
		    plen -= strlen(c);

		    /* pad it out, if necessary */
		    for (i = 0; i < plen; i++)
			BuildStringChar(' ', result);

		    /* throw in the string */
		    BuildString(c, result);
		} else {
		    int i = 0;
		    unsigned short port = 0;
		    unsigned short base = 0;
		    int padzero = 0;
		    static STRING *num = (STRING *)0;

		    if (num == (STRING *)0)
			num = AllocString();
		    BuildString((char *)0, num);

		    /* this should never return zero, but just in case */
		    if ((*s->value) (*r, (char **)0, &i) == 0)
			port = 0;
		    else
			port = (unsigned short)i;

		    /* check the pattern for a length and padding */
		    for (c = r + 1; *c != '\000'; c++)
			if (!isdigit((int)(*c)))
			    break;
		    if (c != r + 1) {
			plen = atoi(r + 1);
			padzero = (r[1] == '0');
		    }

		    /* check for base */
		    switch (*c) {
			case 'd':
			    base = 10;
			    break;
			case 'x':
			case 'X':
			    base = 16;
			    break;
			case 'a':
			case 'A':
			    base = 36;
			    break;
			default:
			    return;
		    }
		    while (port >= base) {
			if (port % base >= 10)
			    BuildStringChar((port % base) - 10 +
					    ((*c == 'x' ||
					      *c == 'a') ? 'a' : 'A'),
					    num);
			else
			    BuildStringChar((port % base) + '0', num);
			port /= base;
		    }
		    if (port >= 10)
			BuildStringChar(port - 10 +
					((*c == 'x' ||
					  *c == 'a') ? 'a' : 'A'), num);
		    else
			BuildStringChar(port + '0', num);

		    /* if we're supposed to be a certain length, pad it */
		    while (num->used - 1 < plen) {
			if (padzero == 0)
			    BuildStringChar(' ', num);
			else
			    BuildStringChar('0', num);
		    }

		    /* reverse the text to put it in forward order */
		    o = num->used - 1;
		    for (i = 0; i < o / 2; i++) {
			char temp;

			temp = num->string[i];
			num->string[i]
			    = num->string[o - i - 1];
			num->string[o - i - 1] = temp;
		    }
		    BuildStringN(num->string, o, result);
		}
	    } else
		BuildStringChar(*p, result);
	}
	free(*repl);
	if ((*repl = StrDup(result->string)) == (char *)0)
	    OutOfMem();
    }

    return;
}

char *
MyVersion(void)
{
    static STRING *version = (STRING *)0;
    if (version != (STRING *)0)
	return version->string;
    version = AllocString();
    BuildStringPrint(version, "%s %d.%d.%d", VERSION_TEXT, VERSION_MAJOR,
		     VERSION_MINOR, VERSION_REV);
    return version->string;
}

unsigned int
AtoU(char *str)
{
    unsigned int v;
    int i;
    v = 0;
    for (i = 0; isdigit((int)str[i]); i++) {
	v *= 10;
	v += str[i] - '0';
    }
    return v;
}

void
StrCpy(char *dst, const char *src, unsigned int size)
{
#ifdef HAVE_STRLCPY
    strlcpy(dst, src, size);
#else
    strcpy(dst, src);
#endif
}

void
Sleep(useconds_t usec)
{
#ifdef HAVE_NANOSLEEP
    struct timespec ts = { 0, usec * 1000 };
    nanosleep(&ts, NULL);
#else
    usleep(usec);
#endif
}
