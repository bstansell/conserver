/*
 *  $Id: util.c,v 1.46 2002-03-11 18:26:51-08 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */
#include <config.h>

#include <stdio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <ctype.h>

#include <compat.h>
#include <port.h>
#include <util.h>

int outputPid = 0;
char *progname = "conserver package";
int thepid = 0;
int fDebug = 0;

/* in the routines below (the init code) we can bomb if malloc fails	(ksb)
 */
void
#if USE_ANSI_PROTO
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

char *
#if USE_ANSI_PROTO
buildMyStringChar(const char ch, STRING * msg)
#else
buildMyStringChar(ch, msg)
    const char ch;
    STRING *msg;
#endif
{
    if (msg->used + 1 >= msg->allocated) {
	if (0 == msg->allocated) {
	    msg->allocated = 1024 * sizeof(char);
	    msg->string = (char *)calloc(1, msg->allocated);
	} else {
	    msg->allocated += 1024 * sizeof(char);
	    msg->string = (char *)realloc(msg->string, msg->allocated);
	}
	Debug(2, "buildMyStringChar: tried allocating %lu bytes",
	      msg->allocated);
	if (msg->string == (char *)0)
	    OutOfMem();
    }
    if (msg->used) {
	msg->string[msg->used - 1] = ch;	/* overwrite NULL and */
	msg->string[msg->used++] = '\000';	/* increment by one */
	Debug(2, "buildMyStringChar: added 1 char (%d/%d now)", msg->used,
	      msg->allocated);
    } else {
	msg->string[msg->used++] = ch;	/* no NULL, so store stuff */
	msg->string[msg->used++] = '\000';	/* and increment by two */
	Debug(2, "buildMyStringChar: added 2 chars (%d/%d now)", msg->used,
	      msg->allocated);
    }
    return msg->string;
}

char *
#if USE_ANSI_PROTO
buildMyString(const char *str, STRING * msg)
#else
buildMyString(str, msg)
    const char *str;
    STRING *msg;
#endif
{
    int len;

    if ((char *)0 == str) {
	msg->used = 0;
	if (msg->string != (char *)0)
	    msg->string[0] = '\000';
	Debug(2, "buildMyString: reset");
	return msg->string;
    }
    len = strlen(str) + 1;
    if (msg->used + len >= msg->allocated) {
	if (0 == msg->allocated) {
	    msg->allocated = (len / 1024 + 1) * 1024 * sizeof(char);
	    msg->string = (char *)calloc(1, msg->allocated);
	} else {
	    msg->allocated += (len / 1024 + 1) * 1024 * sizeof(char);
	    msg->string = (char *)realloc(msg->string, msg->allocated);
	}
	Debug(2, "buildMyString: tried allocating %lu bytes",
	      msg->allocated);
	if (msg->string == (char *)0)
	    OutOfMem();
    }
#if HAVE_MEMCPY
    (void)memcpy(msg->string + (msg->used ? msg->used - 1 : 0), str, len);
#else
    (void)bcopy(str, msg->string + (msg->used ? msg->used - 1 : 0), len);
#endif
    if (msg->used)
	len--;
    msg->used += len;
    Debug(2, "buildMyString: added %d chars (%d/%d now)", len, msg->used,
	  msg->allocated);
    return msg->string;
}

void
#if USE_ANSI_PROTO
initString(STRING * msg)
#else
initString(msg)
    STRING *msg;
#endif
{
    msg->string = (char *)0;
    msg->used = msg->allocated = 0;
}

void
#if USE_ANSI_PROTO
destroyString(STRING * msg)
#else
destroyString(msg)
    STRING *msg;
#endif
{
    if (msg->allocated)
	free(msg->string);
    initString(msg);
}

static STRING mymsg = { (char *)0, 0, 0 };

char *
#if USE_ANSI_PROTO
buildString(const char *str)
#else
buildString(str)
    const char *str;
#endif
{
    return buildMyString(str, &mymsg);
}

char *
#if USE_ANSI_PROTO
buildStringChar(const char c)
#else
buildStringChar(c)
    const char c;
#endif
{
    return buildMyStringChar(c, &mymsg);
}

char *
#if USE_ANSI_PROTO
readLine(FILE * fp, STRING * save, int *iLine)
#else
readLine(fp, save, iLine)
    FILE *fp;
    STRING *save;
    int *iLine;
#endif
{
    static char buf[1024];
    char *wholeline = (char *)0;
    char *ret = (char *)0;
    int i, buflen, peek, commentCheck = 1, comment = 0;
    static STRING bufstr = { (char *)0, 0, 0 };
    static STRING wholestr = { (char *)0, 0, 0 };


    peek = 0;
    wholeline = (char *)0;
    buildMyString((char *)0, &bufstr);
    buildMyString((char *)0, &wholestr);
    while (save->used || ((ret = fgets(buf, sizeof(buf), fp)) != (char *)0)
	   || peek) {
	/* If we have a previously saved line, use it instead */
	if (save->used) {
	    (void)strcpy(buf, save->string);
	    buildMyString((char *)0, save);
	}

	if (peek) {
	    /* End of file?  Never mind. */
	    if (ret == (char *)0)
		break;

	    /* If we don't have a line continuation and we've seen
	     * some worthy data
	     */
	    if (!isspace((int)buf[0]) && (wholeline != (char *)0)) {
		buildMyString((char *)0, save);
		buildMyString(buf, save);
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
		buildMyString(buf, &bufstr);
		wholeline = buildMyString(bufstr.string, &wholestr);
	    }
	    peek = 1;
	    comment = 0;
	    commentCheck = 1;
	    buildMyString((char *)0, &bufstr);
	} else {
	    /* Save off the partial chunk */
	    buildMyString(buf, &bufstr);
	}
    }

    /* If we hit the EOF and weren't peeking ahead
     * and it's not a comment
     */
    if (!peek && (ret == (char *)0) && (comment == 0) &&
	(commentCheck == 0)) {
	(*iLine)++;
	wholeline = buildMyString(bufstr.string, &wholestr);
    }

    Debug(1, "readLine: returning <%s>",
	  (wholeline != (char *)0) ? wholeline : "<NULL>");
    return wholeline;
}

void
#if USE_ANSI_PROTO
FmtCtlStr(char *pcIn, STRING * pcOut)
#else
FmtCtlStr(pcIn, pcOut)
    char *pcIn;
    STRING *pcOut;
#endif
{
    unsigned char c;

    buildMyString((char *)0, pcOut);
    for (; *pcIn != '\000'; pcIn++) {
	c = *pcIn & 0xff;
	if (c > 127) {
	    c -= 128;
	    buildMyString("M-", pcOut);
	}

	if (c < ' ' || c == '\177') {
	    buildMyStringChar('^', pcOut);
	    buildMyStringChar(c ^ 0100, pcOut);
	} else {
	    buildMyStringChar(c, pcOut);
	}
    }
}

void
#if USE_ANSI_PROTO
Debug(int level, char *fmt, ...)
#else
Debug(level, fmt, va_alist)
    int level;
    char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if USE_ANSI_PROTO
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    if (fDebug < level)
	return;
    if (outputPid)
	fprintf(stderr, "%s (%d): DEBUG: ", progname, thepid);
    else
	fprintf(stderr, "%s: DEBUG: ", progname);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void
#if USE_ANSI_PROTO
Error(char *fmt, ...)
#else
Error(fmt, va_alist)
    char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if USE_ANSI_PROTO
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    if (outputPid)
	fprintf(stderr, "%s (%d): ", progname, thepid);
    else
	fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void
#if USE_ANSI_PROTO
Info(char *fmt, ...)
#else
Info(fmt, va_alist)
    char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if USE_ANSI_PROTO
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    if (outputPid)
	fprintf(stdout, "%s (%d): ", progname, thepid);
    else
	fprintf(stdout, "%s: ", progname);
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

void
#if USE_ANSI_PROTO
simpleSignal(int sig, RETSIGTYPE(*disp) (int))
#else
simpleSignal(sig, disp)
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
    (void)signal(sig, disp);
#endif
}

int
#if USE_ANSI_PROTO
cmaxfiles()
#else
cmaxfiles()
#endif
{
    int mf;
#ifdef HAVE_SYSCONF
    mf = sysconf(_SC_OPEN_MAX);
#else
# ifdef HAVE_GETRLIMIT
    struct rlimit rl;

    (void)getrlimit(RLIMIT_NOFILE, &rl);
    mf = rl.rlim_cur;
# else
#  ifdef HAVE_GETDTABLESIZE
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
    Debug(1, "maxfiles=%d", mf);
    return mf;
}

/* Routines for the generic I/O stuff for conserver.  This will handle
 * all open(), close(), read(), and write() calls.
 */

/* This encapsulates a regular file descriptor in a CONSFILE
 * object.  Returns a CONSFILE pointer to that object.
 */
CONSFILE *
#if USE_ANSI_PROTO
fileOpenFD(int fd, enum consFileType type)
#else
fileOpenFD(fd, type)
    int fd;
    enum consFileType type;
#endif
{
    CONSFILE *cfp;

    cfp = (CONSFILE *) calloc(1, sizeof(CONSFILE));
    if ((CONSFILE *) 0 == cfp)
	OutOfMem();
    cfp->ftype = type;
    cfp->fd = fd;

    Debug(1, "File I/O: Encapsulated fd %d type %d", fd, type);
    return cfp;
}

/* This is to "unencapsulate" the file descriptor */
int
#if USE_ANSI_PROTO
fileUnopen(CONSFILE * cfp)
#else
fileUnopen(cfp)
    CONSFILE *cfp;
#endif
{
    int retval = 0;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = cfp->fd;
	    break;
	case simpleSocket:
	    retval = cfp->fd;
	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    retval = cfp->sslfd;
	    break;
#endif
    }
    Debug(1, "File I/O: Unopened fd %d", cfp->fd);
    free(cfp);

    return retval;
}

/* This opens a file like open(2).  Returns a CONSFILE pointer
 * or a (CONSFILE *)0 on error
 */
CONSFILE *
#if USE_ANSI_PROTO
fileOpen(const char *path, int flag, int mode)
#else
fileOpen(path, flag, mode)
    const char *path;
    int flag;
    int mode;
#endif
{
    CONSFILE *cfp;
    int fd;

    if (-1 == (fd = open(path, flag, mode))) {
	Debug(1, "File I/O: Failed to open `%s'", path);
	return (CONSFILE *) 0;
    }
    cfp = (CONSFILE *) calloc(1, sizeof(CONSFILE));
    if ((CONSFILE *) 0 == cfp)
	OutOfMem();
    cfp->ftype = simpleFile;
    cfp->fd = fd;

    Debug(1, "File I/O: Opened `%s' as fd %d", path, fd);
    return cfp;
}

/* Unless otherwise stated, returns the same values as close(2).
 * The CONSFILE object passed in *CANNOT* be used once calling
 * this function - even if there was an error.
 */
int
#if USE_ANSI_PROTO
fileClose(CONSFILE ** pcfp)
#else
fileClose(cfp)
    CONSFILE **pcfp;
#endif
{
    CONSFILE *cfp;
    int retval = 0;
#if defined(__CYGWIN__)
    int client_sock_flags;
    struct linger lingeropt;
#endif

    cfp = *pcfp;
    if (cfp == (CONSFILE *) 0)
	return 0;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = close(cfp->fd);
	    break;
	case simpleSocket:
#if defined(__CYGWIN__)
	    /* flush out the client socket - set it to blocking,
	     * then write to it
	     */
	    client_sock_flags = fcntl(cfp->fd, F_GETFL, 0);
	    if (client_sock_flags != -1)
		/* enable blocking */
		fcntl(cfp->fd, F_SETFL, client_sock_flags & ~O_NONBLOCK);

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
	    retval = close(cfp->fd);


	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    retval = SSL_close(cfp->sslfd);
	    break;
#endif
    }
    Debug(1, "File I/O: Closed fd %d", cfp->fd);
    free(cfp);
    *pcfp = (CONSFILE *) 0;

    return retval;
}

/* Unless otherwise stated, returns the same values as read(2) */
int
#if USE_ANSI_PROTO
fileRead(CONSFILE * cfp, void *buf, int len)
#else
fileRead(cfp, buf, len)
    CONSFILE *cfp;
    void *buf;
    int len;
#endif
{
    int retval = 0;

    switch (cfp->ftype) {
	case simpleFile:
	case simpleSocket:
	    retval = read(cfp->fd, buf, len);
	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    retval = SSL_read(cfp->sslfd, buf, len);
	    break;
#endif
    }

    if (retval >= 0) {
	Debug(1, "File I/O: Read %d byte%s from fd %d", retval,
	      (retval == 1) ? "" : "s", cfp->fd);
    } else {
	Debug(1, "File I/O: Read of %d byte%s from fd %d: %s", len,
	      (retval == 1) ? "" : "s", cfp->fd, strerror(errno));
    }
    return retval;
}

/* Unless otherwise stated, returns the same values as write(2) */
int
#if USE_ANSI_PROTO
fileWrite(CONSFILE * cfp, const char *buf, int len)
#else
fileWrite(cfp, buf, len)
    CONSFILE *cfp;
    const char *buf;
    int len;
#endif
{
    int len_orig = len;
    int len_out = 0;
    int retval = 0;

    if (buf == (char *)0)
	return 0;

    if (len < 0)
	len = strlen(buf);

    if (len == 0)
	return 0;

    switch (cfp->ftype) {
	case simpleFile:
	case simpleSocket:
	    while (len > 0) {
		if ((retval = write(cfp->fd, buf, len)) < 0) {
		    break;
		}
		buf += retval;
		len -= retval;
		len_out += retval;
	    }
	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    len_out = retval = SSL_write(cfp->sslfd, buf, len);
	    break;
#endif
    }

    if (len_out >= 0) {
	Debug(1, "File I/O: Wrote %d byte%s to fd %d", len_out,
	      (len_out == 1) ? "" : "s", cfp->fd);
    } else {
	Debug(1, "File I/O: Write of %d byte%s to fd %d: %s", len_orig,
	      (len_out == 1) ? "" : "s", cfp->fd, strerror(errno));
    }
    return len_out;
}

void
#if USE_ANSI_PROTO
fileVwrite(CONSFILE * cfp, const char *fmt, va_list ap)
#else
fileVwrite(cfp, fmt, ap)
    CONSFILE *cfp;
    const char *fmt;
    va_list ap;
#endif
{
    int s, l, e;
    char c;
    static STRING msg = { (char *)0, 0, 0 };
    static short int flong, fneg;

    if (fmt == (char *)0)
	return;

    fneg = flong = 0;
    for (e = s = l = 0; (c = fmt[s + l]) != '\000'; l++) {
	if (c == '%') {
	    if (e) {
		e = 0;
		fileWrite(cfp, "%", 1);
	    } else {
		e = 1;
		fileWrite(cfp, fmt + s, l);
		s += l;
		l = 0;
	    }
	    continue;
	}
	if (e) {
	    unsigned long i;
	    int u;
	    char *p;
	    char cc;
	    switch (c) {
		case 'l':
		    flong = 1;
		    continue;
		case 'c':
		    cc = (char)va_arg(ap, int);
		    fileWrite(cfp, &cc, 1);
		    break;
		case 's':
		    p = va_arg(ap, char *);
		    fileWrite(cfp, p, -1);
		    break;
		case 'd':
		    i = (flong ? va_arg(ap, long) : (long)va_arg(ap, int));
		    if ((long)i < 0) {
			fneg = 1;
			i = -i;
		    }
		    goto number;
		case 'u':
		    i = (flong ? va_arg(ap, unsigned long)
			 : (unsigned long)va_arg(ap, unsigned int));
		  number:
		    buildMyString((char *)0, &msg);
		    while (i >= 10) {
			buildMyStringChar((i % 10) + '0', &msg);
			i /= 10;
		    }
		    buildMyStringChar(i + '0', &msg);
		    /* reverse the text to put it in forward order
		     */
		    u = msg.used - 1;
		    for (i = 0; i < u / 2; i++) {
			char temp;

			temp = msg.string[i];
			msg.string[i]
			    = msg.string[u - i - 1];
			msg.string[u - i - 1] = temp;
		    }
		    if (fneg) {
			fileWrite(cfp, "-", 1);
			fneg = 0;
		    }
		    fileWrite(cfp, msg.string, msg.used - 1);
		    break;
		default:
		    Error("unknown conversion character `%c' in `%s'", c,
			  fmt);
		    break;
	    }
	    s += l + 1;
	    l = -1;
	    e = flong = 0;
	}
    }
    if (l)
	fileWrite(cfp, fmt + s, l);
}

void
#if USE_ANSI_PROTO
filePrint(CONSFILE * cfp, const char *fmt, ...)
#else
filePrint(cfp, fmt, va_alist)
    CONSFILE *cfp;
    const char *fmt;
    va_dcl
#endif
{
    va_list ap;
#if USE_ANSI_PROTO
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    fileVwrite(cfp, fmt, ap);
    va_end(ap);
}

/* Unless otherwise stated, returns the same values as fstat(2) */
int
#if USE_ANSI_PROTO
fileStat(CONSFILE * cfp, struct stat *buf)
#else
fileStat(cfp, buf)
    CONSFILE *cfp;
    struct stat *buf;
#endif
{
    int retval = 0;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = fstat(cfp->fd, buf);
	    break;
	case simpleSocket:
	    retval = fstat(cfp->fd, buf);
	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    retval = -1;
	    break;
#endif
    }

    return retval;
}

/* Unless otherwise stated, returns the same values as lseek(2) */
int
#if USE_ANSI_PROTO
fileSeek(CONSFILE * cfp, off_t offset, int whence)
#else
fileSeek(cfp, offset, whence)
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
	case simpleSocket:
	    retval = lseek(cfp->fd, offset, whence);
	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    retval = -1;
	    break;
#endif
    }

    return retval;
}

/* Unless otherwise stated, returns the same values as lseek(2) */
int
#if USE_ANSI_PROTO
fileFDNum(CONSFILE * cfp)
#else
fileFDNum(cfp)
    CONSFILE *cfp;
#endif
{
    int retval = 0;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = cfp->fd;
	    break;
	case simpleSocket:
	    retval = cfp->fd;
	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    retval = -1;
	    break;
#endif
    }

    return retval;
}

/* Unless otherwise stated, returns the same values as send(2) */
int
#if USE_ANSI_PROTO
fileSend(CONSFILE * cfp, const void *msg, size_t len, int flags)
#else
fileSend(cfp, msg, len, flags)
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
	case simpleSocket:
	    retval = send(cfp->fd, msg, len, flags);
	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    retval = -1;
	    break;
#endif
    }

    return retval;
}