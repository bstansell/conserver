/*
 *  $Id: util.c,v 1.26 2001-08-04 18:33:27-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000-2001
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */
#include <stdio.h>
#include <varargs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <config.h>
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
OutOfMem()
{
    static char acNoMem[] = ": out of memory\n";

    write(2, progname, strlen(progname));
    write(2, acNoMem, sizeof(acNoMem) - 1);
    exit(EX_UNAVAILABLE);
}

char *
buildMyString(str, msg)
    const char *str;
    STRING *msg;
{
    int len;

    if ((char *)0 == str) {
	msg->used = 0;
	if (msg->string != (char *)0)
	    msg->string[0] = '\000';
	Debug("buildMyString: reset", len);
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
	Debug("buildMyString: tried allocating %lu bytes", msg->allocated);
	if (msg->string == (char *)0)
	    OutOfMem();
    }
    strcat(msg->string, str);
    msg->used += len;
    Debug("buildMyString: added %d chars (%d/%d now)", len, msg->used,
	  msg->allocated);
    return msg->string;
}

char *
buildString(str)
    const char *str;
{
    static STRING msg = { (char *)0, 0, 0 };

    return buildMyString(str, &msg);
}

char *
readLine(fp, save, iLine)
    FILE *fp;
    STRING *save;
    int *iLine;
{
    static char buf[1024];
    char *wholeline = (char *)0;
    char *ret;
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

    Debug("readLine: returning <%s>",
	  (wholeline != (char *)0) ? wholeline : "<NULL>");
    return wholeline;
}

void
FmtCtlStr(pcIn, pcOut)
    char *pcIn;
    char *pcOut;
{
    unsigned char c;

    for (; *pcIn != '\000'; pcIn++) {
	c = *pcIn & 0xff;
	if (c > 127) {
	    c -= 128;
	    *pcOut++ = 'M';
	    *pcOut++ = '-';
	}

	if (c < ' ' || c == '\177') {
	    *pcOut++ = '^';
	    *pcOut++ = c ^ 0100;
	} else {
	    *pcOut++ = c;
	}
    }
    *pcOut = '\000';
}

void
Debug(fmt, va_alist)
    char *fmt;
    va_dcl
{
    va_list ap;
    va_start(ap);
    if (!fDebug)
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
Error(fmt, va_alist)
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
    fprintf(stderr, "\n");
    va_end(ap);
}

void
Info(fmt, va_alist)
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
    fprintf(stdout, "\n");
    va_end(ap);
}

void
simpleSignal(sig, disp)
    int sig;
RETSIGTYPE(*disp) (int);
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
maxfiles()
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
    Debug("maxfiles=%d", mf);
    return mf;
}

/* Routines for the generic I/O stuff for conserver.  This will handle
 * all open(), close(), read(), and write() calls.
 */

/* This encapsulates a regular file descriptor in a CONSFILE
 * object.  Returns a CONSFILE pointer to that object.
 */
CONSFILE *
fileOpenFD(fd, type)
    int fd;
    enum consFileType type;
{
    CONSFILE *cfp;

    cfp = (CONSFILE *) calloc(1, sizeof(CONSFILE));
    if ((CONSFILE *) 0 == cfp)
	OutOfMem();
    cfp->ftype = type;
    cfp->fd = fd;

    Debug("File I/O: Encapsulated fd %d type %d", fd, type);
    return cfp;
}

/* This is to "unencapsulate" the file descriptor */
int
fileUnopen(cfp)
    CONSFILE *cfp;
{
    int retval;

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
    Debug("File I/O: Unopened fd %d", cfp->fd);
    free(cfp);

    return retval;
}

/* This opens a file like open(2).  Returns a CONSFILE pointer
 * or a (CONSFILE *)0 on error
 */
CONSFILE *
fileOpen(path, flag, mode)
    const char *path;
    int flag;
    int mode;
{
    CONSFILE *cfp;
    int fd;

    if (-1 == (fd = open(path, flag, mode))) {
	Debug("File I/O: Failed to open `%s'", path);
	return (CONSFILE *) 0;
    }
    cfp = (CONSFILE *) calloc(1, sizeof(CONSFILE));
    if ((CONSFILE *) 0 == cfp)
	OutOfMem();
    cfp->ftype = simpleFile;
    cfp->fd = fd;

    Debug("File I/O: Opened `%s' as fd %d", path, fd);
    return cfp;
}

/* Unless otherwise stated, returns the same values as close(2).
 * The CONSFILE object passed in *CANNOT* be used once calling
 * this function - even if there was an error.
 */
int
fileClose(cfp)
    CONSFILE *cfp;
{
    int retval;
#if defined(__CYGWIN__)
    int client_sock_flags;
    struct linger lingeropt;
#endif

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
    Debug("File I/O: Closed fd %d", cfp->fd);
    free(cfp);

    return retval;
}

/* Unless otherwise stated, returns the same values as read(2) */
int
fileRead(cfp, buf, len)
    CONSFILE *cfp;
    void *buf;
    int len;
{
    int retval;

    switch (cfp->ftype) {
	case simpleFile:
	    retval = read(cfp->fd, buf, len);
	    break;
	case simpleSocket:
	    retval = read(cfp->fd, buf, len);
	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    retval = SSL_read(cfp->sslfd, buf, len);
	    break;
#endif
    }

    Debug("File I/O: Read %d bytes from fd %d", retval, cfp->fd);
    return retval;
}

/* Unless otherwise stated, returns the same values as write(2) */
int
fileWrite(cfp, buf, len)
    CONSFILE *cfp;
    const char *buf;
    int len;
{
    int retval;

    if (len < 0)
	len = strlen(buf);

    switch (cfp->ftype) {
	case simpleFile:
	    retval = write(cfp->fd, buf, len);
	    break;
	case simpleSocket:
	    retval = write(cfp->fd, buf, len);
	    break;
#ifdef TLS_SUPPORT
	case TLSSocket:
	    retval = SSL_write(cfp->sslfd, buf, len);
	    break;
#endif
    }

    Debug("File I/O: Wrote %d bytes to fd %d", retval, cfp->fd);
    return retval;
}

/* Unless otherwise stated, returns the same values as fstat(2) */
int
fileStat(cfp, buf)
    CONSFILE *cfp;
    struct stat *buf;
{
    int retval;

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
fileSeek(cfp, offset, whence)
    CONSFILE *cfp;
    off_t offset;
    int whence;
{
    int retval;

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
fileFDNum(cfp)
    CONSFILE *cfp;
{
    int retval;

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
fileSend(cfp, msg, len, flags)
    CONSFILE *cfp;
    const void *msg;
    size_t len;
    int flags;
{
    int retval;

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
