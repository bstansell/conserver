/*
 *  $Id: getpassword.c,v 1.6 2003-09-12 10:36:19-07 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
 */

#include <compat.h>

#include <pwd.h>

#include <util.h>
#include <version.h>


/* the next two routines assure that the users tty is in the
 * correct mode for us to do our thing
 */
static int screwy = 0;
static struct termios o_tios;
/* this holds the password given to us by the user */
static STRING *pass = (STRING *)0;


/*
 * show characters that are already tty processed,
 * and read characters before cononical processing
 * we really use cbreak at PUCC because we need even parity...
 */
static void
#if PROTOTYPES
C2Raw(int fd)
#else
C2Raw(fd)
    int fd;
#endif
{
    struct termios n_tios;

    if (!isatty(fd) || 0 != screwy)
	return;

    if (0 != tcgetattr(fd, &o_tios)) {
	Error("tcgetattr(%d): %s", fd, strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    n_tios = o_tios;
    n_tios.c_iflag &= ~(IUCLC | IXON);
    n_tios.c_oflag &= ~OPOST;
    n_tios.c_lflag &= ~(ISIG | ECHO | IEXTEN);
    n_tios.c_cc[VMIN] = 1;
    n_tios.c_cc[VTIME] = 0;
    if (0 != tcsetattr(fd, TCSANOW, &n_tios)) {
	Error("tcsetattr(%d, TCSANOW): %s", fd, strerror(errno));
	exit(EX_UNAVAILABLE);
    }
    screwy = 1;
}

/*
 * put the tty back as it was, however that was
 */
static void
#if PROTOTYPES
C2Normal(int fd)
#else
C2Normal(fd)
    int fd;
#endif
{
    if (!screwy)
	return;
    tcsetattr(fd, TCSANOW, &o_tios);
    screwy = 0;
}

char *
#if PROTOTYPES
GetPassword(char *prompt)
#else
GetPassword(prompt)
    char *prompt;
#endif
{
    int fd;
    int nc;
    char buf[BUFSIZ];
    int done = 0;

    if (prompt == (char *)0)
	prompt = "";
    if ((pass = AllocString()) == (STRING *)0)
	OutOfMem();
    BuildString((char *)0, pass);

    if ((fd = open("/dev/tty", O_RDWR)) == -1) {
	Error("could not open `/dev/tty': %s", strerror(errno));
	return (char *)0;
    }

    C2Raw(fd);
    write(fd, prompt, strlen(prompt));
    while (!done) {
	int i;
	if ((nc = read(0, buf, sizeof(buf))) == 0)
	    break;
	for (i = 0; i < nc; ++i) {
	    if (buf[i] == 0x0d || buf[i] == 0x0a) {
		/* CR, NL */
		done = 1;
		break;
	    } else
		BuildStringChar(buf[i], pass);
	}
    }
    C2Normal(fd);
    /*
       {
       static STRING *c = (STRING *) 0;
       if ((c = AllocString()) == (STRING *) 0)
       OutOfMem();
       write(fd, "\n'", 2);
       if (pass->used) {
       FmtCtlStr(pass->string, pass->used - 1, c);
       write(fd, c->string, c->used - 1);
       }
       write(fd, "'\n", 2);
       }
     */
    write(fd, "\n", 1);
    close(fd);
    /* this way a (char*)0 is only returned on error */
    if (pass->string == (char *)0)
	return "";
    else
	return pass->string;
}

void
#if PROTOTYPES
ClearPassword(void)
#else
ClearPassword()
#endif
{
    if (pass == (STRING *)0 || pass->allocated == 0)
	return;

#if HAVE_MEMSET
    memset((void *)(pass->string), '\000', pass->allocated);
#else
    bzero((char *)(pass->string), pass->allocated);
#endif

    BuildString((char *)0, pass);
}
