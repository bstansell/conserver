/*
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
 */

/*
 * This is a fake library interface to ptyd			    (mtr&ksb)
 *
 * Mike Rowan (mtr@mace.cc.purdue.edu)
 */

#include <compat.h>

#include <cutil.h>

/*
 * get a pty for the user
 *
 * this has been revamped rather heavily for 8.0.0.  i've taken ideas
 * from the xemacs and openssh distributions to get code that *should*
 * work on systems i have no access to.  thanks to those reference
 * packages, i think things are ok...hopefully it's true!
 */
static int
GetPseudoTTY(STRING *slave, int *slaveFD)
{
#if HAVE_OPENPTY
    int fd = -1;
    int sfd = -1;
    int opty = 0;
    char *pcName;
# if HAVE_SIGACTION
    sigset_t oldmask, newmask;
# else
    extern void FlagReapVirt(int);
# endif

# if HAVE_SIGACTION
    sigemptyset(&newmask);
    sigaddset(&newmask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) < 0)
	Error("GetPseudoTTY(): sigprocmask(SIG_BLOCK): %s",
	      strerror(errno));
# else
    SimpleSignal(SIGCHLD, SIG_DFL);
# endif

    opty = openpty(&fd, &sfd, NULL, NULL, NULL);

# if HAVE_SIGACTION
    if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
	Error("GetPseudoTTY(): sigprocmask(SIG_SETMASK): %s",
	      strerror(errno));
# else
    SimpleSignal(SIGCHLD, FlagReapVirt);
# endif

    if (opty != 0) {
	if (fd >= 0)
	    close(fd);
	if (sfd >= 0)
	    close(sfd);
	return -1;
    }
    if ((char *)0 == (pcName = ttyname(sfd))) {
	close(fd);
	close(sfd);
	return -1;
    }
    BuildString((char *)0, slave);
    BuildString(pcName, slave);

    *slaveFD = sfd;
    return fd;
#else
# if (HAVE_PTSNAME && HAVE_GRANTPT && HAVE_UNLOCKPT) || defined(_AIX)
    int fd = -1;
    int sfd = -1;
    char *pcName;
#  if HAVE_SIGACTION
    sigset_t oldmask, newmask;
#  else
    extern void FlagReapVirt(int);
#  endif
    int c;
    /* clone list and idea stolen from xemacs distribution */
    static char *clones[] = {
	"/dev/ptmx",		/* Various systems */
	"/dev/ptm/clone",	/* HPUX */
	"/dev/ptc",		/* AIX */
	"/dev/ptmx_bsd",	/* Tru64 */
	(char *)0
    };

    /* try to find the pty allocator */
    for (c = 0; clones[c] != (char *)0; c++) {
	if ((fd = open(clones[c], O_RDWR, 0)) >= 0)
	    break;
    }
    if (fd < 0)
	return -1;

#  if HAVE_SIGACTION
    sigemptyset(&newmask);
    sigaddset(&newmask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) < 0)
	Error("GetPseudoTTY(): sigprocmask(SIG_BLOCK): %s",
	      strerror(errno));
#  else
    SimpleSignal(SIGCHLD, SIG_DFL);
#  endif

#  if HAVE_GRANTPT
    grantpt(fd);		/* change permission of slave */
#  endif

#  if HAVE_SIGACTION
    if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
	Error("GetPseudoTTY(): sigprocmask(SIG_SETMASK): %s",
	      strerror(errno));
#  else
    SimpleSignal(SIGCHLD, FlagReapVirt);
#  endif

#  if HAVE_UNLOCKPT
    unlockpt(fd);		/* unlock slave */
#  endif

#  if defined(_AIX)
    if ((pcName = ttyname(fd)) == (char *)0) {
	close(fd);
	return -1;
    }
#  else
#   if HAVE_PTSNAME
    if ((pcName = ptsname(fd)) == (char *)0) {
	close(fd);
	return -1;
    }
#   else
    close(fd);
    return -1;
#   endif
#  endif

    /* go ahead and open the slave */
    if ((sfd = open(pcName, O_RDWR, 0)) < 0) {
	Error("GetPseudoTTY(): open(%s): %s", pcName, strerror(errno));
	close(fd);
	return -1;
    }

    BuildString((char *)0, slave);
    BuildString(pcName, slave);

    *slaveFD = sfd;
    return fd;
# else
    /*
     * Below is the string for finding /dev/ptyXX.  For each architecture we
     * leave some pty's world writable because we don't have source for
     * everything that uses pty's.  For the most part, we'll be trying to
     * make /dev/ptyq* the "free" pty's.
     */
    /* all the world's a vax ;-) */
    static char charone[] = "prstuvwxyzPQRSTUVWq";
    static char chartwo[] =
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static char acMaster[] = "/dev/ptyXX";
    static char acSlave[] = "/dev/ttyXX";
    static char *pcOne = charone, *pcTwo = chartwo;
    int fd, sfd, iLoop, iIndex = sizeof("/dev/pty") - 1;
    char *pcOld1;
    struct stat statBuf;

    iLoop = 0;
    pcOld1 = pcOne;
    for (;;) {
	if ('\000' == *++pcTwo) {
	    pcTwo = chartwo;
	    if ('\000' == *++pcOne) {
		pcOne = charone;
		if ((pcOld1 == pcOne && ++iLoop > 1) || (iLoop > 32))
		    return -1;
	    }
	}
	acMaster[iIndex] = *pcOne;
	acMaster[iIndex + 1] = *pcTwo;

	/*
	 * Remeber we are root - stat the file
	 * to see if it exists before we open it
	 * for read/write - if it doesn't we don't
	 * have any pty's left in the row
	 */
	if (-1 == stat(acMaster, &statBuf) ||
	    S_IFCHR != (statBuf.st_mode & S_IFMT)) {
	    pcTwo = "l";
	    continue;
	}

	if (0 > (fd = open(acMaster, O_RDWR | O_NONBLOCK, 0))) {
	    continue;
	}
	acSlave[iIndex] = *pcOne;
	acSlave[iIndex + 1] = *pcTwo;
	if (-1 == access(acSlave, F_OK)) {
	    close(fd);
	    continue;
	}
	break;
    }

    /* go ahead and open the slave */
    if ((sfd = open(acSlave, O_RDWR, 0)) < 0) {
	Error("GetPseudoTTY(): open(%s): %s", acSlave, strerror(errno));
	close(fd);
	return -1;
    }

    BuildString((char *)0, slave);
    BuildString(acSlave, slave);

    *slaveFD = sfd;
    return fd;
# endif/* (HAVE_PTSNAME && HAVE_GRANTPT && HAVE_UNLOCKPT) || defined(_AIX) */
#endif /* HAVE_OPENPTY */
}

/*
 * get a pty using the GetPseudoTTY code above
 */
int
FallBack(char **slave, int *sfd)
{
    int fd;
    static STRING *pcTSlave = (STRING *)0;

    if (pcTSlave == (STRING *)0)
	pcTSlave = AllocString();

    if ((fd = GetPseudoTTY(pcTSlave, sfd)) == -1) {
	return -1;
    }
    if ((*slave) != (char *)0)
	free(*slave);
    if (((*slave) = StrDup(pcTSlave->string))
	== (char *)0)
	OutOfMem();
    return fd;
}
