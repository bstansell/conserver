/*
 *  $Id: fallback.c,v 5.24 2001-02-08 15:31:58-08 bryan Exp $
 *
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

#include <config.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <syslog.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>

#include <compat.h>

#include <port.h>

#if DO_VIRTUAL && ! HAVE_PTYD

static char *__pty_host;
static char *__pty_fmt;

static int iLogPri = LOG_DEBUG;


/*
 * Below is the string for finding /dev/ptyXX.  For each architecture we
 * leave some pty's world writable because we don't have source for
 * everything that uses pty's.  For the most part, we'll be trying to
 * make /dev/ptyq* the "free" pty's.
 */
# if defined(sun)
static char charone[] =
	"prstuvwxyzPQRSTUVWq";
# else
#  if defined(dynix)
static char charone[] =
	"prstuvwxyzPQRSTUVWq";
#  else
#   if defined(ultrix)
static char charone[] =
	"prstuvwxyzPQRSTUVWq";
#   else
/* all the world's a vax ;-) */
static char charone[] =
	"prstuvwxyzPQRSTUVWq";
#   endif
#  endif
# endif

static char chartwo[] =
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

# if (defined(_AIX) || defined(PTX4))
static char acMaster[] =
	"/dev/ptc/XXXXXXXXX";
static char acSlave[] =
	"/dev/pts/XXXXXXXXX";
# else
static char acMaster[] =
	"/dev/ptyXX";
static char acSlave[] =
	"/dev/ttyXX";
# endif /* _AIX */

# if !HAVE_GETPSEUDO
#  ifdef _AIX
/*
 * get a pty for the user (emulate the neato sequent call)		(mm)
 */
static int
getpseudotty(slave, master)
char **master, **slave;
{
	int fd;
	char *pcName, *pcTmp;

	if (0 > (fd = open("/dev/ptc", O_RDWR|O_NDELAY, 0))) {
		return -1;
	}
	if ((char *)0 == (pcName = ttyname(fd))) {
		return -1;
	}
	(void)strcpy(acSlave, pcName);
	*slave = acSlave;

	(void)strcpy(acMaster, pcName);
	acMaster[7] = 'c';
	*master = acMaster;

	return fd;
}

#  else
#   if  HAVE_PTSNAME

/* get a pty for the user -- emulate the neato sequent call under	(gregf)
 * DYNIX/ptx v4.0
 */
static int
getpseudotty(slave, master)
char **master, **slave;
{
	int fd;
	char *pcName, *pcTmp;

	if (0 > (fd = open("/dev/ptmx", O_RDWR, 0))) {
		return -1;
	}
	grantpt(fd);			/* change permission of slave */
	unlockpt(fd);			/* unlock slave */
	if ((char *)0 == (pcName = ttyname(fd))) {
		return -1;
	}
	(void)strcpy(acMaster, pcName);
	*master = acMaster;

	if ((char *) 0 == (pcName = ptsname(fd))) {
		return -1;
	}

	(void)strcpy(acSlave, pcName);
	*slave = acSlave;

	return fd;
}

#   else
/*
 * get a pty for the user (emulate the neato sequent call)		(ksb)
 */
static int
getpseudotty(slave, master)
char **master, **slave;
{
	static char *pcOne = charone, *pcTwo = chartwo;
	auto int fd, iLoop, iIndex = sizeof("/dev/pty")-1;
	auto char *pcOld1;
	auto struct stat statBuf;

	iLoop = 0;
	pcOld1 = pcOne;
	for (;;) {
		if ('\000' == *++pcTwo) {
			pcTwo = chartwo;
			if ('\000' == *++pcOne) {
				pcOne = charone;
				if (pcOld1 == pcOne && ++iLoop > 1 || iLoop > 32)
					return -1;
			}
		}
		acMaster[iIndex] = *pcOne;
		acMaster[iIndex+1] = *pcTwo;

		/*
		 * Remeber we are root - stat the file
		 * to see if it exists before we open it
		 * for read/write - if it doesn't we don't
		 * have any pty's left in the row
		 */
		if (-1 == stat(acMaster, &statBuf) || S_IFCHR != (statBuf.st_mode&S_IFMT)) {
			pcTwo = "l";
			continue;
		}

		if (0 > (fd = open(acMaster, O_RDWR|O_NDELAY, 0))) {
			continue;
		}
		acSlave[iIndex] = *pcOne;
		acSlave[iIndex+1] = *pcTwo;
		if (-1 == access(acSlave, F_OK)) {
			(void) close(fd);
			continue;
		}
		break;
	}
	*master = acMaster;
	*slave = acSlave;
	return fd;
}
#   endif /* PTX version */
#  endif /* _AIX */
# endif /* !HAVE_GETPSEUDO */

/*
 * get a Joe pty bacause the daemon is not with us, sadly.		(ksb)
 */
int
FallBack(pcSlave, pcMaster)
char *pcSlave, *pcMaster;
{
	auto int fd;
	auto char *pcTSlave, *pcTMaster;

	if (-1 == (fd = getpseudotty(& pcTSlave, & pcTMaster))) {
		return -1;
	}
	(void) strcpy(pcSlave, pcTSlave);
	(void) strcpy(pcMaster, pcTMaster);
	return fd;
}

#endif /* no code if it is not used */
