/*
 *	Perform an auto-login on a specified tty port.
 *
 *	autologin [-u] [-c<command>] [-e<env=val>] [-g<group>] -l<login> -t<tty>
 *
 *	Jeff W. Stewart - Purdue University Computing Center
 *
 * some of the ideas in this code are based on the Ohio State
 * console server as re-coded by Kevin Braunsdorf (PUCC)
 *
 * This program was written to be run out of inittab.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <utmp.h>
#include <string.h>


#include <errno.h>
#if !defined IBMR2
extern char *sys_errlist[];
#define strerror(Me) (sys_errlist[Me])
#endif

#define NEED_PUTENV	(!(defined(IBMR2) || defined(EPIX) || defined(SUNOS) || defined(SUN5)))

#if S81
#include <sys/vlimit.h>
#else
#include <limits.h>
#endif

#if SUN5
#define USE_UTENT	1
#include <sys/time.h>
#include <sys/resource.h>

static int
getdtablesize()
{
	auto struct rlimit rl;

	(void)getrlimit(RLIMIT_NOFILE, &rl);
	return rl.rlim_cur;
}
#endif

/* yucky kludges
 */
#ifdef EPIX
#include "/bsd43/usr/include/ttyent.h"
#include <posix/sys/termios.h>
#define NGROUPS_MAX 8
#define getsid(Mp)	(Mp)
#define getdtablesize() 64
struct timeval {
        long    tv_sec;         /* seconds */
        long    tv_usec;        /* and microseconds */
};
typedef int mode_t;
extern struct passwd *getpwnam();
extern struct group *getgrnam();
#define USE_TC		1
#define USE_UTENT	1
#else 

#if defined IBMR2
#include <termios.h>
#define setsid()	getpid()
#define getsid(Mp)	(Mp)
#define HAVE_GETUSERATTR 1
#define USE_TC		1
#define USE_UTENT	1
#else

#if defined V386
typedef int mode_t;
#define getdtablesize()	OPEN_MAX
#define setsid()	getpid()
#define getsid(Mp)	(Mp)
#define setgroups(x, y)	0
#include <sys/ttold.h>
#include <sys/ioctl.h>
#define USE_IOCTL	1
#define USE_TC		1
#else

#if defined S81
#include <sys/time.h>
#include <sys/ioctl.h>
typedef int mode_t;
#define setsid()	getpid()
#define getsid(Mp)	(Mp)
#define USE_IOCTL	1
#define USE_TC		0
#define USE_OLD_UTENT	1
#else

#if defined(NETBSD)
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/ioctl_compat.h>
#define setsid()	getpid()
#define getsid(Mp)	(Mp)
#define USE_IOCTL	1
#define USE_OLD_UTENT	1
#define PATH_SU		"/usr/ucb/su"
#define UTMP_PATH	"/var/run/utmp"
#else

#if defined(FREEBSD)
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/ioctl_compat.h>
#define setsid()	getpid()
#define getsid(Mp)	(Mp)
#define USE_IOCTL	1
#define USE_OLD_UTENT	1
#define PATH_SU		"/usr/ucb/su"
#else

#include <sys/termios.h>
#endif	/* NETBSD */
#endif	/* 386bsd or equiv */
#endif	/* sequent */
#endif	/* intel v386 */
#endif	/* find termios */
#endif	/* find any term stuff */


#ifdef SUNOS
#include <sys/time.h>
#include <ttyent.h>
#define setsid()	getpid()
#define getsid(Mp)	(Mp)
#endif

#if ! defined V386
#include <sys/vnode.h>
#endif

#ifdef	IBMR2
#include <sys/ioctl.h>
#include <usersec.h>
#endif	/* IBMR2 */

#include "main.h"


#define	TTYMODE	0600

#ifndef O_RDWR
#define O_RDWR	2
#endif

#ifndef NGROUPS_MAX
#define NGROUPS_MAX	8
#endif

#if !defined(UTMP_FILE)
#if defined(_PATH_UTMP)
#define UTMP_FILE	_PATH_UTMP
#else
#define UTMP_FILE	"/etc/utmp"
#endif
#endif

#if !defined(PATH_SU)
#define PATH_SU		"/bin/su"
#endif

/*
 * Global variables
 */

#ifndef	lint
char	*rcsid = "$Id: autologin.c,v 1.22 93/09/04 21:48:41 ksb Exp $";
#endif	/* not lint */
char	*progname;
gid_t	 awGrps[NGROUPS_MAX];
int	 iGrps = 0;

/*
 * External variables
 */

extern int optind;
extern char *optarg;

void	make_utmp();
void	usage();

int
Process()
{
	register int		 c;
	int			 iErrs = 0;
	int			 i, iNewGrp;
	gid_t			 wGid;
	uid_t			 wUid;
	char			*pcCmd = (char *)0,
				*pcDevTty = (char *)0;
	char			*pcTmp;
#ifdef	IBMR2
	char			*pcGrps;
#endif	/* IBMR2 */
	struct	passwd		*pwd;
	struct	stat		 st;
#if USE_IOCTL
	auto struct sgttyb n_sty;
#if USE_TC
	auto struct tc n_tchars;
#else
	auto struct tchars n_tchars;
#endif
#if HAVE_JOBS
	auto struct ltchars n_ltchars;
#endif
#else
	struct	termios		 n_tio;
#endif


	if ((char *)0 != pcCommand) {
		if ((char *)0 == (pcCmd = (char *)malloc(strlen(pcCommand) + 4))) {
			(void) fprintf(stderr, "%s: malloc: %s\n", progname, strerror(errno));
			exit(1);
			/* NOTREACHED */
		}
		(void)strcpy(pcCmd, "-c ");
		(void)strcat(pcCmd, pcCommand);
	}

	if ( (char *)0 != pcGroup ) {
		iErrs += addgroup(pcGroup);
	}

	if ( (char *)0 == pcLogin ) {
		static char acLogin[17];
		if ((struct passwd *)0 == (pwd = getpwuid(geteuid()))) {
			(void) fprintf(stderr, "%s: %d: uid unknown\n", progname, geteuid());
			exit(1);
			/* NOTREACHED */
		}
		pcLogin = strcpy(acLogin, pwd->pw_name);
	} else if ((struct passwd *)0 == (pwd = getpwnam(pcLogin))) {
		(void) fprintf(stderr, "%s: %s: login name unknown\n", progname, pcLogin);
		exit(1);
		/* NOTREACHED */
	}
	wUid = pwd->pw_uid;
	wGid = pwd->pw_gid;
#ifdef	HAVE_GETUSERATTR
	/* getuserattr() returns a funny list of groups:
	 *	"grp1\0grp2\0grp3\0\0"
	 */
	if (0 == getuserattr(pcLogin, S_SUGROUPS, &pcGrps, SEC_LIST)) {
		while ('\000' != *pcGrps) {
			/* ignore "ALL" and any group beginning with '!' */
			if ('!' == *pcGrps || 0 != strcmp(pcGrps, "ALL")) {
				iErrs += addgroup(pcGrps);
			}
			pcGrps = pcGrps + strlen(pcGrps) + 1;
		}
	}
#endif	/* HAVE_GETUSERATTR */

	if ((char *)0 != pcTty) {
		if ( '/' == *pcTty ) {
			pcDevTty = pcTty;
		} else {
			if ( (char *)0 == (pcDevTty = (char *)malloc(strlen(pcTty)+5+1) ) ) {
				(void) fprintf(stderr, "%s: malloc: %s\n", progname, strerror(errno));
				exit(1);
			}
			sprintf(pcDevTty, "/dev/%s", pcTty);
		}


		if (0 != stat(pcDevTty, &st)) {
			(void) fprintf(stderr, "%s: Can't stat %s: %s\n", progname, pcDevTty, strerror(errno));
			++iErrs;
#ifdef IBMR2
		} else if (VCHR != st.st_type && VMPC != st.st_type) {
			(void) fprintf(stderr, "%s: %s is not a character device\n", progname, pcDevTty);
			++iErrs;
#endif
		}
	} else {
		pcDevTty = (char *)0;
	}

	if (iErrs) {
		usage();
		exit(1);
		/* NOTREACHED */
	}
	if (0 != geteuid()) {
		(void) fprintf(stderr, "%s: Must be root!!!\n", progname);
		exit(1);
		/* NOTREACHED */
	}
	if (iGrps && 0 < setgroups(iGrps, awGrps)) {
		(void) fprintf(stderr, "%s: Can't setgroups(): %s\n", progname, strerror(errno));
		exit(1);
		/* NOTREACHED */
	}

	/* Close open files
	 */
	for (i = (char *)0 == pcTty ? 3 : 0; i < getdtablesize(); ++i) {
		(void) close(i);
	}

	/* Make us a session leader so that when we open /dev/tty
	 * it will become our controlling terminal.
	 */
	if (-1 == (iNewGrp = getsid(getpid()))) {
		if (-1 == (iNewGrp = setsid())) {
			(void) fprintf(stderr, "%s: setsid: %d: %s\n", progname, iNewGrp, strerror(errno));
			iNewGrp = getpid();
		}
	}

	/* Open the TTY for stdin, stdout and stderr
	 */
	if ((char *)0 != pcDevTty) {
#ifdef TIOCNOTTY
		if (-1 != (i = open("/dev/tty", 2, 0))) {
			if ( ioctl(i, TIOCNOTTY, (char *)0) )
				(void) fprintf(stderr, "%s: ioctl(%d, TIOCNOTTY, (char *)0): %s\n", progname, i, strerror(errno));
			(void) close(i);
		}
#endif
		if (0 != open(pcDevTty, O_RDWR, 0666)) {
			exit(1);
			/* NOTREACHED */
		}
		dup(0);
		dup(0);
	}

	/* put the tty in out process group
	 */
#if ! (EPIX || SUN5)
#if USE_TC
	if (-1 >= (i = tcgetpgrp(0))){
		(void) fprintf(stderr, "%s: tcgetpgrp: %s\n", progname, strerror(errno));
	}
#endif
#if USE_SETPGRP
	if (-1 != i && setpgrp(0, i) ){
		(void) fprintf(stderr, "%s: setpgrp: %s, i = %d\n", progname, strerror(errno), i);
	}
#endif

#if USE_TC
	if (tcsetpgrp(0, iNewGrp)){
		(void) fprintf(stderr, "%s: tcsetpgrp: %s\n", progname, strerror(errno));
	}
#endif
#if USE_SETPGRP
	if (-1 != iNewGrp && setpgrp(0, iNewGrp)){
		(void) fprintf(stderr, "%s: setpgrp: %s, iNewGrp = %d\n", progname, strerror(errno), iNewGrp);
	}
#endif

#endif

	/* put the tty in the correct mode
	 */
#if USE_IOCTL
	if (0 != ioctl(0, TIOCGETP, (char *)&n_sty)) {
		fprintf(stderr, "%s: iotcl: getp: %s\n", progname, strerror(errno));
		exit(10);
	}
#if USE_TC
	n_sty.sg_flags &= ~(O_CBREAK);
	n_sty.sg_flags |= (O_CRMOD|O_ECHO);
#else
	n_sty.sg_flags &= ~(CBREAK);
	n_sty.sg_flags |= (CRMOD|ECHO);
#endif
	n_sty.sg_kill = '\025';             /* ^U   */
	n_sty.sg_erase = '\010';            /* ^H   */
	if (0 != ioctl(0, TIOCSETP, (char *)&n_sty)) {
		fprintf(stderr, "%s: iotcl: setp: %s\n", progname, strerror(errno));
		exit(10);
	}

	/* stty undef all tty chars
	 */
#if 0
	if (-1 == ioctl(0, TIOCGETC, (char *)&n_tchars)) {
		fprintf(stderr, "%s: ioctl: getc: %s\n", progname, strerror(errno));
		return;
	}
	n_tchars.t_intrc = -1;
	n_tchars.t_quitc = -1;
	if (-1 == ioctl(0, TIOCSETC, (char *)&n_tchars)) {
		fprintf(stderr, "%s: ioctl: setc: %s\n", progname, strerror(errno));
		return;
	}
#endif
#if HAVE_JOBS
	if (-1 == ioctl(0, TIOCGLTC, (char *)&n_ltchars)) {
		fprintf(stderr, "%s: ioctl: gltc: %s\n", progname, strerror(errno));
		return;
	}
	n_ltchars.t_suspc = -1;
	n_ltchars.t_dsuspc = -1;
	n_ltchars.t_flushc = -1;
	n_ltchars.t_lnextc = -1;
	if (-1 == ioctl(0, TIOCSLTC, (char *)&n_ltchars)) {
		fprintf(stderr, "%s: ioctl: sltc: %s\n", progname, strerror(errno));
		return;
	}
#endif
#else	/* not using ioctl, using POSIX or sun stuff */
#if USE_TC
	if (0 != tcgetattr(0, &n_tio)) {
		(void) fprintf(stderr, "%s: tcgetattr: %s\n", progname, strerror(errno));
		exit(1);
		/* NOTREACHED */
	}
#else
	if (0 != ioctl(0, TCGETS, &n_tio)) {
		(void) fprintf(stderr, "%s: iotcl: TCGETS: %s\n", progname, strerror(errno));
		exit(1);
		/* NOTREACHED */
	}
#endif
	n_tio.c_iflag &= ~(IGNCR|IUCLC);
	n_tio.c_iflag |= ICRNL|IXON|IXANY;
	n_tio.c_oflag &= ~(OLCUC|ONOCR|ONLRET|OFILL|NLDLY|CRDLY|TABDLY|BSDLY);
	n_tio.c_oflag |= OPOST|ONLCR|TAB3;
	n_tio.c_lflag &= ~(XCASE|NOFLSH|ECHOK|ECHONL);
	n_tio.c_lflag |= ISIG|ICANON|ECHO;
	n_tio.c_cc[VEOF] = '\004';		/* ^D	*/
	n_tio.c_cc[VEOL] = '\000';		/* EOL	*/
	n_tio.c_cc[VERASE] = '\010';		/* ^H	*/
	n_tio.c_cc[VINTR] = '\003';		/* ^C	*/
	n_tio.c_cc[VKILL] = '\025';		/* ^U	*/
	/* MIN */
	n_tio.c_cc[VQUIT] = '\034';		/* ^\	*/
	n_tio.c_cc[VSTART] = '\021';		/* ^Q	*/
	n_tio.c_cc[VSTOP] = '\023';		/* ^S	*/
	n_tio.c_cc[VSUSP] = '\032';		/* ^Z	*/
#if USE_TC
	if (0 != tcsetattr(0, TCSANOW, &n_tio)) {
		(void) fprintf(stderr, "%s: tcsetattr: %s\n", progname, strerror(errno));
		exit(1);
		/* NOTREACHED */
	}
#else
	if (0 != ioctl(0, TCSETS, &n_tio)) {
		(void) fprintf(stderr, "%s: ioctl: TCSETS: %s\n", progname, strerror(errno));
		exit(1);
		/* NOTREACHED */
	}
#endif
#endif	/* setup tty */

	if (fMakeUtmp) {
		extern char *ttyname();
		make_utmp(pcLogin, (char *)0 != pcTty ? pcTty : ttyname(0));
	}
	/* Change ownership and modes on the tty.
	 */
	if ((char *)0 != pcDevTty) {
		(void) chown(pcDevTty, wUid, wGid);
		(void) chmod(pcDevTty, (mode_t) TTYMODE);
	}

	if ((char *)0 != pcCmd) {
		execl(PATH_SU, "su", "-", pcLogin, pcCmd, (char *)0);
	} else {
		execl(PATH_SU, "su", "-", pcLogin, (char *)0);
	}
}

#if NEED_PUTENV
int
putenv(pcAssign)
char *pcAssign;
{
	register char *pcEq;

	if ((char *)0 != (pcEq = strchr(pcAssign, '='))) {
		*pcEq++ = '\000';
		(void)setenv(pcAssign, pcEq, 1);
		*--pcEq = '=';
	} else {
		unsetenv(pcAssign);
	}
}
#endif

int
addgroup(pcGrp)
char	*pcGrp;
{
	struct	group		*grp;

	grp = getgrnam(pcGrp);
	if ((struct group *)0 == grp) {
		(void) fprintf(stderr, "%s: Unknown group: %s\n", progname, pcGrp);
		return(1);
	}
	if (iGrps >= NGROUPS_MAX) {
		(void) fprintf(stderr, "%s: Too many groups specified with \"%s\".\n", progname, pcGrp);
		return(1);
	}
	awGrps[iGrps++] = grp->gr_gid;
	return(0);
}


/* install a utmp entry to show the use we know is here is here		(ksb)
 */
void
make_utmp(pclogin, pctty)
char	*pclogin;
char	*pctty;
{
	register int iFound, iPos;
	register int fdUtmp;
	register char *pcDev;
	register struct utmp *up;
	auto struct utmp outmp, utmp;


	if ((char *)0 == pctty) {
		return;
	}

	if ((fdUtmp = open(UTMP_FILE, O_RDWR, 0664)) < 0) {
		return;
	}
		
	/* create empty utmp entry
	 */
	(void)memset(&utmp, 0, sizeof(struct utmp));

	/* Only the last portion of the tty is saved, unless it's
	 * all digits.  Then back up and include the previous part
	 * /dev/pty/02  -> pty/02 (not just 02)
	 */
	if ((char *)0 != (pcDev = strrchr(pctty, '/'))) {
		if (! *(pcDev + strspn(pcDev, "/0123456789"))) {
			while (pcDev != pctty && *--pcDev != '/') {
			}
		}
		if (*pcDev == '/') {
			++pcDev;
		}
	} else {
		pcDev = pctty;
	}

#if USE_OLD_UTENT
	/* look through /etc/utmp by hand (sigh)
	 */
	iFound = iPos = 0;
	while (sizeof(utmp) == read(fdUtmp, & utmp, sizeof(utmp))) {
		if (0 == strncmp(utmp.ut_line, pcDev, sizeof(utmp.ut_line))) {
			++iFound;
			break;
		}
		iPos++;
	}
	(void)strncpy(utmp.ut_name, pclogin, sizeof(utmp.ut_name));
#else
#if USE_UTENT
	/* look through getutent's by pid
	 */
	(void)setutent();
	utmp.ut_pid = getpid();
	iFound = iPos = 0;
	while ((up = getutent()) != NULL) {
		if (up->ut_pid == utmp.ut_pid) {
			utmp = *up;
			++iFound;
			break;
		}
		iPos++;
	}
	(void)endutent();
	/* we were an initprocess, now we are a login shell
	 */
	utmp.ut_type = USER_PROCESS;
	(void)strncpy(utmp.ut_user, pclogin, sizeof(utmp.ut_user));
	if ('\000' == utmp.ut_line[0]) {
		(void)strncpy(utmp.ut_line, pcDev, sizeof(utmp.ut_line));
	}
#else
	{
	register struct ttyent *ty;

	/* look through ttyslots by line?
	 */
	(void)setttyent();
	iFound = iPos = 0;
	while ((ty = getttyent()) != NULL) {
		if (strcmp(ty->ty_name, pcDev) == 0) {
			++iFound;
			break;
		}
		iPos++;
	}
	/* fill in utmp from ty ZZZ */
	(void)endttyent();
	}
	(void)strncpy(utmp.ut_line, pcDev, sizeof(utmp.ut_line));
	(void)strncpy(utmp.ut_name, pclogin, sizeof(utmp.ut_name));
	(void)strncpy(utmp.ut_host, "(autologin)", sizeof(utmp.ut_host));
#endif
#endif
	utmp.ut_time = time((time_t *) 0);

	if (0 == iFound) {
		fprintf(stderr, "%s: %s: no ttyslot\n", progname, pctty);
	} else if (-1 == lseek(fdUtmp, (off_t)(iPos*sizeof(utmp)), 0)) {
		fprintf(stderr, "%s: lseek: %s\n", progname, strerror(errno));
	} else {
		(void)write(fdUtmp, (char *)&utmp, sizeof(utmp));
	}
	(void)close(fdUtmp);
}


void
usage()
{
	char *u_pch;
	int u_loop;

	for (u_loop = 0; (char *)0 != (u_pch = au_terse[u_loop]); ++u_loop) {
		fprintf(stdout, "%s: usage%s\n", progname, u_pch);
	}
	for (u_loop = 0; (char *)0 != (u_pch = u_help[u_loop]); ++u_loop) {
		fprintf(stdout, "%s\n", u_pch);
	}

}
