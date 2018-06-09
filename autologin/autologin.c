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
#include <config.h>

#include <stdio.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <utmp.h>
#if defined(HAVE_BSM_AUDIT_H) && defined(HAVE_LIBBSM)

/*
 * There is no official registry of non-vendor audit event numbers,
 * but the following should be OK.
 *
 * You need to add a line by hand to /etc/security/audit_event to make
 * praudit(1) look pretty:
 *
 *  32900:AUE_autologin:autologin:lo
 *
 * If you have to change the value for AUE_autologin, you'll also need
 * to change the /etc/security/audit_event line.
 */

# define	AUE_autologin			32900

# include <sys/unistd.h>
# include <netdb.h>
# include <bsm/audit.h>
# include <bsm/libbsm.h>
# include <libintl.h>
#endif

#include <compat.h>

#include "main.h"


#define	TTYMODE	0600

#ifndef O_RDWR
# define O_RDWR	2
#endif

#ifndef UTMP_FILE
# if defined(_PATH_UTMP)
#  define UTMP_FILE	_PATH_UTMP
# else
#  define UTMP_FILE	"/etc/utmp"
# endif
#endif

#define PATH_SU		"/bin/su"

/*
 * Global variables
 */

extern char *progname;
gid_t awGrps[NGROUPS_MAX];
int iGrps = 0;

/*
 * External variables
 */

extern int optind;
extern char *optarg;

void make_utmp(char *pclogin, char *pctty);
void usage(void);

int addgroup(char *pcGrp);

int
Process(void)
{
    int iErrs = 0;
    int i, iNewGrp;
    gid_t wGid;
    uid_t wUid;
    char *pcCmd = (char *)0, *pcDevTty = (char *)0;
#ifdef	HAVE_GETUSERATTR
    char *pcGrps;
#endif
    struct passwd *pwd;
    struct stat st;
    struct termios n_tio;
#if defined(HAVE_BSM_AUDIT_H) && defined(HAVE_LIBBSM)
    char my_hostname[MAXHOSTNAMELEN];
#endif


#if defined(HAVE_BSM_AUDIT_H) && defined(HAVE_LIBBSM)
    if (0 != gethostname(my_hostname, sizeof(my_hostname))) {
	(void)fprintf(stderr, "%s: gethostname: %s\n", progname,
		      strerror(errno));
	exit(1);
	/* NOTREACHED */
    }
#endif
    if ((char *)0 != pcCommand) {
	if ((char *)0 == (pcCmd = (char *)malloc(strlen(pcCommand) + 4))) {
	    (void)fprintf(stderr, "%s: malloc: %s\n", progname,
			  strerror(errno));
	    exit(1);
	    /* NOTREACHED */
	}
	(void)strcpy(pcCmd, "-c ");
	(void)strcat(pcCmd, pcCommand);
    }

    if ((char *)0 != pcGroup) {
	iErrs += addgroup(pcGroup);
    }

    if ((char *)0 == pcLogin) {
	static char acLogin[17];
	if ((struct passwd *)0 == (pwd = getpwuid(geteuid()))) {
	    (void)fprintf(stderr, "%s: %d: uid unknown\n", progname,
			  geteuid());
	    exit(1);
	    /* NOTREACHED */
	}
	pcLogin = strcpy(acLogin, pwd->pw_name);
    } else if ((struct passwd *)0 == (pwd = getpwnam(pcLogin))) {
	(void)fprintf(stderr, "%s: %s: login name unknown\n", progname,
		      pcLogin);
	exit(1);
	/* NOTREACHED */
    }
    wUid = pwd->pw_uid;
    wGid = pwd->pw_gid;
    (void)endpwent();
#ifdef	HAVE_GETUSERATTR
    /* getuserattr() returns a funny list of groups:
     *      "grp1\0grp2\0grp3\0\0"
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
#endif /* HAVE_GETUSERATTR */
    (void)endgrent();

    if ((char *)0 != pcTty) {
	if ('/' == *pcTty) {
	    pcDevTty = pcTty;
	} else {
	    if ((char *)0 ==
		(pcDevTty = (char *)malloc(strlen(pcTty) + 5 + 1))) {
		(void)fprintf(stderr, "%s: malloc: %s\n", progname,
			      strerror(errno));
		exit(1);
	    }
	    sprintf(pcDevTty, "/dev/%s", pcTty);
	}


	if (0 != stat(pcDevTty, &st)) {
	    (void)fprintf(stderr, "%s: Can't stat %s: %s\n", progname,
			  pcDevTty, strerror(errno));
	    ++iErrs;
#if defined(VCHR) && defined(VMPC)
	} else if (VCHR != st.st_type && VMPC != st.st_type) {
	    (void)fprintf(stderr, "%s: %s is not a character device\n",
			  progname, pcDevTty);
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
	(void)fprintf(stderr, "%s: Must be root!!!\n", progname);
	exit(1);
	/* NOTREACHED */
    }
    if (iGrps && 0 < setgroups(iGrps, awGrps)) {
	(void)fprintf(stderr, "%s: Can't setgroups(): %s\n", progname,
		      strerror(errno));
	exit(1);
	/* NOTREACHED */
    }

    /* Close open files
     */
    for (i = (char *)0 == pcTty ? 3 : 0; i < getdtablesize(); ++i) {
	(void)close(i);
    }

    /* Make us a session leader so that when we open /dev/tty
     * it will become our controlling terminal.
     */
    if (-1 == (iNewGrp = getsid(getpid()))) {
	if (-1 == (iNewGrp = setsid())) {
	    (void)fprintf(stderr, "%s: setsid: %d: %s\n", progname,
			  iNewGrp, strerror(errno));
	    iNewGrp = getpid();
	}
    }
#if defined(HAVE_BSM_AUDIT_H) && defined(HAVE_LIBBSM)
    if (!cannot_audit(0)) {
# if defined(HAVE_GETAUDIT_ADDR)
	struct auditinfo_addr audit_info;
# else
	struct auditinfo audit_info;
# endif
	au_mask_t audit_mask;
# if !defined(HAVE_GETAUDIT_ADDR)
	struct hostent *hp;
# endif
	int iAuditFile;
	int fShowEvent = 1;
	token_t *ptAuditToken;

	(void)memset(&audit_info, 0, sizeof(audit_info));
	audit_info.ai_auid = wUid;
	audit_info.ai_asid = getpid();
	audit_mask.am_success = audit_mask.am_failure = 0;
	(void)au_user_mask(pcLogin, &audit_mask);
	audit_info.ai_mask.am_success = audit_mask.am_success;
	audit_info.ai_mask.am_failure = audit_mask.am_failure;
# if defined(HAVE_GETAUDIT_ADDR)
	(void)aug_get_machine(my_hostname,
			      &audit_info.ai_termid.at_addr[0],
			      &audit_info.ai_termid.at_type);
# else
	if ((char *)0 != (hp = gethostbyname(my_hostname))
	    && AF_INET == hp->h_addrtype) {
	    (void)memcpy(&audit_info.ai_termid.machine, hp->h_addr,
			 sizeof(audit_info.ai_termid.machine));
	}
# endif
# if defined(HAVE_GETAUDIT_ADDR)
	if (0 > setaudit_addr(&audit_info, sizeof(audit_info)))
# else
	if (0 > setaudit(&audit_info))
# endif
	{
	    fprintf(stderr, "%s: setaudit failed: %s\n", progname,
		    strerror(errno));
	    fShowEvent = 0;
	}
	if (fShowEvent) {
	    fShowEvent =
		au_preselect(AUE_autologin, &audit_mask, AU_PRS_SUCCESS,
			     AU_PRS_REREAD);
	}
	if (fShowEvent) {
	    iAuditFile = au_open();
# if defined(HAVE_GETAUDIT_ADDR)
	    ptAuditToken =
		au_to_subject_ex(wUid, wUid, wGid, wUid, wGid,
				 audit_info.ai_asid, audit_info.ai_asid,
				 &audit_info.ai_termid),
# else
	    ptAuditToken =
		au_to_subject(wUid, wUid, wGid, wUid, wGid,
			      audit_info.ai_asid, audit_info.ai_asid,
			      &audit_info.ai_termid),
# endif
		(void)au_write(iAuditFile, ptAuditToken);
	    ptAuditToken = au_to_text(gettext("successful login"));
	    (void)au_write(iAuditFile, ptAuditToken);
	    if ((char *)0 != pcCmd) {
		ptAuditToken = au_to_text(pcCmd);
		(void)au_write(iAuditFile, ptAuditToken);
	    }
# if defined(HAVE_GETAUDIT_ADDR)
	    ptAuditToken = au_to_return32(0, 0);
# else
	    ptAuditToken = au_to_return(0, 0);
# endif
	    (void)au_write(iAuditFile, ptAuditToken);
	    if (0 > au_close(iAuditFile, AU_TO_WRITE, AUE_autologin)) {
		fprintf(stderr, "%s: audit write failed: %s", progname,
			strerror(errno));
	    }
	}
    }
#endif

    /* Open the TTY for stdin, stdout and stderr
     */
    if ((char *)0 != pcDevTty) {
#ifdef TIOCNOTTY
	if (-1 != (i = open("/dev/tty", 2, 0))) {
	    if (ioctl(i, TIOCNOTTY, (char *)0))
		(void)fprintf(stderr,
			      "%s: ioctl(%d, TIOCNOTTY, (char *)0): %s\n",
			      progname, i, strerror(errno));
	    (void)close(i);
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
#ifdef HAVE_TCGETPGRP
    if (-1 >= (i = tcgetpgrp(0))) {
	(void)fprintf(stderr, "%s: tcgetpgrp: %s\n", progname,
		      strerror(errno));
    }
#endif
    if (-1 != i && setpgrp()) {
	(void)fprintf(stderr, "%s: setpgrp: %s, i = %d\n", progname,
		      strerror(errno), i);
    }
#ifdef HAVE_TCSETPGRP
    if (tcsetpgrp(0, iNewGrp)) {
	(void)fprintf(stderr, "%s: tcsetpgrp: %s\n", progname,
		      strerror(errno));
    }
#endif
    if (-1 != iNewGrp && setpgrp()) {
	(void)fprintf(stderr, "%s: setpgrp: %s, iNewGrp = %d\n", progname,
		      strerror(errno), iNewGrp);
    }

    /* put the tty in the correct mode
     */
#ifdef HAVE_TCGETATTR
    if (0 != tcgetattr(0, &n_tio)) {
	(void)fprintf(stderr, "%s: tcgetattr: %s\n", progname,
		      strerror(errno));
	exit(1);
	/* NOTREACHED */
    }
#else
    if (0 != ioctl(0, TCGETS, &n_tio)) {
	(void)fprintf(stderr, "%s: iotcl: TCGETS: %s\n", progname,
		      strerror(errno));
	exit(1);
	/* NOTREACHED */
    }
#endif
    n_tio.c_iflag &= ~(IGNCR | IUCLC);
    n_tio.c_iflag |= ICRNL | IXON | IXANY;
    n_tio.c_oflag &=
	~(OLCUC | ONOCR | ONLRET | OFILL | NLDLY | CRDLY | TABDLY | BSDLY);
    n_tio.c_oflag |= OPOST | ONLCR | TAB3;
    n_tio.c_lflag &= ~(XCASE | NOFLSH | ECHOK | ECHONL);
    n_tio.c_lflag |= ISIG | ICANON | ECHO;
    n_tio.c_cc[VEOF] = '\004';	/* ^D   */
    n_tio.c_cc[VEOL] = '\000';	/* EOL  */
    n_tio.c_cc[VERASE] = '\010';	/* ^H   */
    n_tio.c_cc[VINTR] = '\003';	/* ^C   */
    n_tio.c_cc[VKILL] = '\025';	/* ^U   */
    /* MIN */
    n_tio.c_cc[VQUIT] = '\034';	/* ^\   */
    n_tio.c_cc[VSTART] = '\021';	/* ^Q   */
    n_tio.c_cc[VSTOP] = '\023';	/* ^S   */
    n_tio.c_cc[VSUSP] = '\032';	/* ^Z   */
#ifdef HAVE_TCSETATTR
    if (0 != tcsetattr(0, TCSANOW, &n_tio)) {
	(void)fprintf(stderr, "%s: tcsetattr: %s\n", progname,
		      strerror(errno));
	exit(1);
	/* NOTREACHED */
    }
#endif

    if (fMakeUtmp) {
	extern char *ttyname();
	make_utmp(pcLogin, (char *)0 != pcTty ? pcTty : ttyname(0));
    }
    /* Change ownership and modes on the tty.
     */
    if ((char *)0 != pcDevTty) {
	(void)chown(pcDevTty, wUid, wGid);
	(void)chmod(pcDevTty, (mode_t) TTYMODE);
    }

    if ((char *)0 != pcCmd) {
	execl(PATH_SU, "su", "-", pcLogin, pcCmd, (char *)0);
    } else {
	execl(PATH_SU, "su", "-", pcLogin, (char *)0);
    }
}

#ifndef HAVE_PUTENV
int
putenv(char *pcAssign)
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
addgroup(char *pcGrp)
{
    struct group *grp;

    grp = getgrnam(pcGrp);
    if ((struct group *)0 == grp) {
	(void)fprintf(stderr, "%s: Unknown group: %s\n", progname, pcGrp);
	return (1);
    }
    if (iGrps >= NGROUPS_MAX) {
	(void)fprintf(stderr,
		      "%s: Too many groups specified with \"%s\".\n",
		      progname, pcGrp);
	return (1);
    }
    awGrps[iGrps++] = grp->gr_gid;
    return (0);
}


/* install a utmp entry to show the use we know is here is here		(ksb)
 */
void
make_utmp(char *pclogin, char *pctty)
{
    register int iFound, iPos;
    register int fdUtmp;
    register char *pcDev;
    register struct utmp *up;
    auto struct utmp utmp;


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
	if (!*(pcDev + strspn(pcDev, "/0123456789"))) {
	    while (pcDev != pctty && *--pcDev != '/') {
	    }
	}
	if (*pcDev == '/') {
	    ++pcDev;
	}
    } else {
	pcDev = pctty;
    }

#ifdef HAVE_GETUTENT
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
# ifdef HAVE_SETTTYENT
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
# else
    /* look through /etc/utmp by hand (sigh)
     */
    iFound = iPos = 0;
    while (sizeof(utmp) == read(fdUtmp, &utmp, sizeof(utmp))) {
	if (0 == strncmp(utmp.ut_line, pcDev, sizeof(utmp.ut_line))) {
	    ++iFound;
	    break;
	}
	iPos++;
    }
    (void)strncpy(utmp.ut_name, pclogin, sizeof(utmp.ut_name));
# endif
#endif
    utmp.ut_time = time((time_t *)0);

    if (0 == iFound) {
	fprintf(stderr, "%s: %s: no ttyslot\n", progname, pctty);
    } else if (-1 == lseek(fdUtmp, (off_t) (iPos * sizeof(utmp)), 0)) {
	fprintf(stderr, "%s: lseek: %s\n", progname, strerror(errno));
    } else {
	(void)write(fdUtmp, (char *)&utmp, sizeof(utmp));
    }
    (void)close(fdUtmp);
}


void
usage(void)
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
