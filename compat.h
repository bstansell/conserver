#include <config.h>


/* hpux doesn't have getdtablesize() and they don't provide a macro
 * in non-KERNEL cpp mode
 */
#ifndef HAVE_GETDTABLESIZE
# ifdef HAVE_GETRLIMIT
static int
getdtablesize()
{
	auto struct rlimit rl;

	(void)getrlimit(RLIMIT_NOFILE, &rl);
	return rl.rlim_cur;
}
# else /* ! HAVE_GETRLIMIT */
#  ifndef OPEN_MAX
#   define OPEN_MAX		64
#  endif
#  define getdtablesize()	OPEN_MAX
# endif /* HAVE_GETRLIMIT */
#endif /* ! HAVE_GETDTABLESIZE */

#if STDC_HEADERS
# include <string.h>
# include <stdlib.h>
#else
# include <strings.h>
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

/* if you do not have fd_set's here is a possible emulation
 */
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ifndef FD_ZERO
typedef long fd_set;

# define FD_ZERO(a)	{*(a)=0;}
# define FD_SET(d,a)	{*(a) |= (1 << (d));}
# define FD_CLR(d,a)	{*(a) &= ~(1 << (d));}
# define FD_ISSET(d,a)	(*(a) & (1 << (d)))
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_IOCTL_COMPAT_H
# include <sys/ioctl_compat.h>
#endif

#ifdef HAVE_TERMIOS_H
# include <termios.h>		/* POSIX */
#else
# ifdef HAVE_TERMIO_H
#  include <termio.h>		/* SysV */
# else
#  ifdef HAVE_SGTTY_H
#   include <sgtty.h>		/* BSD */
#  endif
# endif
#endif

#ifdef HAVE_STROPTS_H
# include <stropts.h>
#endif


#ifdef HAVE_TTYENT_H
# include <ttyent.h>
#endif

#ifdef HAVE_SYS_TTOLD_H
# include <sys/ttold.h>
#endif


/* which type does wait(2) take for status location
 */
#include <sys/types.h>
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#else
# define WEXITSTATUS(stat_val)	((unsigned)(stat_val) >> 8)
#endif

#ifdef HAVE_SIGACTION
extern void Set_signal(int isg, RETSIGTYPE (*disp)(int));
#else
# define Set_signal(sig, disp)	(void)signal((sig), (disp))
#endif

#include <errno.h>
#if !defined(HAVE_STRERROR)
extern int errno;
extern char *sys_errlist[];
# define strerror(Me)	(sys_errlist[Me])
#endif

#if HAVE_H_ERRLIST
extern int h_errno;
extern char *h_errlist[];
# define hstrerror(Me)	(h_errlist[Me])
#else
# define hstrerror(Me)	"host lookup error"
#endif


#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif


#if HAVE_SHADOW_H
# include <shadow.h>
#endif

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#ifdef HAVE_SYS_VLIMIT_H
# include <sys/vlimit.h>
#else
# include <limits.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif

#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif

#ifdef HAVE_SYS_PROC_H
# include <sys/proc.h>
#endif

#ifdef HAVE_SYS_AUDIT_H
# include <sys/audit.h>
#endif

#ifdef HAVE_USERSEC_H
#include <usersec.h>
#endif


#ifndef NGROUPS_MAX
# define NGROUPS_MAX	8
#endif

#ifndef HAVE_GETSID
# define getsid(Mp)	(Mp)
#endif

#ifndef HAVE_SETSID
# define setsid()	getpid()
#endif

#ifndef HAVE_SETGROUPS
# define setgroups(x, y)	0
#endif

/*
 * IUCLC, OLCUC and XCASE were removed from IEEE Std 1003.1-200x
 *  as legacy definitions.
 */
#ifndef IUCLC
#define IUCLC 0
#endif
#ifndef OLCUC
#define OLCUC 0
#endif
#ifndef XCASE
#define XCASE 0
#endif
/* Some systems don't have OFILL or *DLY. */
#ifndef OFILL
#define OFILL 0
#endif
#ifndef NLDLY
#define NLDLY 0
#endif
#ifndef CRDLY
#define CRDLY 0
#endif
#ifndef TABDLY
#define TABDLY 0
#endif
#ifndef BSDLY
#define BSDLY 0
#endif
