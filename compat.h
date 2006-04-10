#include <config.h>

/* things everything seems to need */
#include <stdio.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <signal.h>

/* If, when processing a logfile for replaying the last N lines,
 * we end up seeing more than MAXREPLAYLINELEN characters in a line,
 * abort processing and display the data.  Why?  There could be some
 * very large logfiles and very long lines and we'd chew up lots of
 * memory and send a LOT of data down to the client - all potentially
 * bad.  If there's a line over this in size, would you really want to
 * see the whole thing (and possibly others)?
 */
#if !defined(MAXREPLAYLINELEN)
# define MAXREPLAYLINELEN 10000
#endif

/* the default escape sequence used to give meta commands
 */
#if !defined(DEFATTN)
# define DEFATTN	'\005'
#endif
#if !defined(DEFESC)
# define DEFESC		'c'
#endif

/* set the default length of the replay functions
 * DEFREPLAY for 'r'
 * DEFPLAYBACK for 'p'
 */
#if !defined(DEFREPLAY)
# define DEFREPLAY	20
#endif
#if !defined(PLAYBACK)
# define DEFPLAYBACK	60
#endif

/* For legacy compile-time setting of the port...
 */
#if ! defined(DEFPORT)
#  if defined(SERVICENAME)
#    define DEFPORT SERVICENAME
#  else
#    if defined(PORTNUMBER)
#      define DEFPORT PORTNUMBER
#    else
#      define DEFPORT "conserver"
#    endif
#  endif
#endif

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
#if !HAVE_STRCASECMP && HAVE_STRICMP
# define strcasecmp stricmp
# define strncasecmp strnicmp
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

#include <termios.h>

#ifndef TAB3
# ifdef OXTABS
#  define TAB3 OXTABS
# else
#  ifdef XTABS
#   define TAB3 XTABS
#  else
#   define TAB3 0
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

#if HAVE_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#define LO(s) ((unsigned)((s) & 0377))
#define HI(s) ((unsigned)(((s) >> 8) & 0377))
#if !defined(WIFEXITED)
#define WIFEXITED(s) (LO(s)==0)
#endif
#if !defined(WEXITSTATUS)
#define WEXITSTATUS(s) HI(s)
#endif
#if !defined(WIFSIGNALED)
#define WIFSIGNALED(s) ((LO(s)>0)&&(HI(s)==0))
#endif
#if !defined(WTERMSIG)
#define WTERMSIG(s) (LO(s)&0177)
#endif
#if !defined(WIFSTOPPED)
#define WIFSTOPPED(s) ((LO(s)==0177)&&(HI(s)!=0))
#endif
#if !defined(WSTOPSIG)
#define WSTOPSIG(s) HI(s)
#endif

#if HAVE_SYSEXITS_H
#include <sysexits.h>
#else
#define EX_OK 0
#define EX_UNAVAILABLE 69
#define EX_TEMPFAIL 75
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

#ifdef HAVE_HPSECURITY_H
# include <hpsecurity.h>
#endif

#ifdef HAVE_PROT_H
# include <prot.h>
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

#ifdef HAVE_PTY_H
#include <pty.h>
#endif

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#ifdef HAVE_UTIL_H
#include <util.h>
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

#ifndef HAVE_IN_ADDR_T
typedef unsigned long in_addr_t;
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
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
#ifndef ONOCR
#define ONOCR 0
#endif
#ifndef ONLRET
#define ONLRET 0
#endif

#ifndef SEEK_SET
#define SEEK_SET L_SET
#endif

#ifndef PARAMS
# if PROTOTYPES
#  define PARAMS(protos) protos
# else /* no PROTOTYPES */
#  define PARAMS(protos) ()
# endif	/* no PROTOTYPES */
#endif

/* setup a conditional debugging line */
#ifndef CONDDEBUG
#define CONDDEBUG(line) if (fDebug) {debugFileName=__FILE__; debugLineNo=__LINE__; Debug line;}
#endif

#if HAVE_DMALLOC
#include <dmalloc.h>
#endif
