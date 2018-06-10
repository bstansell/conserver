AC_PREREQ([2.59])
AC_INIT([conserver],
  [m4_esyscmd([build-aux/git-version-gen .tarball-version])],
  [bryan@conserver.com], [],
  [https://www.conserver.com/])
configure_flags="$*"
AC_CONFIG_SRCDIR([conserver/main.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([
  1.7.9
  dist-xz
  foreign
  no-dist-gzip
  subdir-objects
  tar-pax
])

# Basic autotools configuration.
m4_ifdef([AM_SILENT_RULES],
  [AM_SILENT_RULES([yes])],
  [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AC_CANONICAL_HOST
AC_C_CONST
AC_PROG_CC_C99
AC_PROG_INSTALL

AC_DEFINE_UNQUOTED([VERSION_TEXT], ["conserver.com version"], [Version banner])
version_int=`echo $PACKAGE_VERSION | awk -F. '{print $1 * 1000000 + $2 * 1000 + $3}'`
AC_DEFINE_UNQUOTED([VERSION_UINT], [$version_int],
  [Conserver version as unsigned int])

AC_DEFINE_UNQUOTED([COPYRIGHT],
  ["Copyright 1990 The Ohio State University.\n\
Copyright 1992 Purdue Research Foundation.\n\
Copyright 1998 GNAC, Inc.\n\
Copyright 2000 conserver.com.\n\
All rights reserved.\n"],
  [Conserver copyright])

usrsbin_execdir='${exec_prefix}/sbin'
AC_SUBST([usrsbin_execdir])

# Check pkg-config availability.
m4_ifndef([PKG_PROG_PKG_CONFIG],
  [m4_fatal(
[Could not locate the pkg-config autoconf macros.  These are usually located
in /usr/share/aclocal/pkg.m4.  If your macros are in a different location,
try setting the environment variable ACLOCAL_OPTS="-I/other/macro/dir"
before running ./autogen.sh again.])
])
PKG_PROG_PKG_CONFIG

# Check headers.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_TIME

AC_CHECK_HEADERS([ \
  bsd/unistd.h \
  bsm/audit.h \
  hpsecurity.h \
  libutil.h \
  prot.h \
  pty.h \
  sys/ioctl.h \
  sys/proc.h \
  util.h \
])

# Check functions.
AC_CHECK_FUNCS([ \
  bigcrypt \
  getaudit \
  getaudit_addr \
  getdtablesize \
  getlogin \
  getopt \
  getprpwnam \
  getrlimit \
  getsid \
  getspnam \
  gettimeofday \
  getuserattr \
  getutent \
  grantpt \
  inet_aton \
  iscomsec \
  memcmp \
  memcpy \
  memmove \
  memset \
  ptsname \
  putenv \
  setgroups \
  setlinebuf \
  setpgrp \
  setsid \
  setsockopt \
  setttyent \
  setvbuf \
  sigaction \
  strerror \
  strlcpy \
  sysconf \
  tcgetattr \
  tcgetpgrp \
  tcsendbreak \
  tcsetattr \
  tcsetpgrp \
  unlockpt \
])

dnl Check if openpty() is available without linking with libutil.
AC_SEARCH_LIBS([openpty], [util], [UTIL_LIBS=""], [UTIL_LIBS="-lutil"])
AS_IF([test "x$ac_cv_search_openpty" != "xno"],
  [AC_DEFINE([HAVE_OPENPTY], [1], [Defined if openpty exists])])
AC_SUBST([UTIL_LIBS])

# Check types.
AC_TYPE_MODE_T
AC_TYPE_SIGNAL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T

AC_CHECK_TYPE([sig_atomic_t], [], [
  AC_DEFINE([sig_atomic_t, volatile int],
    [Define if <signal.h> does not define sig_atomic_t])
], [#include <signal.h>])

AC_CHECK_TYPE([in_addr_t], [
  AC_DEFINE([HAVE_IN_ADDR_T], [1], [Defined if in_addr_t exists])
], [], [$ac_includes_default
#include <netinet/in.h>])
AC_CHECK_TYPE([socklen_t], [
  AC_DEFINE([HAVE_SOCKLEN_T], [1], [Defined if socklen_t exists])
], [], [$ac_includes_default
#include <sys/socket.h>])

AC_MSG_CHECKING([for sa_len in struct sockaddr])
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>], [struct sockaddr s; s.sa_len=0;],
[AC_MSG_RESULT([yes])
 AC_DEFINE([HAVE_SA_LEN], [1], [Define if struct sockaddr has sa_len field])],
[AC_MSG_RESULT([no])])

# Check libraries.
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([crypt], [crypt])

# Add function for dependencies provided by pkg-config.
# CONSERVER_PKG([with], [description], [VALUE], [pkg-config package])
AC_DEFUN([CONSERVER_PKG], [
  AC_ARG_WITH([$1],
    [AS_HELP_STRING([--with-$1], [Define to compile with $2 support])])
  AS_IF([test "x$with_$1" = "xyes"], [
    PKG_CHECK_MODULES([$3], [$4],
      [AC_DEFINE([HAVE_$3], [1], [Use $2])])
  ], [
    with_$1="no"
  ])
])

# Add function implementing --with-foo=bar options.
# CONSERVER_WITH([with], [VALUE], [default], [description], [unquoted])
AC_DEFUN([CONSERVER_WITH], [
  AC_ARG_WITH([$1],
    [AS_HELP_STRING([--with-$1=$2], [$4, default: @<:@$3@:>@])],
    [conserver_withval="$withval"],
    [conserver_withval=$3])
  AS_IF([test "1" = "$5"],
    [AC_DEFINE_UNQUOTED([$2], [$conserver_withval], [$4])],
    [AC_DEFINE_UNQUOTED([$2], ["$conserver_withval"], [$4])]
  )
  AC_SUBST([$2], [$conserver_withval])
  $2=$conserver_withval
])

# Add function implemeting --with-foo / --without-foo boolean.
# CONSERVER_WWOPT([with], [VALUE], [description])
AC_DEFUN([CONSERVER_WWOPT], [
  AC_ARG_WITH([$1],
    [AS_HELP_STRING([--with-$1],[$3])],
    [AC_DEFINE([$2], [1], [$3])
     AM_CONDITIONAL([$2], [true])
     $2=yes],
    [AM_CONDITIONAL([$2], [false])
     $2=no]
  )
])

# Add function implementing --with-foo=PATH
# CONSERVER_PATH([with], [VALUE], [default], [description])
AC_DEFUN([CONSERVER_PATH], [
  conserver_withval="$3"
  AC_ARG_WITH([$1],
    [AS_HELP_STRING([--with-$1=PATH], [$4, default: @<:@$3@:>@])],
    [conserver_withval="$withval"])
  AC_SUBST([$2], [$conserver_withval])
  $2=$conserver_withval
])

# The dmalloc is one of a kind.
with_dmalloc=no
AC_ARG_WITH([dmalloc],
  [AS_HELP_STRING([--with-dmalloc=DIR], [Define to compile with dmalloc support)])],
  [AS_CASE([$with_dmalloc],
    [yes], [],
    [no], [],
    [CPPFLAGS="$CPPFLAGS -I$with_dmalloc"]
  )]
  AS_IF([test "$with_dmalloc" != "no"],
    [AC_CHECK_HEADERS([dmalloc.h], [], [AC_MSG_ERROR([cannot find dmalloc.h header])])]
  )
)

CONSERVER_PKG([freeipmi], [FreeIPMI], [FREEIPMI], [libipmiconsole])
CONSERVER_PKG([gssapi], [GSS-API], [GSSAPI], [krb5-gssapi])
CONSERVER_PKG([json], [json-c], [JSON], [json-c])
CONSERVER_PKG([libbsd], [libbsd], [SETPROCTITLE], [libbsd])
CONSERVER_PKG([openssl], [OpenSSL], [OPENSSL], [openssl])

CONSERVER_WWOPT([libwrap], [USE_LIBWRAP], [Define to compile with libwrap support])
AS_IF([test -z "$USE_LIBWRAP_TRUE"],
  [AC_CHECK_HEADERS([tcpd.h], [],
    [AC_MSG_ERROR([cannot find tcpd.h header])])],
  [with_libwrap="no"]
)
CONSERVER_WWOPT([pam], [HAVE_PAM], [Define to compile with PAM support])
AS_IF([test -z "$HAVE_PAM_TRUE"],
  [AC_CHECK_HEADERS([security/pam_misc.h], [],
    [AC_MSG_ERROR([cannot find security/pam_misc.h header])])],
  [with_pam="no"]
)
CONSERVER_WWOPT([ipv6], [USE_IPV6], [Define to compile with (experimental) IPv6 client/server])
CONSERVER_WWOPT([autologin], [BUILD_AUTOLOGIN], [Define to compile autologin])
CONSERVER_WWOPT([chat], [BUILD_CHAT], [Define to compile chat from contrib])

CONSERVER_WITH([port], [DEFPORT], [conserver], [Socket used to communicate])
CONSERVER_WITH([base], [DEFBASEPORT], [0], [Base socket used for secondary channel])
CONSERVER_WITH([master], [MASTERHOST], [console], [Master server hostname])

CONSERVER_PATH([cffile], [CONFIGFILE], [${sysconfdir}/conserver.cf], [Config file path])
CONSERVER_PATH([ccffile], [CLIENTCONFIGFILE], [${sysconfdir}/conserver.cf], [Client config file path])
CONSERVER_PATH([pwdfile], [PASSWDFILE], [${sysconfdir}/conserver.passwd], [Password file path])
CONSERVER_PATH([logfile], [LOGFILEPATH], [${localstatedir}/log/conserver], [Logfile path])
CONSERVER_PATH([pidfile], [PIDFILE], [${localstatedir}/run/conserver.pid], [pidfile to write to])

CONSERVER_WITH([maxmemb], [MAXMEMB], [16], [Number of consoles per child process], [1])
CONSERVER_WITH([timeout], [CONNECTTIMEOUT], [10], [TCP connection timeout], [1])
CONSERVER_WITH([uds], [UDSDIR], [/tmp/conserver], [Directory for Unix domain sockets])

CONSERVER_WWOPT([striprealm], [STRIP_REALM], [Define to retry username without @REALM with gss-api authentication])
CONSERVER_WWOPT([trustrevdns], [TRUST_REVERSE_DNS], [Define if we trust reverse DNS])
CONSERVER_WWOPT([extmsgs], [USE_EXTENDED_MESSAGES], [Define if we produce extended messages])
CONSERVER_WWOPT([trust-uds-cred], [TRUST_UDS_CRED], [Define if we trust credentials from UDS client])
CONSERVER_WWOPT([req-server-cert], [REQ_SERVER_CERT], [Defined if client requires server SSL certificate])
CONSERVER_WWOPT([cycladests], [FOR_CYCLADES_TS], [(deprecated - noop) Define for a Cyclades TS])

AC_DEFINE_UNQUOTED([CONFIGINVOCATION], ["$0 $configure_flags"], [Build time ./configure command line])

# Prepare config.h, Makefile, and output them.
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

AC_MSG_RESULT([==============================================================
Feature Summary
  ${PACKAGE}:         ${VERSION}

  compiler:         ${CC}
  cflags:           ${CFLAGS}

  prefix:           ${prefix}
  cffile:           ${CONFIGFILE}
  ccffile:          ${CLIENTCONFIGFILE}
  pwdfile:          ${PASSWDFILE}
  logfile:          ${LOGFILEPATH}
  pidfile:          ${PIDFILE}

  dmalloc:          ${with_dmalloc}
  freeipmi:         ${with_freeipmi}
  gssapi:           ${with_gssapi}
  openssl:          ${with_openssl}
  json:             ${with_json}
  libbsd:           ${with_libbsd}
  libwrap:          ${with_libwrap}
  pam:              ${with_pam}
  ipv6:             ${USE_IPV6}
  autologin:        ${BUILD_AUTOLOGIN}
  chat:             ${BUILD_CHAT}
  port:             ${DEFPORT}
  base:             ${DEFBASEPORT}
  master:           ${MASTERHOST}
  maxmemb:          ${MAXMEMB}
  timeout:          ${CONNECTTIMEOUT}
  uds:              ${UDSDIR}
  striprealm:       ${STRIP_REALM}
  trustrevdns:      ${TRUST_REVERSE_DNS}
  extmsgs:          ${USE_EXTENDED_MESSAGES}
  trust-uds-cred:   ${TRUST_UDS_CRED}
  req-server-cert:  ${REQ_SERVER_CERT}
==============================================================])
