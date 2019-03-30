dnl ### autoheader templates ########################################
AH_TEMPLATE([CONFIGINVOCATION], [./configure invocation])
AH_TEMPLATE([DEFPORT], [Socket used to communicate])
AH_TEMPLATE([DEFBASEPORT], [Base socket used for secondary channel])
AH_TEMPLATE([MASTERHOST], [Hostname of console server])
AH_TEMPLATE([CONFIGFILE], [Config file path])
AH_TEMPLATE([CLIENTCONFIGFILE], [Client config file path])
AH_TEMPLATE([PASSWDFILE], [Password file path])
AH_TEMPLATE([LOGFILEPATH], [Logfile path])
AH_TEMPLATE([MAXMEMB], [Number of consoles per child process])
AH_TEMPLATE([CONNECTTIMEOUT], [TCP connection timeout])
AH_TEMPLATE([PIDFILE], [pidfile to write to])
AH_TEMPLATE([USE_LIBWRAP], [use tcp_wrappers libwrap])
dnl AH_TEMPLATE([HAVE_POSIX_REGCOMP], [have POSIX regcomp])
AH_TEMPLATE([HAVE_PAM], [have PAM support])
AH_TEMPLATE([HAVE_OPENSSL], [have openssl support])
AH_TEMPLATE([HAVE_GSSAPI], [have gss-api support])
AH_TEMPLATE([HAVE_FREEIPMI], [have freeipmi support])
AH_TEMPLATE([STRIP_REALM], [retry username without @REALM with gss-api authentication])
AH_TEMPLATE([HAVE_DMALLOC], [have dmalloc support])
AH_TEMPLATE([HAVE_SA_LEN],[Defined if sa_len member exists in struct sockaddr])
AH_TEMPLATE([TRUST_REVERSE_DNS],[Defined if we trust reverse DNS])
AH_TEMPLATE([USE_EXTENDED_MESSAGES],[Defined if we produce extended messages])
AH_TEMPLATE([USE_UNIX_DOMAIN_SOCKETS],[Defined if we use Unix domain sockets])
AH_TEMPLATE([USE_IPV6], [Defined if building with IPv6 support])
AH_TEMPLATE([UDSDIR], [Directory for Unix domain sockets])
AH_TEMPLATE([FOR_CYCLADES_TS], [Defined if building for a Cyclades TS])
AH_TEMPLATE([REQ_SERVER_CERT], [Defined if client requires server SSL certificate])
AH_TEMPLATE([TRUST_UDS_CRED], [Defined if we trust credentials from UDS client])

dnl ### Normal initialization. ######################################
AC_INIT([conserver],m4_esyscmd_s([./package/get-version number]))
AC_PREREQ(2.59)
AC_CONFIG_SRCDIR([conserver/main.c])
AC_CONFIG_HEADER(config.h)

AC_DEFINE_UNQUOTED(CONFIGINVOCATION, "$0 $@")

dnl ### Set some option defaults. ###################################
if test -z "$CFLAGS"; then
  CFLAGS="-O"
fi
MKDIR="mkdir -p -m 755"
AC_SUBST(MKDIR)

AC_SUBST(CONSERVER_VERSION, m4_esyscmd_s([./package/get-version number]))
AC_SUBST(CONSERVER_DATE, m4_esyscmd_s([./package/get-version date]))


dnl ### Custom settings. ############################################
dnl AC_MSG_CHECKING(whether to allow 64bit compilation)
dnl AC_ARG_WITH(64bit,
dnl 	AC_HELP_STRING([--with-64bit],[Allow 64bit compilation]),
dnl 		[case "$withval" in
dnl 		    yes)
dnl 			with_64bit=yes
dnl 			;;
dnl 		    *)
dnl 			with_64bit=no
dnl 			;;
dnl 		esac], [with_64bit=no])
dnl AC_MSG_RESULT($with_64bit)

AC_MSG_CHECKING(for port number specification)
AC_ARG_WITH(port,
	AS_HELP_STRING([--with-port=PORT],[Specify port number @<:@conserver@:>@]),
	[case "$withval" in
	    yes|no)
		AC_DEFINE_UNQUOTED(DEFPORT, "conserver")
		AC_MSG_RESULT(port 'conserver')
		;;
	    *)
		AC_DEFINE_UNQUOTED(DEFPORT, "$withval")
		AC_MSG_RESULT(port '$withval')
		;;
	esac],
	[AC_DEFINE_UNQUOTED(DEFPORT, "conserver")
	AC_MSG_RESULT(port 'conserver')])

AC_MSG_CHECKING(for secondary channel base port)
AC_ARG_WITH(base,
	AS_HELP_STRING([--with-base=PORT], [Base port for secondary channel @<:@0@:>@]),
	[case "$withval" in
	    yes|no)
		AC_DEFINE_UNQUOTED(DEFBASEPORT, "0")
		AC_MSG_RESULT(port '0')
		;;
	    *)
		AC_DEFINE_UNQUOTED(DEFBASEPORT, "$withval")
		AC_MSG_RESULT(port '$withval')
		;;
	esac],
	[AC_DEFINE_UNQUOTED(DEFBASEPORT, "0")
	AC_MSG_RESULT(port '0')])

AC_MSG_CHECKING(for master conserver hostname)
AC_ARG_WITH(master,
	AS_HELP_STRING([--with-master=MASTER],[Specify master server hostname @<:@console@:>@]),
	[case "$withval" in
	    yes|no)
		AC_DEFINE_UNQUOTED(MASTERHOST, "console")
		AC_MSG_RESULT('console')
		;;
	    *)
		AC_DEFINE_UNQUOTED(MASTERHOST, "$withval")
		AC_MSG_RESULT('$withval')
		;;
	esac],
	[AC_DEFINE_UNQUOTED(MASTERHOST, "console")
	AC_MSG_RESULT('console')])

AC_MSG_CHECKING(for client configuration filename)
AC_ARG_WITH(ccffile,
	AS_HELP_STRING([--with-ccffile=CFFILE],[Specify client config filename @<:@SYSCONFDIR/console.cf@:>@]),
	[case "$withval" in
	    yes|no)
		AC_DEFINE_UNQUOTED(CLIENTCONFIGFILE, [SYSCONFDIR "/console.cf"])
		AC_MSG_RESULT('$sysconfdir/console.cf')
		;;
	    [[\\/]]* | ?:[[\\/]]* )
		AC_DEFINE_UNQUOTED(CLIENTCONFIGFILE, ["$withval"])
		AC_MSG_RESULT('$withval')
		;;
	    *)
		AC_DEFINE_UNQUOTED(CLIENTCONFIGFILE, [SYSCONFDIR "/$withval"])
		AC_MSG_RESULT('$sysconfdir/$withval')
		;;
	esac],
	[AC_DEFINE_UNQUOTED(CLIENTCONFIGFILE, [SYSCONFDIR "/console.cf"])
	AC_MSG_RESULT('$sysconfdir/console.cf')])

AC_MSG_CHECKING(for configuration filename)
AC_ARG_WITH(cffile,
	AS_HELP_STRING([--with-cffile=CFFILE],[Specify config filename @<:@SYSCONFDIR/conserver.cf@:>@]),
	[case "$withval" in
	    yes|no)
		AC_DEFINE_UNQUOTED(CONFIGFILE, [SYSCONFDIR "/conserver.cf"])
		AC_MSG_RESULT('$sysconfdir/conserver.cf')
		;;
	    [[\\/]]* | ?:[[\\/]]* )
		AC_DEFINE_UNQUOTED(CONFIGFILE, ["$withval"])
		AC_MSG_RESULT('$withval')
		;;
	    *)
		AC_DEFINE_UNQUOTED(CONFIGFILE, [SYSCONFDIR "/$withval"])
		AC_MSG_RESULT('$sysconfdir/$withval')
		;;
	esac],
	[AC_DEFINE_UNQUOTED(CONFIGFILE, [SYSCONFDIR "/conserver.cf"])
	AC_MSG_RESULT('$sysconfdir/conserver.cf')])

AC_MSG_CHECKING(for password filename)
AC_ARG_WITH(pwdfile,
	AS_HELP_STRING([--with-pwdfile=PWDFILE],[Specify password filename @<:@SYSCONFDIR/conserver.passwd@:>@]),
	[case "$withval" in
	    yes|no)
		AC_DEFINE_UNQUOTED(PASSWDFILE, [SYSCONFDIR "/conserver.passwd"])
		AC_MSG_RESULT('$sysconfdir/conserver.passwd')
		;;
	    [[\\/]]* | ?:[[\\/]]* )
		AC_DEFINE_UNQUOTED(PASSWDFILE, ["$withval"])
		AC_MSG_RESULT('$withval')
		;;
	    *)
		AC_DEFINE_UNQUOTED(PASSWDFILE, [SYSCONFDIR "/$withval"])
		AC_MSG_RESULT('$sysconfdir/$withval')
		;;
	esac],
	[AC_DEFINE_UNQUOTED(PASSWDFILE, [SYSCONFDIR "/conserver.passwd"])
	AC_MSG_RESULT('$sysconfdir/conserver.passwd')])

AC_MSG_CHECKING(for log filename)
AC_ARG_WITH(logfile,
	AS_HELP_STRING([--with-logfile=LOGFILE],[Specify log filename @<:@/var/log/conserver@:>@]),
	[case "$withval" in
	    yes|no)
		AC_DEFINE_UNQUOTED(LOGFILEPATH, "/var/log/conserver")
		AC_MSG_RESULT('/var/log/conserver')
		;;
	    *)
		AC_DEFINE_UNQUOTED(LOGFILEPATH, "$withval")
		AC_MSG_RESULT('$withval')
		;;
	esac],
	[AC_DEFINE_UNQUOTED(LOGFILEPATH, "/var/log/conserver")
	AC_MSG_RESULT('/var/log/conserver')])

AC_SUBST(PIDFILE)
AC_MSG_CHECKING(for PID filename)
AC_ARG_WITH(pidfile,
	AS_HELP_STRING([--with-pidfile=PIDFILE],[Specify PID filepath @<:@/var/run/conserver.pid@:>@]),
	[case "$withval" in
	    yes|no)
		PIDFILE="/var/run/conserver.pid"
		;;
	    *)
		PIDFILE="$withval"
		;;
	esac],
	[PIDFILE="/var/run/conserver.pid"])
AC_DEFINE_UNQUOTED(PIDFILE, "$PIDFILE")
AC_MSG_RESULT('$PIDFILE')

AC_MSG_CHECKING(for MAXMEMB setting)
AC_ARG_WITH(maxmemb,
	AS_HELP_STRING([--with-maxmemb=MAXMEMB],[Specify maximum consoles per process @<:@16@:>@]),
	[case "$withval" in
	    yes|no)
		AC_DEFINE_UNQUOTED(MAXMEMB, 16)
		AC_MSG_RESULT(16)
		;;
	    *)
		if expr "$withval" : '[[0-9]]*$' >/dev/null 2>&1 &&
		   test "$withval" -gt 0 -a "$withval" -lt 256; then
		    AC_DEFINE_UNQUOTED(MAXMEMB, $withval)
		    AC_MSG_RESULT($withval)
		else
		    AC_DEFINE_UNQUOTED(MAXMEMB, 16)
		    AC_MSG_RESULT([value out of bounds (0<x<256) - setting to 16])
		fi
		;;
	esac],
	[AC_DEFINE_UNQUOTED(MAXMEMB, 16)
	AC_MSG_RESULT(16)])

AC_MSG_CHECKING(for connect() timeout)
AC_ARG_WITH(timeout,
	AS_HELP_STRING([--with-timeout=TIMEOUT],[Specify connect() timeout in seconds @<:@10@:>@]),
	[if expr "$withval" : '[[0-9]]*$' >/dev/null 2>&1 &&
	    test "$withval" -gt 0 -a "$withval" -lt 300; then
		AC_DEFINE_UNQUOTED(CONNECTTIMEOUT, $withval)
		AC_MSG_RESULT($withval)
	else
		AC_DEFINE_UNQUOTED(CONNECTTIMEOUT, 10)
		AC_MSG_RESULT([value out of bounds (0<x<300) - setting to 10])
	fi],
	[AC_DEFINE_UNQUOTED(CONNECTTIMEOUT, 10)
	AC_MSG_RESULT(10)])

AC_MSG_CHECKING(whether to trust reverse DNS)
AC_ARG_WITH(trustrevdns,
	AS_HELP_STRING([--with-trustrevdns],[Trust reverse DNS information]),
	[case "$withval" in
	    yes)
		AC_DEFINE(TRUST_REVERSE_DNS)
		AC_MSG_RESULT(yes)
		;;
	    *)
		AC_MSG_RESULT(no)
		;;
	esac],[AC_MSG_RESULT(no)])

AC_MSG_CHECKING(whether to display extended messages)
AC_ARG_WITH(extmsgs,
	AS_HELP_STRING([--with-extmsgs],[Produce extended messages]),
	[case "$withval" in
	    yes)
		AC_DEFINE(USE_EXTENDED_MESSAGES)
		AC_MSG_RESULT(yes)
		;;
	    *)
		AC_MSG_RESULT(no)
		;;
	esac],[AC_MSG_RESULT(no)])

use_dash_r=no
AC_MSG_CHECKING(whether to use -R paths as well as -L)
AC_ARG_WITH(rpath,
	AS_HELP_STRING([--with-rpath],[Use -R as well as -L for libraries]),
	[case "$withval" in
	    yes|no)
		AC_MSG_RESULT($withval)
		use_dash_r=$withval
		;;
	    *)
		AC_MSG_RESULT(no)
		;;
	esac],
	[AC_MSG_RESULT(no)])

AC_MSG_CHECKING(whether we are building for a Cyclades TS)
AC_ARG_WITH(cycladests,
	AS_HELP_STRING([--with-cycladests],[(deprecated - noop) Build for a Cyclades TS]),
	[case "$withval" in
	    yes)
		AC_DEFINE(FOR_CYCLADES_TS)
		AC_MSG_RESULT(yes)
		;;
	    *)
		AC_MSG_RESULT(no)
		;;
	esac],[AC_MSG_RESULT(no)])


dnl ### Check for compiler et al. ###################################
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

dnl ### Compiler characteristics. ##################################
AC_AIX
AC_C_CONST

dnl AC_CHECK_SIZEOF(long)
dnl if test "$ac_cv_sizeof_long" -gt 4; then
dnl     if test "$with_64bit" != "yes"; then
dnl 	AC_MSG_ERROR([cannot build on >32bit systems (to override use --with-64bit)])
dnl     else
dnl 	AC_MSG_WARN([building a 64bit version of conserver - good luck!])
dnl     fi
dnl fi

dnl ### Checks for header files. ###################################
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/ioctl.h)

AC_SYS_POSIX_TERMIOS
if test "$ac_cv_sys_posix_termios" != "yes"; then
    AC_MSG_ERROR([POSIX termios interface required])
fi

AC_CHECK_HEADERS(unistd.h getopt.h sys/vlimit.h sys/resource.h ttyent.h sys/ttold.h sys/uio.h sys/ioctl_compat.h usersec.h sys/select.h stropts.h sys/audit.h shadow.h sys/time.h crypt.h sysexits.h types.h sys/sockio.h sys/param.h sys/un.h)
dnl sys/proc.h needs sys/param.h on openbsd, apparently
AC_CHECK_HEADERS(sys/proc.h, [], [],
[#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
])
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_TYPE_MODE_T
AC_TYPE_SIGNAL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T

AC_CHECK_TYPE([sig_atomic_t],,
    AC_DEFINE(sig_atomic_t, volatile int,
	[Define if <signal.h> does not define sig_atomic_t]),
    [#include <signal.h>])

AC_CHECK_TYPE([in_addr_t],[AC_DEFINE(HAVE_IN_ADDR_T,1,
	[Defined if in_addr_t exists])],,[$ac_includes_default
#include <netinet/in.h>])
AC_CHECK_TYPE([socklen_t],[AC_DEFINE(HAVE_SOCKLEN_T,1,
	[Defined if socklen_t exists])],,[$ac_includes_default
#include <sys/socket.h>])

AC_MSG_CHECKING(for sa_len in struct sockaddr)
AC_TRY_COMPILE([#include <sys/types.h>
	#include <sys/socket.h>],
	[struct sockaddr s; s.sa_len=0;],
	[AC_MSG_RESULT(yes)
	 AC_DEFINE(HAVE_SA_LEN)],
	[AC_MSG_RESULT(no)])


dnl ### Host specific checks. ######################################
AC_CANONICAL_HOST

case "$host" in
*-*-hpux*)
    CPPFLAGS="$CPPFLAGS -D_XOPEN_SOURCE_EXTENDED=1"
    AC_CHECK_LIB(xnet,t_error,,AC_MSG_ERROR([-lxnet needed on HP-UX]))
    AC_CHECK_LIB(sec,getspnam)
    AC_CHECK_HEADERS(hpsecurity.h prot.h)
    AC_CHECK_FUNCS(bigcrypt iscomsec getprpwnam)
    ;;
esac

dnl ### Check for libraries. #######################################
AC_SEARCH_LIBS(socket,socket)
AC_SEARCH_LIBS(gethostbyname,nsl)
AC_SEARCH_LIBS(crypt,crypt)

AC_SUBST(CONSLIBS)
AC_SUBST(CONSCPPFLAGS)
AC_SUBST(CONSLDFLAGS)

AC_MSG_CHECKING(whether to use Unix domain sockets)
cons_with_uds="NO"
AC_ARG_WITH(uds,
	AS_HELP_STRING([--with-uds@<:@=DIR@:>@    ],
	    [Use Unix domain sockets for client/server communication @<:@/tmp/conserver@:>@]),
	[case "$withval" in
	    yes)
		AC_DEFINE_UNQUOTED(UDSDIR, "/tmp/conserver")
		AC_DEFINE(USE_UNIX_DOMAIN_SOCKETS)
		AC_MSG_RESULT([/tmp/conserver])
		cons_with_uds="YES"
		;;
	    no)
		AC_MSG_RESULT(no)
		;;
	    *)
		AC_DEFINE_UNQUOTED(UDSDIR, "$withval")
		AC_DEFINE(USE_UNIX_DOMAIN_SOCKETS)
		AC_MSG_RESULT('$withval')
		cons_with_uds="YES"
		if expr "$withval" : '/' >/dev/null 2>&1; then
		    :
		else
		    echo "*** WARNING *** you may have better success using a fully-qualified path"
		    echo "*** WARNING *** instead of '$withval'"
		fi
		;;
	esac
	
	if test $cons_with_uds = YES; then
	    AC_MSG_CHECKING(whether to trust UDS credentials)
	    AC_ARG_WITH(trust-uds-cred,
		    AS_HELP_STRING([--with-trust-uds-cred],[Trust UDS credentials obtained via socket]),
		    [case "$withval" in
			yes)
			    AC_TRY_COMPILE([#include <sys/types.h>
				    #include <sys/socket.h>],
				    [
struct sockpeercred u;
u.uid = 0;
#if !defined(SO_PEERCRED)
#error "no SO_PEERCRED defined"
#endif
				    ],
				    [AC_MSG_RESULT(yes)
				     AC_DEFINE(UDS_CRED_STYPE, sockpeercred, [Defined to UDS credential structure name])
				     AC_DEFINE(UDS_CRED_UID, uid, [Defined to UDS credential structure uid field])
				     AC_DEFINE(UDS_CRED_SO, SO_PEERCRED, [Defined to UDS credential socket option])
				     AC_DEFINE(TRUST_UDS_CRED)],
				    [
					AC_TRY_COMPILE([#include <sys/types.h>
						#include <sys/socket.h>],
						[
struct ucred u;
u.euid = 0;
#if !defined(SO_PEERCRED)
#error "no SO_PEERCRED defined"
#endif
						],
						[AC_MSG_RESULT(yes)
						AC_DEFINE(UDS_CRED_STYPE, ucred, [Defined to UDS credential structure name])
						AC_DEFINE(UDS_CRED_UID, uid, [Defined to UDS credential structure uid field])
						AC_DEFINE(UDS_CRED_SO, SO_PEERCRED, [Defined to UDS credential socket option])
						AC_DEFINE(TRUST_UDS_CRED)],
						[
							AC_TRY_COMPILE([#include <sys/types.h>
								#include <sys/socket.h>],
								[
struct peercred_struct u;
u.euid = 0;
#if !defined(SO_PEERID)
#error "no SO_PEERID defined"
#endif
								],
								[AC_MSG_RESULT(yes)
								 AC_DEFINE(UDS_CRED_STYPE, peercred_struct, [Defined to UDS credential structure name])
								 AC_DEFINE(UDS_CRED_UID, euid, [Defined to UDS credential structure uid field])
								 AC_DEFINE(UDS_CRED_SO, SO_PEERID, [Defined to UDS credential socket option])
								 AC_DEFINE(TRUST_UDS_CRED)],
								[AC_MSG_RESULT(no)]),
						    ])
				    ])
			    ;;
			*)
			    AC_MSG_RESULT(no)
			    ;;
		    esac],[AC_MSG_RESULT(no)])
	fi
	],[AC_MSG_RESULT(no)])

cons_with_libwrap="NO"
AC_ARG_WITH(libwrap,
    AS_HELP_STRING([--with-libwrap@<:@=PATH@:>@],
	[Compile in libwrap (tcp_wrappers) support]),
    [if test "$withval" != "no"; then
	if test "$withval" != "yes"; then
	    WRAPCPPFLAGS="-I$withval/include"
	    if test "$use_dash_r" != "yes"; then
		WRAPLDFLAGS="-L$withval/lib"
	    else
		WRAPLDFLAGS="-L$withval/lib -R$withval/lib"
	    fi
	else
	    WRAPCPPFLAGS=""
	    WRAPLDFLAGS=""
	fi

	oCPPFLAGS="$CPPFLAGS"
	oLDFLAGS="$LDFLAGS"
	oLIBS="$LIBS"

	CPPFLAGS="$CPPFLAGS $WRAPCPPFLAGS"
	LDFLAGS="$LDFLAGS $WRAPLDFLAGS"

	AC_CHECK_HEADER(tcpd.h,
	    [LIBS="$LIBS -lwrap"
	    AC_MSG_CHECKING(for TCP wrappers library -lwrap)
	    AC_TRY_LINK([#include <tcpd.h>
		int allow_severity = 0;
		int deny_severity  = 0;
		],[hosts_access((void *)0)],
		[AC_MSG_RESULT(yes)
		 cons_with_libwrap="YES"
		 AC_DEFINE(USE_LIBWRAP)
		 CONSLIBS="$CONSLIBS -lwrap"
		 CONSLDFLAGS="$CONSLDFLAGS $WRAPLDFLAGS"
		 CONSCPPFLAGS="$CONSCPPFLAGS $WRAPCPPFLAGS"],
		[AC_MSG_RESULT(no)
		 LIBS="$LIBS -lnsl"
		 AC_MSG_CHECKING(for TCP wrappers library -lwrap with -lnsl)
		 AC_TRY_LINK([#include <tcpd.h>
		    int allow_severity = 0;
		    int deny_severity  = 0;
		    ],[hosts_access((void *)0)],
		    [AC_MSG_RESULT(yes)
		     cons_with_libwrap="YES"
		     AC_DEFINE(USE_LIBWRAP)
		     CONSLIBS="$CONSLIBS -lwrap -lnsl"
		     CONSLDFLAGS="$CONSLDFLAGS $WRAPLDFLAGS"
		     CONSCPPFLAGS="$CONSCPPFLAGS $WRAPCPPFLAGS"],
		    [AC_MSG_RESULT(no)])])],)
	LIBS="$oLIBS"
	CPPFLAGS="$oCPPFLAGS"
	LDFLAGS="$oLDFLAGS"
    fi]
)

cons_with_openssl="NO"
AC_ARG_WITH(openssl,
    AS_HELP_STRING([--with-openssl@<:@=PATH@:>@],
	[Compile in OpenSSL support]),
    [if test "$withval" != "no"; then
	if test "$withval" != "yes"; then
	    OPENSSLCPPFLAGS="-I$withval/include"
	    if test "$use_dash_r" != "yes"; then
		OPENSSLLDFLAGS="-L$withval/lib"
	    else
		OPENSSLLDFLAGS="-L$withval/lib -R$withval/lib"
	    fi
	else
	    OPENSSLCPPFLAGS=""
	    OPENSSLLDFLAGS=""
	fi

	oCPPFLAGS="$CPPFLAGS"
	oLDFLAGS="$LDFLAGS"
	oLIBS="$LIBS"
	have_openssl=no

	CPPFLAGS="$CPPFLAGS $OPENSSLCPPFLAGS"
	LDFLAGS="$LDFLAGS $OPENSSLLDFLAGS"

	AC_CHECK_HEADER([openssl/ssl.h],
	    [LIBS="$LIBS -lssl -lcrypto"
	    AC_MSG_CHECKING(for openssl libraries -lssl and -lcrypto)
	    AC_TRY_LINK([#include <openssl/ssl.h>
		],[SSL_CTX_new(NULL)],
		[AC_MSG_RESULT(yes)
		cons_with_openssl="YES"
		AC_DEFINE(HAVE_OPENSSL)
		have_openssl=yes],
		[AC_MSG_RESULT(no)])],)

	if test $have_openssl = no; then
	    LIBS="$oLIBS"
	    CPPFLAGS="$oCPPFLAGS"
	    LDFLAGS="$oLDFLAGS"
	fi

	AC_MSG_CHECKING(whether to require server cert)
	AC_ARG_WITH(req-server-cert,
		AS_HELP_STRING([--with-req-server-cert],[Require server SSL certificate by client]),
		[case "$withval" in
		    yes)
			AC_DEFINE(REQ_SERVER_CERT)
			AC_MSG_RESULT(yes)
			;;
		    *)
			AC_MSG_RESULT(no)
			;;
		esac],[AC_MSG_RESULT(no)])
    fi]
)

cons_with_gssapi="NO"
cons_strip_realm="NO"
AC_ARG_WITH(gssapi,
    AS_HELP_STRING([--with-gssapi@<:@=PATH@:>@],
	[Compile in GSS-API support]),
    [if test "$withval" != "no"; then
	if test "$withval" != "yes"; then
	    GSSAPICPPFLAGS="-I$withval/include"
	    if test "$use_dash_r" != "yes"; then
		GSSAPILDFLAGS="-L$withval/lib"
	    else
		GSSAPILDFLAGS="-L$withval/lib -R$withval/lib"
	    fi
	else
	    GSSAPICPPFLAGS=""
	    GSSAPILDFLAGS=""
	fi

	oCPPFLAGS="$CPPFLAGS"
	oLDFLAGS="$LDFLAGS"
	oLIBS="$LIBS"
	have_gssapi=no

	CPPFLAGS="$CPPFLAGS $GSSAPICPPFLAGS"
	LDFLAGS="$LDFLAGS $GSSAPILDFLAGS"

	AC_CHECK_HEADER([gssapi/gssapi.h],
	    [LIBS="$oLIBS -lgssapi"
	    AC_MSG_CHECKING(for gssapi library -lgssapi)
	    AC_TRY_LINK([#include <gssapi/gssapi.h>
			 #include <stdio.h>
		],[gss_create_empty_oid_set(NULL, NULL)],
		[AC_MSG_RESULT(yes)
		cons_with_gssapi="YES"
		AC_DEFINE(HAVE_GSSAPI)
		have_gssapi=yes],
		[AC_MSG_RESULT(no)
		LIBS="$oLIBS -lgssglue"
		AC_MSG_CHECKING(for gssapi library -lgssglue)
		AC_TRY_LINK([#include <gssapi/gssapi.h>
			     #include <stdio.h>
		    ],[gss_create_empty_oid_set(NULL, NULL)],
		    [AC_MSG_RESULT(yes)
		    cons_with_gssapi="YES"
		    AC_DEFINE(HAVE_GSSAPI)
		    have_gssapi=yes],
		    [AC_MSG_RESULT(no)
		    LIBS="$oLIBS -lgss"
		    AC_MSG_CHECKING(for gssapi library -lgss)
		    AC_TRY_LINK([#include <gssapi/gssapi.h>
				 #include <stdio.h>
			],[gss_create_empty_oid_set(NULL, NULL)],
			[AC_MSG_RESULT(yes)
			cons_with_gssapi="YES"
			AC_DEFINE(HAVE_GSSAPI)
			have_gssapi=yes],
			[AC_MSG_RESULT(no)])])])],)

	if test $have_gssapi = no; then
	    LIBS="$oLIBS"
	    CPPFLAGS="$oCPPFLAGS"
	    LDFLAGS="$oLDFLAGS"
	else
	    AC_MSG_CHECKING(whether to fallback to username without @REALM)
	    AC_ARG_WITH(striprealm,
		    AS_HELP_STRING([--with-striprealm],[retry username without @REALM with gss-api authentication]),
		    [case "$withval" in
			yes)
			    AC_DEFINE(STRIP_REALM)
			    AC_MSG_RESULT(yes)
			    cons_strip_realm="YES"
			    ;;
			*)
			    AC_MSG_RESULT(no)
			    ;;
		    esac],[AC_MSG_RESULT(no)])
	fi
    fi]
)

cons_with_freeipmi="NO"
AC_ARG_WITH(freeipmi,
    AS_HELP_STRING([--with-freeipmi@<:@=PATH@:>@],
	[Compile in FreeIPMI support]),
    [if test "$withval" != "no"; then
	if test "$withval" != "yes"; then
	    FREEIPMICPPFLAGS="-I$withval/include"
	    if test "$use_dash_r" != "yes"; then
		FREEIPMILDFLAGS="-L$withval/lib"
	    else
		FREEIPMILDFLAGS="-L$withval/lib -R$withval/lib"
	    fi
	else
	    FREEIPMICPPFLAGS=""
	    FREEIPMILDFLAGS=""
	fi

	oCPPFLAGS="$CPPFLAGS"
	oLDFLAGS="$LDFLAGS"
	oLIBS="$LIBS"
	have_freeipmi=no

	CPPFLAGS="$CPPFLAGS $FREEIPMICPPFLAGS"
	LDFLAGS="$LDFLAGS $FREEIPMILDFLAGS"

	AC_CHECK_HEADER([ipmiconsole.h],
	    [LIBS="$LIBS -lipmiconsole"
	    AC_MSG_CHECKING(for freeipmi libraries -lipmiconsole)
	    AC_TRY_LINK([#include <ipmiconsole.h>
		],[ipmiconsole_ctx_fd(0)],
		[AC_MSG_RESULT(yes)
		cons_with_freeipmi="YES"
		AC_DEFINE(HAVE_FREEIPMI)
		CONSLIBS="$CONSLIBS -lipmiconsole"
		have_freeipmi=yes],
		[AC_MSG_RESULT(no)])],)

	LIBS="$oLIBS"
	if test $have_freeipmi = no; then
	    CPPFLAGS="$oCPPFLAGS"
	    LDFLAGS="$oLDFLAGS"
	fi
    fi]
)

cons_with_dmalloc="NO"
AC_ARG_WITH(dmalloc,
    AS_HELP_STRING([--with-dmalloc@<:@=PATH@:>@],
	[Compile in dmalloc support]),
    [if test "$withval" != "no"; then
	if test "$withval" != "yes"; then
	    DMALLOCCPPFLAGS="-I$withval/include"
	    if test "$use_dash_r" != "yes"; then
		DMALLOCLDFLAGS="-L$withval/lib"
	    else
		DMALLOCLDFLAGS="-L$withval/lib -R$withval/lib"
	    fi
	else
	    DMALLOCCPPFLAGS=""
	    DMALLOCLDFLAGS=""
	fi

	oCPPFLAGS="$CPPFLAGS"
	oLDFLAGS="$LDFLAGS"
	oLIBS="$LIBS"
	have_dmalloc=no

	CPPFLAGS="$CPPFLAGS $DMALLOCCPPFLAGS"
	LDFLAGS="$LDFLAGS $DMALLOCLDFLAGS"

	AC_CHECK_HEADER([dmalloc.h],
	    [LIBS="$LIBS -ldmalloc"
	    AC_MSG_CHECKING(for dmalloc libraries -ldmalloc)
	    AC_TRY_LINK([#include <dmalloc.h>
		],[dmalloc_debug(0)],
		[AC_MSG_RESULT(yes)
		cons_with_dmalloc="YES"
		AC_DEFINE(HAVE_DMALLOC)
		have_dmalloc=yes],
		[AC_MSG_RESULT(no)])],)

	if test $have_dmalloc = no; then
	    LIBS="$oLIBS"
	    CPPFLAGS="$oCPPFLAGS"
	    LDFLAGS="$oLDFLAGS"
	fi
    fi]
)


dnl ### Check for needed functions. ################################

dnl dnl The following basically stollen from the less-358 distribution, but
dnl dnl modified for my own purposes
dnl AC_MSG_CHECKING(for POSIX regex)
dnl AC_ARG_WITH(regex,
dnl     AC_HELP_STRING([--with-regex],
dnl 	[Use regular expressions in conserver.passwd]),
dnl 	[if test "$withval" = yes; then
dnl 	    AC_TRY_RUN([
dnl 		#include <sys/types.h>
dnl 		#include <regex.h>
dnl 		main() { regex_t r; regmatch_t rm; char *text = "xabcy";
dnl 		if (regcomp(&r, "abc", 0)) exit(1);
dnl 		if (regexec(&r, text, 1, &rm, 0)) exit(1);
dnl 		if (rm.rm_so != 1) exit(1); /* check for correct offset */
dnl 		exit(0); }
dnl 	    ],have_posix_regex=yes,have_posix_regex=no,have_posix_regex=unknown)
dnl 	    if test $have_posix_regex = yes; then
dnl 	      AC_MSG_RESULT(yes)
dnl 	      AC_DEFINE(HAVE_POSIX_REGCOMP)
dnl 	    elif test $have_posix_regex = unknown; then
dnl 		AC_TRY_LINK([
dnl 		    #include <sys/types.h>
dnl 		    #include <regex.h>],
dnl 		[regex_t *r; regfree(r);],
dnl 		AC_MSG_RESULT(yes)
dnl 		AC_DEFINE(HAVE_POSIX_REGCOMP))
dnl 	    else
dnl 	      AC_MSG_RESULT(no)
dnl 	    fi
dnl 	else
dnl 	    AC_MSG_RESULT(no)
dnl 	fi],[AC_MSG_RESULT(no)])

cons_with_pam="NO"
AC_MSG_CHECKING(for PAM support)
AC_ARG_WITH(pam,
    AS_HELP_STRING([--with-pam],
	[Enable PAM support]),
	[if test "$withval" = yes; then
	    oLIBS="$LIBS"

	    AC_CHECK_HEADER(security/pam_appl.h,
		[LIBS="$LIBS -lpam"
		AC_MSG_CHECKING(for PAM library -lpam)
		AC_TRY_LINK_FUNC([pam_start],
		    [AC_MSG_RESULT(yes)
		    cons_with_pam="YES"
		    AC_DEFINE(HAVE_PAM)
		    CONSLIBS="$CONSLIBS -lpam"],
		    [LIBS="$LIBS -ldl"
		    AC_MSG_RESULT(no)
		    AC_MSG_CHECKING(for PAM library -lpam with -ldl)
		    AC_TRY_LINK_FUNC([pam_end],
			[AC_MSG_RESULT(yes)
			cons_with_pam="YES"
			AC_DEFINE(HAVE_PAM)
			CONSLIBS="$CONSLIBS -lpam -ldl"],
			[AC_MSG_RESULT(no)])])],)

	    LIBS="$oLIBS"
	else
	    AC_MSG_RESULT(no)
	fi],[AC_MSG_RESULT(no)])

cons_with_ipv6="NO"
AC_MSG_CHECKING(whether to support IPv6)
AC_ARG_WITH(ipv6,
	AS_HELP_STRING([--with-ipv6],
	    [(experimental) Use IPv6 for client/server communication]),
	[case "$withval" in
	    yes)
		AC_DEFINE(USE_IPV6)
		AC_MSG_RESULT(yes)
		cons_with_ipv6="YES"
		;;
	    *)
		AC_MSG_RESULT(no)
		;;
	esac],[AC_MSG_RESULT(no)])


dnl Checks for pty allocation...
dnl According to the xemacs distribution:
dnl   getpt()  is the preferred pty allocation method on glibc systems.
dnl   _getpty() is the preferred pty allocation method on SGI systems.
dnl   grantpt(), unlockpt(), ptsname() are defined by Unix98.
dnl   openpty() is the preferred pty allocation method on BSD and Tru64 systems.
dnl   openpty() might be declared in:
dnl   - pty.h (Tru64 or Linux)
dnl   - libutil.h (FreeBSD)
dnl   - util.h (NetBSD)
dnl Conserver doesn't support getpt() or _getpt() yet.
AC_CHECK_HEADERS(pty.h libutil.h util.h)
AC_CHECK_LIB(util, openpty)
AC_CHECK_FUNCS(openpty)

AC_CHECK_FUNCS(getopt strerror getrlimit getsid setsid getuserattr setgroups tcgetpgrp tcsetpgrp tcgetattr tcsetattr tcsendbreak setpgrp getutent setttyent getspnam setlinebuf setvbuf ptsname grantpt unlockpt sigaction setsockopt getdtablesize putenv memset memcpy memcmp memmove sysconf getlogin inet_aton setproctitle gettimeofday strlcpy closefrom)
AC_CHECK_FUNC(strcasecmp,
	[AC_DEFINE(HAVE_STRCASECMP, 1, [Define if strcasecmp is available])],
	[AC_CHECK_FUNC(stricmp,
		[AC_DEFINE(HAVE_STRICMP, 1, [Define if stricmp is available])],
		[AC_MSG_ERROR([strcasecmp or stricmp must be available])])])

dnl    Checks for libbsm functions
AC_CHECK_HEADERS(bsm/audit.h)
AC_CHECK_LIB(bsm, getaudit)
AC_CHECK_FUNCS(getaudit getaudit_addr)


dnl ### Create output files. #######################################
AC_CONFIG_FILES([Makefile conserver/Makefile conserver.cf/Makefile console/Makefile autologin/Makefile contrib/chat/Makefile])
AC_CONFIG_FILES([conserver/conserver.rc], [chmod +x conserver/conserver.rc])
AC_CONFIG_FILES([conserver.cf/conserver.cf.man conserver.cf/conserver.passwd.man conserver/conserver.man console/console.man])
AC_OUTPUT

[
echo "=============================================================="
echo "                      Feature Summary"
echo ""
echo "  Unix domain sockets (--with-uds)       : $cons_with_uds"
echo "         TCP wrappers (--with-libwrap)   : $cons_with_libwrap"
echo "              OpenSSL (--with-openssl)   : $cons_with_openssl"
echo "              GSS-API (--with-gssapi)    : $cons_with_gssapi"
echo "             FreeIPMI (--with-freeipmi)  : $cons_with_freeipmi"
if [ $cons_with_gssapi = "YES" ]; then
echo "         strip @REALM (--with-striprealm): $cons_strip_realm"
fi
echo "              dmalloc (--with-dmalloc)   : $cons_with_dmalloc"
echo "          PAM support (--with-pam)       : $cons_with_pam"
echo "         IPv6 support (--with-ipv6)      : $cons_with_ipv6"
echo ""
echo "=============================================================="
]
