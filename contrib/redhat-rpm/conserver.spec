#
# rpm spec file for conserver, but I don't think it'll work on any
# platform that doesn't have red hat rpm >= 4.0.2 installed.
#

%define pkg  conserver
%define ver  8.1.17

# define the name of the machine on which the main conserver
# daemon will be running if you don't want to use the default
# hostname (console)
%define master console

# what red hat (or other distibution) version are you running?
%define distver 1

# compile arguments. defaults to 0
# example: rpmbuild -bb conserver.spec --with openssl
%define with_openssl %{?_with_openssl: 1} %{?!_with_openssl: 0}
%define with_libwrap %{?_with_libwrap: 1} %{?!_with_libwrap: 0}
%define with_pam     %{?_with_pam:     1} %{?!_with_pam:     0}
%define with_dmalloc %{?_with_dmalloc: 1} %{?!_with_dmalloc: 0}

# additionally you can use macros logfile pidfile
# example: rpmbuild -bb conserver.spec --define "pidfile /var/run/conserver/pid"

Summary: Serial console server daemon/client
Name: %{pkg}
Version: %{ver}
Release: %{distver}
License: BSD
Group: System Environment/Daemons
URL: http://www.conserver.com/
Source: http://www.conserver.com/%{pkg}-%{ver}.tar.gz
BuildRoot: %{_tmppath}/%{pkg}-buildroot
%if %{with_openssl}
BuildRequires: openssl-devel
%endif
%if %{with_pam}
BuildRequires: pam-devel
%endif
%if %{with_libwrap}
Requires: tcp_wrappers
%endif
%if %{with_dmalloc}
Requires: dmalloc
BuildRequires: dmalloc
%endif
Prefix: %{_prefix}


%description
Conserver is an application that allows multiple users to watch a
serial console at the same time.  It can log the data, allows users to
take write-access of a console (one at a time), and has a variety of
bells and whistles to accentuate that basic functionality.


%prep
%{__rm} -rf %{buildroot}
%setup -q


%build
# we don't want to install the solaris conserver.rc file
f="conserver/Makefile.in"
%{__mv} $f $f.orig
%{__sed} -e 's/^.*conserver\.rc.*$//' < $f.orig > $f

%configure %{?_with_openssl} %{?_with_libwrap} %{?_with_dmalloc} %{?_with_pam} %{?logfile: --with-logfile=%{logfile}} %{?pidfile: --with-pidfile=%{pidfile}} %{?master: --with-master=%{master}}

make


%install
%{makeinstall}

# put commented copies of the sample configure files in the
# system configuration directory
%{__mkdir_p} %{buildroot}/%{_sysconfdir}
%{__sed} -e 's/^/#/' \
  < conserver.cf/conserver.cf \
  > %{buildroot}/%{_sysconfdir}/conserver.cf
%{__sed} -e 's/^/#/' \
  < conserver.cf/conserver.passwd \
  > %{buildroot}/%{_sysconfdir}/conserver.passwd

# install copy of init script
%{__mkdir_p} %{buildroot}/%{_initrddir}
%{__cp} contrib/redhat-rpm/conserver.init %{buildroot}/%{_initrddir}/conserver

# install copy of init script defaults
%{__mkdir_p} %{buildroot}/%{_sysconfdir}/default
%{__cp} contrib/redhat-rpm/conserver.defaults %{buildroot}/%{_sysconfdir}/default/conserver

%clean
%{__rm} -rf %{buildroot}


%post
if [ -x %{_initrddir}/conserver ]; then
  /sbin/chkconfig --add conserver
fi
# make sure /etc/services has a conserver entry
if ! egrep '\<conserver\>' /etc/services > /dev/null 2>&1 ; then
  echo "console		782/tcp		conserver" >> /etc/services
fi


%preun
if [ "$1" = 0 ]; then
  if [ -x %{_initrddir}/conserver ]; then
    %{_initrddir}/conserver stop
    /sbin/chkconfig --del conserver
  fi
fi


%files
%defattr(-,root,root)
%doc CHANGES FAQ INSTALL README conserver.cf
%config(noreplace) %{_sysconfdir}/conserver.cf
%config(noreplace) %{_sysconfdir}/conserver.passwd
%config(noreplace) %{_sysconfdir}/default/conserver
%attr(555,root,root) %{_initrddir}/conserver
%{_bindir}/console
%{_libdir}/conserver/convert
%{_mandir}/man1/console.1.gz
%{_mandir}/man8/conserver.8.gz
%{_mandir}/man5/conserver.cf.5.gz
%{_mandir}/man5/conserver.passwd.5.gz
%{_datadir}/examples/conserver/conserver.cf
%{_datadir}/examples/conserver/conserver.passwd
%{_sbindir}/conserver

%changelog
* Wed Sep 25 2009 Fabien Wernli
  - added configure prerequisites
* Thu Sep 24 2009 Fabien Wernli
  - added prefix to configure
  - changed some hardcoded values to proper macros:
    didn't work on x64 lib -> lib64

