#
# rpm spec file for conserver, but I don't think it'll work on any
# platform that doesn't have red hat rpm >= 4.0.2 installed.
#

%define pkg  conserver
%define ver  8.1.8

# define the name of the machine on which the main conserver
# daemon will be running if you don't want to use the default
# hostname (console)
%define master console

# what red hat (or other distibution) version are you running?
%define distver 6

Summary: Serial console server daemon/client
Name: %{pkg}
Version: %{ver}
Release: 1.%{distver}
Copyright: distributable
Group: System Environment/Daemons
URL: http://www.conserver.com/
Source: http://www.conserver.com/%{pkg}-%{ver}.tar.gz
BuildRoot: %{_tmppath}/%{pkg}-buildroot
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

%configure --with-master=%{master}
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
%attr(555,root,root) %{_initrddir}/conserver
%{prefix}/bin/console
%{prefix}/share/man/man1/console.1.gz
%{prefix}/share/man/man8/conserver.8.gz
%{prefix}/share/man/man5/conserver.cf.5.gz
%{prefix}/share/man/man5/conserver.passwd.5.gz
%{prefix}/share/examples/conserver/conserver.cf
%{prefix}/share/examples/conserver/conserver.passwd
%{prefix}/sbin/conserver
