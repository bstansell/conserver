# Makefile for System V package

PKGNAME = conserver

# where to put package
PKGSPOOLDIR = /var/spool/pkg

# where package's files ultimately go (when package is installed)
PKGROOT = /opt

# temporary directory used while building package
INSTALLROOT = /tmp/conserverinstallroot

BUILDDIR = ../..

# temporary install directories
BINDIR   = $(INSTALLROOT)/bin
LIBDIR   = $(INSTALLROOT)/lib
MAN1MDIR = $(INSTALLROOT)/share/man/man1m
MAN4DIR  = $(INSTALLROOT)/share/man/man4
MAN1MEXT = 1m
MAN4EXT  = 4

# command to correct section numbers and file names in manual pages
FIXMANCMD = sed -e '/^\.TH/s/8/1m/' -e 's/([18]L)/(1m)/g' -e 's/(5L)/(4)/g' -e 's|/etc/|/etc/opt/conserver/|' -e 's|/usr/local/lib/|/etc/opt/conserver/|'

# command to change program location in script
FIXSCRIPTCMD = sed -e 's!/usr/local!$(PKGROOT)!'

package: pkginfo prototype fakeinstall
	test -d $(PKGSPOOLDIR) || mkdir $(PKGSPOOLDIR)
	pkgmk -d $(PKGSPOOLDIR) -o -a `uname -p` -r $(INSTALLROOT)
	$(RM) -r $(INSTALLROOT)

fakeinstall:
	mkdir -p $(BINDIR) $(LIBDIR) $(MAN1MDIR) $(MAN4DIR)
	/usr/ucb/install -cs $(BUILDDIR)/conserver/conserver $(BINDIR)/conserver
	/usr/ucb/install -cs $(BUILDDIR)/console/console $(BINDIR)/console
	$(FIXMANCMD) man_tbl_header $(BUILDDIR)/conserver/conserver.man > $(MAN1MDIR)/conserver.$(MAN1MEXT)
	$(FIXMANCMD) man_tbl_header $(BUILDDIR)/console/console.man > $(MAN1MDIR)/console.$(MAN1MEXT)
	$(FIXMANCMD) $(BUILDDIR)/conserver.cf/conserver.cf.man > $(MAN4DIR)/conserver.cf.$(MAN4EXT)
	$(FIXMANCMD) $(BUILDDIR)/conserver.cf/conserver.passwd.man > $(MAN4DIR)/conserver.passwd.$(MAN4EXT)
	$(FIXSCRIPTCMD) $(BUILDDIR)/conserver/conserver.rc > $(LIBDIR)/conserver.rc
