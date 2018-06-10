AM_CPPFLAGS = \
	-DCLIENTCONFIGFILE=\"$(CLIENTCONFIGFILE)\" \
	-DCONFIGFILE=\"$(CONFIGFILE)\" \
	-DLOGFILEPATH=\"$(LOGFILEPATH)\" \
	-DPASSWDFILE=\"$(PASSWDFILE)\" \
	-DPIDFILE=\"$(PIDFILE)\" \
	-include config.h \
	-I$(top_srcdir)/conserver \
	$(FREEIPMI_CFLAGS) \
	$(GSSAPI_CFLAGS) \
	$(JSON_CFLAGS) \
	$(OPENSSL_CFLAGS)

EXTRA_DIST = \
	CHANGES \
	FAQ \
	INSTALL \
	LICENSE \
	LICENSES \
	PROTOCOL \
	README \
	TODO \
	compat.h

dist_man_MANS =
bin_PROGRAMS =
usrsbin_exec_PROGRAMS =
dist_doc_DATA =
PATHFILES =

if BUILD_AUTOLOGIN
include autologin/Makemodule.am
endif
include conserver.cf/Makemodule.am
include conserver/Makemodule.am
include console/Makemodule.am
include contrib/Makemodule.am
include test/Makemodule.am

dist-hook:
	$(AM_V_GEN)echo $(VERSION) > $(distdir)/.tarball-version

edit_cmd = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@CONFIGFILE[@]|$(CONFIGFILE)|g' \
	-e 's|@DEFPORT[@]|$(DEFPORT)|g' \
	-e 's|@LOGFILEPATH[@]|$(LOGFILEPATH)|g' \
	-e 's|@PASSWDFILE[@]|$(PASSWDFILE)|g' \
	-e 's|@PIDFILE[@]|$(PIDFILE)|g' \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@UDSDIR[@]|$(UDSDIR)|g' \
	-e 's|@VERSION[@]|$(VERSION)|g'

$(PATHFILES): Makefile
	@ rm -f $@ $@.tmp
	$(AM_V_at) $(MKDIR_P) $$(dirname $@)
	$(AM_V_GEN) srcdir=''; \
		test -f ./$@.in || srcdir=$(srcdir)/; \
		$(edit_cmd) $${srcdir}$@.in >$@.tmp
	@ mv $@.tmp $@

CLEANFILES = $(PATHFILES)
EXTRA_DIST += $(PATHFILES:=.in)
