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
