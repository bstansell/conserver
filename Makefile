#	$Id: Makefile,v 1.6 1999-02-01 15:42:42-08 bryan Exp $
#
#	Master Makefile
#

SUBDIRS=conserver console conserver.cf

all clean install install.man: FRC
	@if [ -f .settings ]; then \
    	    s=`cat .settings | grep -v '^#'`; \
	    settings=`echo $$s`; \
	    if [ -n "${PREFIX}" ]; then settings="'PREFIX=${PREFIX}' $$settings"; fi; \
	    for s in ${SUBDIRS}; do \
		( cd $$s; eval ${MAKE} $$settings $@ ) \
	    done; \
	else \
	    echo "Please run 'make config' to set up platform type"; \
	    exit; \
	fi

config:
	@p=`port/system 2>/dev/null`; \
	if [ -n "$$p" ]; then \
	    rm -f .settings; \
	    ln -s port/$$p .settings; \
	    echo "Configured for $$p"; \
	else \
	    echo "*** Can't determine system type."; \
	    echo "*** See ./port for porting issues."; \
	fi

FRC:

SHELL=/bin/sh
