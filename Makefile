#	$Id: Makefile,v 1.8 2000-03-06 18:08:31-08 bryan Exp $
#
#	Master Makefile
#

SUBDIRS=conserver console conserver.cf

all clean install install.man: FRC
	@if [ ! -f .settings ]; then \
	    echo "Running a 'make config' for you"; \
	    ${MAKE} config; \
	fi
	@if [ -f .settings ]; then \
    	    s=`cat .settings | grep -v '^#'`; \
	    settings=`echo $$s`; \
	    if [ -n "${PREFIX}" ]; then settings="'PREFIX=${PREFIX}' $$settings"; fi; \
	    for s in ${SUBDIRS}; do \
		( cd $$s; eval ${MAKE} $$settings $@ ) \
	    done; \
	else \
	    echo; \
	    echo "There is a problem with your platform type.  Try running"; \
	    echo "'make config' and look into the errors"; \
	    echo; \
	    exit; \
	fi
	@if [ "$@" = "clean" ]; then rm .settings; fi

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
