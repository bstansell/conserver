#	$Id: Makefile,v 1.5 1999-01-25 15:10:05-08 bryan Exp $
#
#	Master Makefile
#

SUBDIRS=conserver console conserver.cf

all clean install install.man: FRC
	@if [ -f .settings ]; then \
    	    s=`cat .settings | grep -v '^#'`; \
	    settings=`echo $$s`; \
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
