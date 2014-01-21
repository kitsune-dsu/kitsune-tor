TESTS = test

noinst_PROGRAMS =  tor.ktt

bin_PROGRAMS = tor.so tor-update.so
noinst_LIBRARIES = libtor.a

if BUILD_NT_SERVICES
tor_platform_source=ntmain.c
else
tor_platform_source=
endif

EXTRA_DIST=ntmain.c

# Kitsune
@kitsune_make@
DSU_SLIB = $(KITSUNE_LIB) -lkitsune

CC = $(KITSUNE_BIN)ktcc
SAVETYPES_FLAGS = --typesfile-out=$*.ktt
EKCC_FLAGS = --keepunused --doglobalreg  --automigrate --doktsavetypes $(SAVETYPES_FLAGS) --save-temps
EKJOIN = $(KITSUNE_BIN)kttjoin
EKGEN = $(KITSUNE_BIN)xfgen

CFLAGS=				#DSU change
AM_CFLAGS = -O0 -ggdb3 		#DSU change

GENERATED_XFORM=dsu.c		#DSU change
USER_XFORM=tor.xf		#DSU change
PREVEKT=tor.ktt

tor_SOURCES = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dirvote.c \
	dns.c dnsserv.c geoip.c hibernate.c main.c $(tor_platform_source) \
	networkstatus.c onion.c policies.c \
	reasons.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	eventdns.c dynamicupdate.c \
	tor_main.c

AM_CPPFLAGS = -DSHARE_DATADIR="\"$(datadir)\"" \
        -DLOCALSTATEDIR="\"$(localstatedir)\"" \
        -DBINDIR="\"$(bindir)\"" \
	$(KITSUNE_INCLUDE) -include kitsune.h

# -L flags need to go in LDFLAGS. -l flags need to go in LDADD.
# This seems to matter nowhere but on windows, but I assure you that it
# matters a lot there, and is quite hard to debug if you forget to do it.

tor_CPPFLAGS= -DKITSUNE_VERSION=9 $(AM_CPPFLAGS)
tor_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ @TOR_LDFLAGS_libevent@
tor_LDADD = ../common/libor.a ../common/libor-crypto.a $(DSU_SLIB) \
  -lz @TOR_LIBEVENT_LIBS@ @TOR_OPENSSL_LIBS@ @TOR_LIB_WS32@ @TOR_LIB_GDI@

tor_CPPFLAGS= -DKITSUNE_VERSION=9 $(AM_CPPFLAGS)
tor_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ @TOR_LDFLAGS_libevent@ 
tor_LDADD = ../common/libor.a ../common/libor-crypto.a $(DSU_SLIB) \
  -lz -levent -lssl -lcrypto @TOR_LIB_WS32@ @TOR_LIB_GDI@  # DSU change


tor_so_SOURCES = $(GENERATED_XFORM) tor_main.c
libtor_a_SOURCES = buffers.c circuitbuild.c circuitlist.c \
       circuituse.c command.c config.c \
       connection.c connection_edge.c connection_or.c control.c \
       cpuworker.c directory.c dirserv.c dirvote.c \
       dns.c dnsserv.c geoip.c hibernate.c main.c $(tor_platform_source) \
       networkstatus.c onion.c policies.c \
       reasons.c relay.c rendcommon.c rendclient.c rendmid.c \
       rendservice.c rephist.c router.c routerlist.c routerparse.c \
       eventdns.c

tor_so_CPPFLAGS = -DKITSUNE_VERSION=0 $(AM_CPPFLAGS)
libtor_so_CPPFLAGS = $(tor_so_CPPFLAGS)
tor_so_CFLAGS = -fPIC $(AM_CFLAGS)
libtor_a_CFLAGS = $(EKCC_FLAGS) $(tor_so_CFLAGS)
tor_so_LDFLAGS = -shared @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ @TOR_LDFLAGS_libevent@ 
tor_so_LDADD = ./libtor.a ../common/libor.a ../common/libor-crypto.a  \
	$(DSU_SLIB) \
  -lz -levent -lssl -lcrypto @TOR_LIB_WS32@ @TOR_LIB_GDI@  # DSU change

tor-update.so: tor.so
	cp tor.so tor-update.so

or.ktt: libtor.a 
	$(EKJOIN) $@ libtor_a-*.ktt

tor.ktt: or.ktt ../common/common.ktt
	$(EKJOIN) $@ $^

$(GENERATED_XFORM): tor.ktt $(USER_XFORM)
	$(EKGEN) $@ $(PREVEKT) tor.ktt $(USER_XFORM)

clean-local:
	test -z dsu.c || rm -f dsu.c
	text -z or.ktt || rm -f or.ktt
	test -z tor.ktt || rm -f tor.ktt
	rm *.ktt || true
	test -z tor-update.so || rm -f tor-update.so

test_SOURCES = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dirvote.c \
	dns.c dnsserv.c geoip.c hibernate.c main.c $(tor_platform_source) \
	networkstatus.c onion.c policies.c \
	reasons.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	eventdns.c dsu.c \
	test_data.c test.c

test_CPPFLAGS= -DKITSUNE_VERSION=9 $(AM_CPPFLAGS)
test_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ \
        @TOR_LDFLAGS_libevent@
test_LDADD = ../common/libor.a ../common/libor-crypto.a $(DSU_SLIB) \
        -lz @TOR_LIBEVENT_LIBS@ @TOR_OPENSSL_LIBS@ @TOR_LIB_WS32@ @TOR_LIB_GDI@

noinst_HEADERS = or.h eventdns.h eventdns_tor.h micro-revision.i

tor_main.o: micro-revision.i

micro-revision.i: FORCE
	@svkdir=$$SVKROOT; 					\
	if test "x$$svkdir" = x ; then 				\
	  svkdir=$$HOME/.svk; 					\
	fi; 							\
	if test -d ../../.git && test -x "`which git 2>&1;true`" ; then \
	  if test -d ../../.git/svn && test -x "`which git-svn 2>&1;true`" ; then \
	    git-svn info ../../README | 			\
	    sed -n 's/^Revision: \([0-9][0-9]*\).*/"\1"/p'      \
	                                   > micro-revision.tmp \
	        || true; 					\
	  fi; 							\
	elif test -d ../../.svn && test -x "`which svn 2>&1;true`" ; then \
	  svn info ../.. |					\
	  sed -n 's/^Revision: \([0-9][0-9]*\).*/"\1"/p' > micro-revision.tmp \
	     || true;						\
	elif test -x "`which svk 2>&1;true`" && test -d $$svkdir/local; then \
	  location=../..;					\
	  rev=x;						\
	  while test x$$rev = xx; do				\
	    x=`svk info $$location |				\
	      sed -n 's/^Mirrored From:.*, Rev\. \([0-9][0-9]*\)/\1/p'`; \
	    if test x$$x != x; then				\
	      rev=$$x;						\
	      break;						\
	    else						\
	      loc=`svk info $$location |			\
		sed -n 's/^Copied From: \(.*\), Rev\. [0-9][0-9]*/\1/p' | \
	        head -1`;					\
	      if test x$$loc = x; then				\
		break;						\
	      else						\
		location=/$$loc;				\
	      fi;						\
	    fi;							\
	  done;							\
	  if test x$$rev != xx; then				\
	    echo \"$$rev\" > micro-revision.tmp;		\
	  fi;							\
	fi;							\
	if test ! -f micro-revision.tmp ; then			\
	  if test ! -f micro-revision.i ; then			\
	    echo '""' > micro-revision.i;			\
	  fi;							\
	elif test ! -f micro-revision.i ||			\
	  test x"`cat micro-revision.tmp`" != x"`cat micro-revision.i`"; then \
	  mv micro-revision.tmp micro-revision.i;		\
	fi; true

#Dummy target to ensure that micro-revision.i _always_ gets built.
FORCE:
