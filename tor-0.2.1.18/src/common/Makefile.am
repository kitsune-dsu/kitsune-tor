
noinst_LIBRARIES = libor.a libor-crypto.a 
noinst_PROGRAMS = common.ktt

#CFLAGS  = -Wall -Wpointer-arith -O2
# Kitsune
@kitsune_make@
DSU_SLIB = $(KITSUNE_LIB) -lkitsune
EKJOIN = $(KITSUNE_BIN)kttjoin

CC = $(KITSUNE_BIN)ktcc
EKCC_FLAGS = --keepunused --doglobalreg  --automigrate --doktsavetypes --typesfile-out=$*.ktt --save-temps 

CFLAGS=				#DSU change
AM_CFLAGS =  -include kitsune.h $(EKCC_FLAGS) $(KITSUNE_INCLUDE) -fPIC -O0 -ggdb3 #DSU change

if USE_OPENBSD_MALLOC
libor_extra_source=OpenBSD_malloc_Linux.c
else
libor_extra_source=
endif

libor_a_SOURCES = address.c log.c util.c compat.c container.c mempool.c \
	memarea.c $(libor_extra_source)
libor_crypto_a_SOURCES = crypto.c aes.c tortls.c torgzip.c

noinst_HEADERS = address.h log.h crypto.h test.h util.h compat.h aes.h torint.h tortls.h strlcpy.c strlcat.c torgzip.h container.h ht.h mempool.h memarea.h ciphers.inc

common.ktt: libor.a libor-crypto.a
	$(EKJOIN) $@ *.ktt

clean-local:
	rm *.ktt
