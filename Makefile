# $OpenLDAP$

# You may want to edit the following line if you chose a different --prefix when
# using ./configure for OpenLDAP itself

# If you want to enable debugging, uncomment the following line, recompile and reinstall
# WARNING: This will log all passwords in plaintext!
#DEFS = -DSLAPD_BCRYPT_DEBUG


LDAP_SRC = ../../../..
LDAP_BUILD = $(LDAP_SRC)
LDAP_INC = -I$(LDAP_BUILD)/include -I$(LDAP_SRC)/include -I$(LDAP_SRC)/servers/slapd
LDAP_LIB = $(LDAP_BUILD)/libraries/libldap/libldap.la \
	$(LDAP_BUILD)/libraries/liblber/liblber.la

PLAT = UNIX
LIBTOOL = $(LDAP_BUILD)/libtool
UNIX_LDFLAGS = -version-info $(LTVER)
CC = gcc
OPT = -g -O2 -Wall -fomit-frame-pointer -funroll-loops
DEFS =
INCS = $(LDAP_INC)
LIBS = $(LDAP_LIB)
LD_FLAGS = $(LDFLAGS) $($(PLAT)_LDFLAGS) -rpath $(moduledir) -module

PROGRAMS = bcrypt_plugin.la
LTVER = 0:0:0

prefix=/usr/local
exec_prefix=$(prefix)
ldap_subdir=/openldap

libdir=$(exec_prefix)/lib
libexecdir=$(exec_prefix)/libexec
moduledir = $(libexecdir)$(ldap_subdir)

.SUFFIXES: .c .o .lo

.c.lo:
	$(LIBTOOL) --mode=compile $(CC) $(OPT) $(DEFS) $(INCS) -c $<

all: $(PROGRAMS)

bcrypt_plugin.la:  bcrypt_plugin.lo crypt_blowfish.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) $(LD_FLAGS) -o $@ $? $(LIBS)

clean:
	rm -rf  *.o *.lo *.loT *.la .libs core test

install:	$(PROGRAMS)
	mkdir -p $(DESTDIR)$(moduledir)
	for p in $(PROGRAMS) ; do \
		$(LIBTOOL) --mode=install cp $$p $(DESTDIR)$(moduledir) ; \
	done

