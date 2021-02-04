default-target: all
default-target: .PHONY
.PHONY:


# Parameters
#
DESTDIR =

prefix = /usr/local

libexecdir = $(prefix)/libexec

INSTALL = install
INSTALL_DIR = $(INSTALL) -d
INSTALL_PROGRAM = $(INSTALL)


# Public targets
all: .PHONY
all: age-plugin-fido
all: check

clean: .PHONY
check: .PHONY
test: .PHONY check
install: .PHONY


# Installation targets
#
install: install-libexec
install-libexec: .PHONY
	$(INSTALL_DIR) $(DESTDIR)$(libexecdir)
	$(INSTALL_PROGRAM) age-plugin-fido $(DESTDIR)$(libexecdir)/


# Suffix rules
#
.c.o:
	$(CC) $(_CFLAGS) $(_CPPFLAGS) -c $<

_CFLAGS = -g -Og -Wall -Wextra -Werror -std=c99 $(CFLAGS)
_CPPFLAGS = -MD -MF $@.d -D_POSIX_C_SOURCE=200809L -I. $(CPPFLAGS)


# age-plugin-fido
#
SRCS = \
	b64dec.c \
	b64write.c \
	bech32.c \
	dae.c \
	freadline.c \
	main.c \
	progname.c \
	reallocn.c \
	strprefix.c \
	# end of SRCS_age-plugin-fido
DEPS = $(SRCS:.c=.o.d)
-include $(DEPS)

age-plugin-fido: $(SRCS:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS:.c=.o) \
		-lfido2 -lcrypto

clean: clean-age-plugin-fido
clean-age-plugin-fido: .PHONY
	-rm -f $(SRCS:.c=.o)
	-rm -f $(SRCS:.c=.o.d)
	-rm -f age-plugin-fido


# Tests
#
check: check-bech32
check-bech32: .PHONY
check-bech32: t_bech32.exp t_bech32.out
	diff -u t_bech32.exp t_bech32.out

t_bech32.out: t_bech32
	./t_bech32 > $@.tmp && mv -f $@.tmp $@

SRCS_t_bech32 = \
	bech32.c \
	t_bech32.c \
	# end of SRCS_t_bech32
DEPS_t_bech32 = $(SRCS_t_bech32:.c=.o.d)
-include $(DEPS_t_bech32)

t_bech32: $(SRCS_t_bech32:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_bech32:.c=.o)

clean: clean-bech32
clean-bech32: .PHONY
	-rm -f $(SRCS_t_bech32:.c=.o)
	-rm -f $(SRCS_t_bech32:.c=.o.d)
	-rm -f t_bech32
	-rm -f t_bech32.out
	-rm -f t_bech32.out.tmp


check: check-dae
check-dae: .PHONY
check-dae: t_dae.exp t_dae.out
	diff -u t_dae.exp t_dae.out

t_dae.out: t_dae
	./t_dae > $@.tmp && mv -f $@.tmp $@

SRCS_t_dae = \
	dae.c \
	t_dae.c \
	# end of SRCS_t_dae
DEPS_t_dae = $(SRCS_t_dae:.c=.o.d)
-include $(DEPS_t_dae)

t_dae: $(SRCS_t_dae:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_dae:.c=.o) -lcrypto

clean: clean-dae
clean-dae: .PHONY
	-rm -f $(SRCS_t_dae:.c=.o)
	-rm -f $(SRCS_t_dae:.c=.o.d)
	-rm -f t_dae
	-rm -f t_dae.out
	-rm -f t_dae.out.tmp
