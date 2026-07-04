# librig.so build for the EXP-1 runner (Item 2).
# Compiles the canonical rig, l0 dependencies, and h_scorer with -fPIC
# into one shared object for ctypes. No source is modified; the shim
# is a packaging step, not a fork. axilog substrate objects are built
# from axioma-spec source so axilog_commit is exported for the chain
# cross-check.
#
# Usage: make L0=~/axilog/axioma-l0 SPEC=~/axilog/axioma-spec

L0   ?= ../../axioma/axioma-l0
SPEC ?= ../../axioma/axioma-spec

CC      = gcc
CSTD    = -std=c99
WARN    = -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion \
          -Wstrict-prototypes -Wno-sign-conversion
DETFLAG = -fno-strict-aliasing -fwrapv -fno-tree-vectorize -fno-builtin \
          -fno-omit-frame-pointer -fstack-protector-strong -ffp-contract=off
CFLAGS  = $(CSTD) $(WARN) $(DETFLAG) -O2 -fPIC \
          -I$(L0)/include -I$(L0)/exp1/include -I$(L0)/harness/include \
          -I$(SPEC)/include

L0_SRC   = l0_pcg.c l0_canon.c l0_ledger.c l0_session.c l0_nfc.c \
           l0_admit.c l0_boundary.c l0_channel.c l0_fingerprint.c \
           l0_project.c l0_schema.c
X_SRC    = x_schedule.c x_template.c x_rig.c x_redact.c x_demarc.c \
           x_instantiate.c x_serve.c x_e2.c
H_SRC    = h_scorer.c
SPEC_SRC = axilog_sha256.c

OBJDIR = obj
OBJS   = $(addprefix $(OBJDIR)/,$(L0_SRC:.c=.o) $(X_SRC:.c=.o) \
         $(H_SRC:.c=.o) $(SPEC_SRC:.c=.o))

librig.so: $(OBJS)
	$(CC) -shared -o $@ $(OBJS) -lm

$(OBJDIR)/%.o: $(L0)/src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@
$(OBJDIR)/%.o: $(L0)/exp1/src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@
$(OBJDIR)/%.o: $(L0)/harness/src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@
$(OBJDIR)/%.o: $(SPEC)/src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) librig.so

.PHONY: clean
