PLATFORM_SRC = $(wildcard patches/*)
SRC = $(wildcard src/*)
OBJDIR = obj
PLATFORM_OBJS = $(patsubst patches/%,$(OBJDIR)/patches/%,$(PLATFORM_SRC:.c=.o))
OBJS = $(patsubst src/%,$(OBJDIR)/%,$(SRC:.c=.o)) $(PLATFORM_OBJS)
PLOOSHFINDER = plooshfinder/libplooshfinder.a
INCLDIRS = -I./include -I./plooshfinder/include

LDFLAGS ?= -fuse-ld=lld
LDFLAGS += -L./plooshfinder
CFLAGS ?= -O2
CC := clang
LIBS = -lplooshfinder

.PHONY: $(PLOOSHFINDER) all

all: dirs $(PLOOSHFINDER) $(OBJS) RealRoot

submodules:
	@git submodule update --init --remote --recursive || true

dirs:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(OBJDIR)/patches
	@mkdir -p $(OBJDIR)/patches

clean:
	@rm -rf RealRoot obj
	@$(MAKE) -C plooshfinder clean

RealRoot: $(OBJS) $(PLOOSHFINDER)
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $(INCLDIRS) $(OBJS) -o $@

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLDIRS) -c -o $@ $<

$(OBJDIR)/patches/%.o: patches/%.c
	$(CC) $(CFLAGS) $(INCLDIRS) -c -o $@ $<

$(PLOOSHFINDER):
	$(MAKE) -C plooshfinder all