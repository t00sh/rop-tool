.PHONY: clean release test
include Makefile.inc


CC = gcc

CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wuninitialized
CFLAGS += -Wunreachable-code -g -fstack-protector-all
CFLAGS += -DVERSION="\"$(VERSION)\"" -DPACKAGE="\"$(PACKAGE)\""

CFLAGS += -I include/

ifeq ($(ARCH), i686)
	CFLAGS += -m32 -L capstone-linux32
	STATIC_LIBS = ./capstone-linux32/libcapstone.a
	LIBS = -L ./capstone-linux32/ -lcapstone
else
	ARCH = x86-64
	CFLAGS += -m64 -L capstone-linux64
	STATIC_LIBS = ./capstone-linux64/libcapstone.a
	LIBS = -L ./capstone-linux64/ -lcapstone
endif

CFLAGS += -DARCHITECTURE="\"$(ARCH)\""

SRC  = $(wildcard api/*/*.c)
SRC += $(wildcard src/*.c)
SRC += $(wildcard src/*/*.c)

OBJ  = $(SRC:%.c=%.o)

EXE = $(PACKAGE)-$(SYSTEM)-$(ARCH)
EXE_STATIC = $(EXE)-static

LIB_HEAP = libheap-$(ARCH).so

all: $(EXE) $(LIB_HEAP)
static: $(EXE_STATIC)

$(EXE): $(OBJ)
	@echo " LINK $@" ;
	@$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS);

$(EXE_STATIC): $(OBJ)
	@echo " LINK $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJ) $(STATIC_LIBS) -static

$(LIB_HEAP):
	@echo " MAKE $@"
	@make -f lib/heap/Makefile

%.o:%.c
	@echo " CC $@" ;
	@$(CC) $(CFLAGS) -c $< -o $@ ;

clean:
	rm -f $(EXE) $(EXE_STATIC) $(OBJ)
	make -f lib/heap/Makefile clean
	find . -name "*~" -delete

release: $(EXE) $(EXE_STATIC) $(LIB_HEAP)
	strip $(EXE)
	strip $(EXE_STATIC)
	gpg --armor --detach-sign $(EXE)
	gpg --armor --detach-sign $(EXE_STATIC)
	gpg --armor --detach-sign $(LIB_HEAP)	

test: $(EXE)
	@bash scripts/test.sh -t
