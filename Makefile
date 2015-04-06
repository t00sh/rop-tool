.PHONY: clean release
include Makefile.inc


CC = gcc

CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wuninitialized
CFLAGS += -Wunreachable-code -g -fstack-protector-all
CFLAGS += -DVERSION="\"$(VERSION)\"" -DPACKAGE="\"$(PACKAGE)\""

CFLAGS += -I include/

ARCH ?= $(shell uname -m)

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

SRC  = $(wildcard api/*/*.c)
SRC += $(wildcard src/*.c)
SRC += $(wildcard src/*/*.c)

OBJ  = $(SRC:%.c=%.o)

SYSTEM=$(shell uname -s)

EXE = $(PACKAGE)-$(SYSTEM)-$(ARCH)
EXE_STATIC = $(EXE)-static

all: $(EXE)
static: $(EXE_STATIC)

$(EXE): $(OBJ)
	@echo " LINK $@" ;
	@$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS);

$(EXE_STATIC): $(OBJ)
	@echo " LINK $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJ) $(STATIC_LIBS) -static

%.o:%.c
	@echo " CC $@" ;
	@$(CC) $(CFLAGS) -c $< -o $@ ;

clean:
	rm $(EXE) $(OBJ)
	find . -name "*~" -delete

release: $(EXE) $(EXE_STATIC)
	strip $(EXE)
	strip $(EXE_STATIC)
	gpg --armor --detach-sign $(EXE)
	gpg --armor --detach-sign $(EXE_STATIC)
