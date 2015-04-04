.PHONY: clean release

VERSION = 2.0
PACKAGE = rop-tool

CC = gcc
CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wuninitialized
CFLAGS += -Wunreachable-code -g -fstack-protector-all
CFLAGS += -DVERSION="\"$(VERSION)\"" -DPACKAGE="\"$(PACKAGE)\""

LIBS = -lcapstone
STATIC_LIBS = ../capstone/libcapstone.a

CFLAGS += -I include/

#CFLAGS += -pg

SRC  = $(wildcard api/*/*.c)
SRC += $(wildcard src/*.c)
SRC += $(wildcard src/*/*.c)

OBJ  = $(SRC:%.c=%.o)

ARCH=$(shell uname -m)

EXE = $(PACKAGE)-$(ARCH)
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
