.PHONY: clean release

VERSION = 2.0
PACKAGE = rop-tool

CC = gcc
CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wuninitialized
CFLAGS += -Wunreachable-code -g -fstack-protector-all
CFLAGS += -lcapstone
CFLAGS += -DVERSION="\"$(VERSION)\"" -DPACKAGE="\"$(PACKAGE)\""

CFLAGS += -I include/

#CFLAGS += -pg

SRC  = $(wildcard api/*/*.c)
SRC += $(wildcard src/*.c)
SRC += $(wildcard src/*/*.c)

OBJ  = $(SRC:%.c=%.o)

ARCH=$(shell uname -m)
EXE = $(PACKAGE)"_"$(ARCH)"_v"$(VERSION)

all: $(EXE)

$(EXE): $(OBJ)
	@echo " LINK $(EXE)" ;
	@$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(LIB);

%.o:%.c
	@echo " CC $@" ;
	@$(CC) $(CFLAGS) -c $< -o $@ ;

clean:
	rm $(EXE) $(OBJ)
	find . -name "*~" -delete

release: $(EXE)
	strip $(EXE)
	gpg --armor --detach-sign $(EXE)
