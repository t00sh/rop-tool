include Makefile.inc

.PHONY: clean release test

CC = gcc

CFLAGS = -O2 -Wextra -Wall -Wwrite-strings -Wstrict-prototypes -Wuninitialized
CFLAGS += -Wunreachable-code -g -fstack-protector-all -Werror
CFLAGS += -DVERSION="\"$(VERSION)\"" -DPACKAGE="\"$(PACKAGE)\""

CFLAGS += -I include/

ifeq ($(ARCH), i686)
	CFLAGS += -m32 -L capstone-linux32
	STATIC_LIBS = ./capstone-linux32/libcapstone.a
	LIBS = -L ./capstone-linux32/ -lcapstone
else
	ARCH = x86_64
	CFLAGS += -m64 -L capstone-linux64
	STATIC_LIBS = ./capstone-linux64/libcapstone.a
	LIBS = -L ./capstone-linux64/ -lcapstone
endif


CFLAGS += -DARCHITECTURE="\"$(ARCH)\""
CFLAGS += -D__ARCH_$(ARCH)

SRC  = $(wildcard api/*/*.c)
SRC += $(wildcard src/*.c)
SRC += $(wildcard src/*/*.c)

OBJ  = $(SRC:%.c=%.o)

EXE = $(PACKAGE)-$(SYSTEM)-$(ARCH)
EXE_STATIC = $(EXE)-static

LIB_HEAP_AUTO_FILES = src/heap/libheap.c

LIB_HEAP = libheap-$(ARCH).so




all: $(EXE)
static: $(EXE_STATIC)

$(EXE): $(OBJ) $(LIB_HEAP_AUTO_FILES)
	@echo " LINK $@" ;
	@$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS);

$(EXE_STATIC): $(OBJ) $(LIB_HEAP_AUTO_FILES)
	@echo " LINK $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJ) $(STATIC_LIBS) -static


$(LIB_HEAP_AUTO_FILES): $(LIB_HEAP)
	@perl scripts/dumplibheap.pl $(ARCH)

$(LIB_HEAP):
	@echo " MAKE $@"
	@make -f lib/heap/Makefile
	@strip $(LIB_HEAP)

clean:
	rm -f $(EXE) $(EXE_STATIC) $(OBJ)
	make -f lib/heap/Makefile clean
	find . -name "*~" -delete

release: $(LIB_HEAP) $(EXE) $(EXE_STATIC)
	strip $(EXE)
	strip $(EXE_STATIC)
	gpg --armor --detach-sign $(EXE)
	gpg --armor --detach-sign $(EXE_STATIC)

test: $(EXE)
	@bash scripts/test.sh -t


%.o:%.c
	@echo " CC $@" ;
	@$(CC) $(CFLAGS) -c $< -o $@ ;
