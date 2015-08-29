include Makefile.inc

CC = gcc
AR = ar

CFLAGS = -fPIC -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wuninitialized
CFLAGS += -Wunreachable-code -g -fstack-protector-all
CFLAGS += -DVERSION="\"$(VERSION)\"" -DPACKAGE="\"$(PACKAGE)\""

CFLAGS += -I ./include/

ifeq ($(ARCH), i686)
	CFLAGS += -m32 -L ./capstone-linux32
	STATIC_LIBS = ./capstone-linux32/libcapstone.a
	LIBS = -L ./capstone-linux32/ -lcapstone
else
	ARCH = x86_64
	CFLAGS += -m64 -L ./capstone-linux64
	STATIC_LIBS = ./capstone-linux64/libcapstone.a
	LIBS = -L ./capstone-linux64/ -lcapstone
endif

CFLAGS += -DARCHITECTURE="\"$(ARCH)\""
CFLAGS += -D__ARCH_$(ARCH)

SRC  = $(wildcard ./api/*/*.c)

OBJ  = $(SRC:%.c=%.o)

LIB_DYN = $(PACKAGE)-API-$(SYSTEM)-$(ARCH).so
LIB_STATIC = $(PACKAGE)-API-$(SYSTEM)-$(ARCH).a

.PHONY: clean

all: $(LIB_DYN) $(LIB_STATIC)

$(LIB_DYN): $(OBJ)
	@echo " LINK $@" ;
	@$(CC) $(CFLAGS) -shared -o $@ $(OBJ) $(LIBS);

$(LIB_STATIC): $(OBJ)
	@echo " LINK $@"
	@$(AR) rcs $@ $(OBJ)

clean:
	rm -f $(LIB_DYN) $(LIB_STATIC) $(OBJ)
	find . -name "*~" -delete

%.o:%.c
	@echo " CC $@" ;
	@$(CC) $(CFLAGS) -c $< -o $@ ;
