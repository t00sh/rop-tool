include ../Makefile.inc

.PHONY: clean

CFLAGS  = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes
CFLAGS += -fPIC -Wunreachable-code -g -fstack-protector-all

CPPFLAGS  = -I. -I./include/ -I../capstone/include
CPPFLAGS += -DVERSION="\"$(VERSION)\"" -DPACKAGE="\"$(PACKAGE)\""

SRC  = $(wildcard ./src/*/*.c)
OBJ  = $(SRC:%.c=%.o)

LIB_DYN = lib$(PACKAGE)-api.so
LIB_STATIC = lib$(PACKAGE)-api.a

all: $(LIB_DYN) $(LIB_STATIC)

$(LIB_DYN): $(OBJ)
	@ echo " LINK $@" ;
	@ $(CC) $(CFLAGS) -shared -o $@ $(OBJ) $(LDFLAGS)

$(LIB_STATIC): $(OBJ)
	@ echo " LINK $@"
	@ $(AR) rcs $@ $(OBJ)

%.o:%.c
	@ echo " CC $@" ;
	@ $(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ ;

clean:
	rm -f $(LIB_DYN) $(LIB_STATIC) $(OBJ)
