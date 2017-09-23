include ../Makefile.inc

.PHONY: clean

LIBROP_TOOL_API_STATIC = ../api/librop-tool-api.a
LIBCAPSTONE_STATIC = ../capstone/libcapstone.a

CFLAGS  = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes
CFLAGS += -Wunreachable-code -g -fstack-protector-all

CPPFLAGS  = -I. -I./include/ -I../capstone/include -I../api/ -I../api/include
CPPFLAGS += -DVERSION="\"$(VERSION)\"" -DPACKAGE="\"$(PACKAGE)\""

LDFLAGS = -L../capstone/ -static

SRC  = $(wildcard ./src/*/*.c)
SRC += $(wildcard ./src/*.c)
OBJ  = $(SRC:%.c=%.o)

EXE = $(PACKAGE)

all: $(EXE)

$(EXE): $(OBJ) $(LIBROP_TOOL_API_STATIC) $(LIBCAPSTONE_STATIC)
	@ echo " LINK $@" ;
	@ $(CC) $(CFLAGS) -o $@ $(OBJ)  \
		$(LIBROP_TOOL_API_STATIC) $(LIBCAPSTONE_STATIC) $(LDFLAGS)

%.o:%.c
	@ echo " CC $@" ;
	@ $(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ ;

clean:
	rm -f $(EXE) $(OBJ)
