.PHONY: clean

CC = gcc
CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wuninitialized 
CFLAGS += -Wunreachable-code -g3 -DLINUX
CFLAGS += -L lib/ -I include/

SRC = $(wildcard src/*.c) 
OBJ = $(SRC:%.c=%.o)

LIB = lib/libdasm.a
LIB_SRC = $(wildcard lib/*.c)
LIB_OBJ = $(LIB_SRC:%.c=%.o)

EXE = ropc

all: $(EXE)

$(EXE): $(OBJ) $(LIB)
	@echo "  LINK $(EXE)" ;
	@$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(LIB);

%.o:%.c
	@echo "  CC $@" ;
	@$(CC) $(CFLAGS) -c $< -o $@ ;

$(LIB): $(LIB_OBJ)
	@echo "  AR $@" ;
	@ar -q $@ $(LIB_OBJ) 2>/dev/null;

$(LIB_OBJ): $(LIB_SRC)
	@echo "  CC $@" ;
	@$(CC) $(CFLAGS) -c $< -o $@ ;

clean:
	rm $(EXE) $(OBJ) $(LIB) $(LIB_OBJ)
