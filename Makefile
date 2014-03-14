.PHONY: clean

VERSION = 1.0
PACKAGE = ropc

CC = gcc
CFLAGS = -O3 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wuninitialized
CFLAGS += -Wunreachable-code -g3 -fstack-protector-all
CFLAGS += -I include/
CFLAGS += -lBeaEngine
CFLAGS += -DVERSION=\"$(VERSION)\" -DPACKAGE=\"$(PACKAGE)\"
#CFLAGS += -pg

SRC = $(wildcard src/*.c)
OBJ = $(SRC:%.c=%.o)

EXE = $(PACKAGE)

all: $(EXE)

$(EXE): $(OBJ)
	@echo " LINK $(EXE)" ;
	@$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(LIB);

%.o:%.c
	@echo " CC $@" ;
	@$(CC) $(CFLAGS) -c $< -o $@ ;

clean:
	rm $(EXE) $(OBJ)
