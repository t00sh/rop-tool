.PHONY: clean

CC = gcc

CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wuninitialized
CFLAGS += -Wunreachable-code -g -fstack-protector-all

CFLAGS += -I include/

ifeq ($(ARCH), i686)
	CFLAGS += -m32
else
	ARCH = x86-64
	CFLAGS += -m64
endif

SRC = $(wildcard lib/heap/src/*.c)
OBJ  = $(SRC:%.c=%.o)

LIB_HEAP = libheap-$(ARCH).so

all: $(LIB_HEAP)

$(LIB_HEAP): $(OBJ)
	@echo " LINK $@"
	@$(CC) $(CFLAGS) -ldl -fPIC -shared -o $@ $(OBJ)

%.o:%.c
	@echo " CC $@" ;
	@$(CC) $(CFLAGS) -fPIC -c $< -o $@ ;

clean:
	rm -f $(LIB_HEAP) $(OBJ)
	find . -name "*~" -delete
