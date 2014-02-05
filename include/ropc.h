#ifndef DEF_ROPC_H
#define DEF_ROPC_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <ctype.h>
#include <getopt.h>

#include "libdasm.h"

#define VERSION "1.0"
#define PROGNAME "ROPc"

#define MAX_PATH_LEN 256
#define MAX_DEPTH 50

#define STAGE0_STRCPY 1
#define STAGE0_MEMSET 2
#define STAGE0_MEMCPY 3

#define COLOR_RESET    "\033[m"
#define COLOR_RED      "\033[31m"
#define COLOR_WHITE    "\033[37m"
#define COLOR_BLACK    "\033[30m"
#define COLOR_BG_WHITE "\033[47m"

#define SYSCALL_FATAL_ERROR(...) do {				\
    fprintf(stderr, "[-] ");					\
    fprintf(stderr, __VA_ARGS__);				\
    fprintf(stderr, " : %s\n", strerror(errno));		\
    exit(EXIT_FAILURE);						\
  }while(0)

#define FATAL_ERROR(...) do {					\
    fprintf(stderr, "[-] ");					\
    fprintf(stderr, __VA_ARGS__);				\
    fprintf(stderr, "\n");					\
    exit(EXIT_FAILURE);						\
  }while(0)

typedef struct DATA {
  uint8_t *data;
  uint32_t length;
  uint32_t addr;
}DATA, STRING;

typedef struct ELF {
  Elf32_Ehdr *ehdr;
  Elf32_Shdr *shdr;
  Elf32_Phdr *phdr;
  DATA data;

}ELF;

typedef struct GADGET {
  char *string;
  uint32_t addr;
  struct GADGET *next;

}GADGET;

# define GADGET_TABLE_SIZE 0x5000

typedef struct GADGETS {
  GADGET* table[GADGET_TABLE_SIZE];  
}GADGETS;

typedef struct STRINGS {
  STRING **lst;
  uint32_t entries;
  uint32_t entries_alloc;
}STRINGS;

typedef struct OPTIONS {
  int search_gadget;
  int search_string;
  char filename[MAX_PATH_LEN];
  int depth;  
  int call;
  DATA bad_chars;
  int filter;
  int no_colors;
  int stage0;
  FILE *out;
  int att_syntax;

}OPTIONS;

extern OPTIONS Options;
extern ELF File;
extern DATA String;

/* elf */
void load_elf(const char *filename, ELF *elf);
void free_elf(ELF *elf);

/* string */
void free_strings(STRINGS *s);
void add_string(STRINGS *s, STRING *string);
void print_string(STRING *s);
void print_strings(STRINGS *s);
STRINGS searching_strings_in_elf(ELF *elf, STRING *string);

/* gadget */
void free_gadgets(GADGETS *g);
void print_gadgets(GADGETS *g);
void searching_gadgets_in_elf(GADGETS *g, ELF *elf);

/* misc */
DATA memdup(DATA *data);
uint32_t memsearch(DATA *dst, DATA *src, uint32_t offset);
int is_good_addr(uint32_t addr, DATA *bad);
int is_hexa_char(int c);
int hex_to_dec(int c);
int dec_to_hex(int c);
char* data_to_opcodes(DATA *data);
DATA opcodes_to_data(char *str);

/* filter */
int filter_gadget(char *gadget);

/* stage0 */
void stage0_strcpy(void);
#endif
