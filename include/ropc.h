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
#include <limits.h>
#include <assert.h>
#include <beaengine/BeaEngine.h>

#define MAX_DEPTH 50
#define MAX_INSTR_SIZE 128

#define COLOR_RESET    "\033[m"
#define COLOR_RED      "\033[31m"
#define COLOR_GREEN    "\033[32m"
#define COLOR_WHITE    "\033[37m"
#define COLOR_BLACK    "\033[30m"
#define COLOR_BG_WHITE "\033[47m"


enum MODE {
  MODE_NONE=0,
  MODE_STRING,
  MODE_GADGET
};

enum OUTPUT {
  OUTPUT_NONE=0,
  OUTPUT_C,
  OUTPUT_PERL,
  OUTPUT_BASH,
  OUTPUT_C_PLUS,
  OUTPUT_PYTHON,
  OUTPUT_RUBY,
  OUTPUT_PHP,
  OUTPUT_ASM
};

enum FLAVOR {
  FLAVOR_NONE=0,
  FLAVOR_INTEL,
  FLAVOR_ATT
};

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

/* Memory structure */
typedef struct MEM {
  uint32_t addr;
  uint32_t length;
  uint8_t  *start;
}MEM;

/* Elf structure */
typedef struct ELF {
  
  union ehdr {
    Elf32_Ehdr *x32;
    Elf64_Ehdr *x64;
  }ehdr;

  union shdr {
    Elf32_Shdr *x32;
    Elf64_Shdr *x64;
  }shdr;

  union phdr {
    Elf32_Phdr *x32;
    Elf64_Phdr *x64;
  }phdr;

  uint8_t *e_ident;
  MEM mem;

}ELF;

#define GADGET_COMMENT_LEN 256

/* Gadget structure */
typedef struct GADGET {
  char comment[GADGET_COMMENT_LEN];
  uint32_t value;
  struct GADGET *next;

}GADGET;

/* Gadget list structure */
typedef struct GLIST {
  GADGET **g_table;
  uint32_t size;
}GLIST;

/* Bytes list structure */
typedef struct BLIST {
  uint8_t *start;
  uint32_t length;

}BLIST;

typedef struct STRING {
  uint32_t addr;
  char *string;
  struct STRING *next;

}STRING;

typedef struct SLIST {
  STRING *head;
  STRING *tail;
  uint32_t size;

}SLIST;

extern char options_filename[PATH_MAX];
extern enum MODE options_mode;
extern enum FLAVOR options_flavor;
extern enum OUTPUT options_output;
extern int options_color;
extern uint8_t options_depth;
extern int options_filter;
extern BLIST options_bad;
extern BLIST options_search;

/* elf */
void elf_load(ELF *elf, const char *filename);
void elf_free(ELF *elf);
MEM elf_getseg(ELF *elf, uint32_t p_type, uint32_t p_flags);


/* dis */
int dis_instr(DISASM *dis, uint8_t *code, uint32_t len, int arch);
int dis_is_call(DISASM *dis);
int dis_is_jmp(DISASM *dis);
int dis_is_ret(DISASM *dis);
 
/* gfind */
void gfind_in_elf(GLIST *glist, ELF *elf);

/* glist */
void glist_free(GLIST **glist);
void glist_add(GLIST *glist, GADGET *g);
GLIST* glist_new(void);
GADGET* glist_find(GLIST *glist, const char *comment);
uint32_t glist_size(GLIST *glist);
void glist_foreach(GLIST *glist, void(*callback)(GADGET*));

/* slist */
SLIST* slist_new(void);
void slist_add(SLIST *slist, char *string, uint32_t addr);
void slist_free(SLIST **slist);
void slist_foreach(SLIST *slist, void (*callback)(STRING*));
uint32_t slist_size(SLIST *slist);

/* misc */
BLIST opcodes_to_blist(char *str);
char* blist_to_opcodes(BLIST *blist);
int is_good_addr(uint32_t addr, BLIST *bad);
uint32_t memsearch(void *s1, size_t s1_len, void *s2, size_t s2_len);

/* print */
void print_glist(GLIST *glist);
void print_slist(SLIST *slist);

/* options */
void options_parse(int argc, char **argv);

/* gfilter */
int gfilter_gadget(char *instr);

/* sfind */
void sfind_in_elf(SLIST *slist, ELF *elf, BLIST *string);

#endif
