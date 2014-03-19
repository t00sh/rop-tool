#ifndef DEF_ROPC_H
#define DEF_ROPC_H

/************************************************************************/
/* RopC - A Return Oriented Programming tool			        */
/* 								        */
/* Copyright 2013-2014, -TOSH-					        */
/* File coded by -TOSH-						        */
/* 								        */
/* This file is part of RopC.					        */
/* 								        */
/* RopC is free software: you can redistribute it and/or modify	        */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* RopC is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with RopC.  If not, see <http://www.gnu.org/licenses/>	        */
/************************************************************************/


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <elf.h>

#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <assert.h>
#include <beaengine/BeaEngine.h>

#include "xfunc.h"
#include "safe_int.h"

/* =========================================================================
   ======================================================================= */

#define FATAL_ERROR(...) do {					\
    fprintf(stderr, "[-] ");					\
    fprintf(stderr, __VA_ARGS__);				\
    fprintf(stderr, "\n");					\
    exit(EXIT_FAILURE);						\
  }while(0)

#ifndef NDEBUG
#define DEBUG(...) do {				\
  fprintf(stderr, "[DEBUG] ");			\
  fprintf(stderr, __VA_ARGS__);			\
  fprintf(stderr, "\n");			\
  }while(0)
#else
#define DEBUG(...)
#endif

/* =========================================================================
   ======================================================================= */

typedef uint64_t addr_t;
typedef uint64_t len_t;
typedef uint8_t byte_t;

/* =========================================================================
   ======================================================================= */

#define NOT_FOUND ((addr_t)-1)
#define MAX_DEPTH 50

#define COLOR_RESET    "\033[m"
#define COLOR_BLACK    "\033[30m"
#define COLOR_RED      "\033[31m"
#define COLOR_GREEN    "\033[32m"
#define COLOR_YELLOW   "\033[33m"
#define COLOR_BLUE     "\033[34m"
#define COLOR_MAGENTA  "\033[35m"
#define COLOR_CYAN     "\033[36m"
#define COLOR_WHITE    "\033[37m"

#define COLOR_BG_BLACK    "\033[40m"
#define COLOR_BG_RED      "\033[41m"
#define COLOR_BG_GREEN    "\033[42m"
#define COLOR_BG_YELLOW   "\033[43m"
#define COLOR_BG_BLUE     "\033[44m"
#define COLOR_BG_MAGENTA  "\033[45m"
#define COLOR_BG_CYAN     "\033[46m"
#define COLOR_BG_WHITE    "\033[47m"



/* =========================================================================
   ======================================================================= */

enum MODE {
  MODE_NONE=0,
  MODE_STRING,
  MODE_GADGET,
  MODE_PAYLOAD
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

enum ARCH {
  ARCH_NONE=0,
  ARCH_X86,
  ARCH_X86_64
};

/* =========================================================================
   ======================================================================= */

#define MEM_FLAG_PROT_X 1
#define MEM_FLAG_PROT_R 2
#define MEM_FLAG_PROT_W 4

/* Memory structure */
typedef struct MEM {
  addr_t addr;
  byte_t *start;
  len_t length;
  uint32_t flags;
  struct MEM *next;
}MEM;

typedef struct MLIST {
  MEM *head;
  int size;
}MLIST;

/* =========================================================================
   ======================================================================= */
enum BINFMT_ERR {
  BINFMT_ERR_OK=0,
  BINFMT_ERR_UNRECOGNIZED,
  BINFMT_ERR_NOTSUPPORTED,
  BINFMT_ERR_MALFORMEDFILE,
};

enum BINFMT_TYPE {
  BINFMT_TYPE_UNDEF=0,
  BINFMT_TYPE_ELF32,
  BINFMT_TYPE_ELF64,
  BINFMT_TYPE_PE,
  BINFMT_TYPE_RAW
};

enum BINFMT_ENDIAN {
  BINFMT_ENDIAN_UNDEF=0,
  BINFMT_ENDIAN_LITTLE,
  BINFMT_ENDIAN_BIG
};

enum BINFMT_ARCH {
  BINFMT_ARCH_UNDEF=0,
  BINFMT_ARCH_X86,
  BINFMT_ARCH_X86_64,
};

typedef struct BINFMT {
  enum BINFMT_TYPE type;
  enum BINFMT_ENDIAN endian;
  enum BINFMT_ARCH arch;
  MLIST *mlist;

  /* TODO: Symbols list */

  byte_t *mapped;
  size_t mapped_size;
}BINFMT;


/* =========================================================================
   ======================================================================= */

#define GADGET_COMMENT_LEN 256

/* Gadget structure */
typedef struct GADGET {
  char comment[GADGET_COMMENT_LEN];
  addr_t addr;
  struct GADGET *next;

}GADGET;

/* Gadget list structure */
typedef struct GLIST {
  GADGET **g_table;
  int size;
}GLIST;

/* =========================================================================
   ======================================================================= */

/* Bytes list structure */
typedef struct BLIST {
  byte_t *start;
  len_t length;

}BLIST;

/* =========================================================================
   ======================================================================= */
typedef struct PAYLOAD {
  GADGET *head;
  GADGET *tail;
  int size;
}PAYLOAD;

/* =========================================================================
   ======================================================================= */

typedef struct STRING {
  addr_t addr;
  char *string;
  struct STRING *next;

}STRING;

typedef struct SLIST {
  STRING *head;
  STRING *tail;
  int size;

}SLIST;

/* =========================================================================
   ======================================================================= */

extern char options_filename[PATH_MAX];
extern enum MODE options_mode;
extern enum FLAVOR options_flavor;
extern enum OUTPUT options_output;
extern enum ARCH options_arch;
extern int options_color;
extern int options_raw;
extern uint8_t options_depth;
extern int options_filter;
extern const char *options_payload;
extern BLIST options_bad;
extern BLIST options_search;

/* =========================================================================
   ======================================================================= */

/* elf32 */
enum BINFMT_ERR elf32_load(BINFMT *bin);

/* elf64 */
enum BINFMT_ERR elf64_load(BINFMT *bin);

/* pe */
enum BINFMT_ERR pe_load(BINFMT *bin);

/* raw */
enum BINFMT_ERR raw_load(BINFMT *bin);

/* dis */
int dis_instr(DISASM *dis, byte_t *code, len_t len, enum BINFMT_ARCH arch);
int dis_is_call(DISASM *dis);
int dis_is_jmp(DISASM *dis);
int dis_is_ret(DISASM *dis);
 
/* gfind */
void gfind_in_bin(GLIST *glist, BINFMT *bin);

/* glist */
void glist_free(GLIST **glist);
void glist_add(GLIST *glist, GADGET *g);
GLIST* glist_new(void);
GADGET* glist_find(const GLIST *glist, int (*compare)(GADGET*, const void*), const void *user);
int glist_size(GLIST *glist);
void glist_foreach(GLIST *glist, void(*callback)(GADGET*));
int glist_exist(GLIST *glist, const char *comment);

/* slist */
SLIST* slist_new(void);
void slist_add(SLIST *slist, char *string, addr_t addr);
void slist_free(SLIST **slist);
void slist_foreach(SLIST *slist, void (*callback)(STRING*));
int slist_size(SLIST *slist);

/* mlist */
void mlist_add(MLIST *mlist, addr_t addr, byte_t *start, len_t length, uint32_t flags);
void mlist_free(MLIST **mlist);
void mlist_foreach(MLIST *mlist, void (*callback)(MEM*));
int mlist_size(MLIST *mlist);
MLIST* mlist_new(void);

/* misc */
BLIST opcodes_to_blist(char *str);
char* blist_to_opcodes(BLIST *blist);
int is_good_addr(addr_t addr, BLIST *bad);
addr_t memsearch(void *s1, len_t s1_len, void *s2, len_t s2_len);

/* print */
void print_glist(GLIST *glist);
void print_slist(SLIST *slist);
void print_payload(PAYLOAD *payload);

/* options */
void options_parse(int argc, char **argv);

/* gfilter */
int gfilter_gadget(char *instr, enum BINFMT_ARCH arch);
GADGET* gfilter_search(const GLIST *glist, const char *gadget);

/* sfind */
void sfind_in_bin(SLIST *slist, BINFMT *bin, BLIST *string);

/* xfunc */
void *xmalloc(size_t size);
void* xcalloc(size_t nmemb, size_t size);
char* xstrdup(const char *s);
void* xrealloc(void *ptr, size_t size);
FILE* xfopen(const char *path, const char *mode);
int xfseek(FILE *stream, long offset, int whence);
long xftell(FILE *stream);

/* bin */
void bin_free(BINFMT *bin);
void bin_load(BINFMT *bin, const char *filename);
MEM* bin_getmem(BINFMT *bin, uint32_t flags);

/* payload */
void payload_make(BINFMT *bin, const GLIST *src, PAYLOAD *dst, const char *payload);
PAYLOAD* payload_new(void);
void payload_add(PAYLOAD *payload, const char *comment, addr_t addr);
void payload_free(PAYLOAD **payload);
void payload_foreach(PAYLOAD *payload, void (*callback)(GADGET*));
int payload_size(PAYLOAD *payload);
void payload_list(void);

/* payload_x86.c */
void payload_x86_execve_bin_sh(BINFMT *bin, const GLIST *src, PAYLOAD *dst);

/* gmake_x86 */
void gmake_x86_setreg(const GLIST *src, PAYLOAD *dst, const char *reg, addr_t value);
void gmake_x86_swapstack(const GLIST *src, PAYLOAD *dst, addr_t addr);
void gmake_x86_setmem(const GLIST *src, PAYLOAD *dst, addr_t addr, addr_t value);
void gmake_x86_strcp(const GLIST *src, PAYLOAD *dst, addr_t addr, const char *str);
void gmake_x86_syscall(const GLIST *src, PAYLOAD *dst);

/* endian */
uint64_t endian_get64(byte_t *p, enum BINFMT_ENDIAN endian);
uint32_t endian_get32(byte_t *p, enum BINFMT_ENDIAN endian);
uint16_t endian_get16(byte_t *p, enum BINFMT_ENDIAN endian);

#endif
