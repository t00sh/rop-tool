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

#define MAX_DEPTH 50

#define COLOR_RESET    "\033[m"
#define COLOR_RED      "\033[31m"
#define COLOR_GREEN    "\033[32m"
#define COLOR_WHITE    "\033[37m"
#define COLOR_BLACK    "\033[30m"
#define COLOR_BG_WHITE "\033[47m"

/* =========================================================================
   ======================================================================= */

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
  BINFMT_TYPE_ELF64
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
  addr_t value;
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
extern int options_color;
extern uint8_t options_depth;
extern int options_filter;
extern BLIST options_bad;
extern BLIST options_search;

/* =========================================================================
   ======================================================================= */

/* elf32 */
enum BINFMT_ERR elf32_load(BINFMT *bin);

/* elf64 */
enum BINFMT_ERR elf64_load(BINFMT *bin);

/* dis */
int dis_instr(DISASM *dis, byte_t *code, len_t len, int arch);
int dis_is_call(DISASM *dis);
int dis_is_jmp(DISASM *dis);
int dis_is_ret(DISASM *dis);
 
/* gfind */
void gfind_in_bin(GLIST *glist, BINFMT *bin);

/* glist */
void glist_free(GLIST **glist);
void glist_add(GLIST *glist, GADGET *g);
GLIST* glist_new(void);
GADGET* glist_find(GLIST *glist, const char *comment);
int glist_size(GLIST *glist);
void glist_foreach(GLIST *glist, void(*callback)(GADGET*));

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
off_t memsearch(void *s1, len_t s1_len, void *s2, len_t s2_len);

/* print */
void print_glist(GLIST *glist);
void print_slist(SLIST *slist);

/* options */
void options_parse(int argc, char **argv);

/* gfilter */
int gfilter_gadget(char *instr);

/* sfind */
void sfind_in_bin(SLIST *slist, BINFMT *bin, BLIST *string);

/* xfunc */
void *xmalloc(size_t size);
void* xcalloc(size_t nmemb, size_t size);
char* xstrdup(const char *s);
int xopen(const char *path, int oflag);
ssize_t xread(int fd, void *buf, size_t count);
ssize_t xwrite(int fd, const void *buf, size_t count);
void* xrealloc(void *ptr, size_t size);
void* xmmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
int xclose(int fildes);
int xfstat(int fildes, struct stat *buf);

/* bin */
void bin_free(BINFMT *bin);
void bin_load(BINFMT *bin, const char *filename);

#endif
