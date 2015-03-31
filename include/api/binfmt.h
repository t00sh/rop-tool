#ifndef DEF_ROPC_BINFMT_API_H
#define DEF_ROPC_BINFMT_API_H

#include <elf.h>
#include "api/utils.h"

#define R_BINFMT_BAD_ADDR ((u64)-1)

typedef enum r_binfmt_mem_flag {
  R_BINFMT_MEM_FLAG_NONE=0,
  R_BINFMT_MEM_FLAG_PROT_X=1,
  R_BINFMT_MEM_FLAG_PROT_R=2,
  R_BINFMT_MEM_FLAG_PROT_W=4,
}r_binfmt_mem_flag_e;

typedef struct r_binfmt_mem {
  addr_t addr;
  len_t length;
  u32 flags;
  byte_t *start;
  struct r_binfmt_mem *next;
}r_binfmt_mem_s;

typedef struct r_binfmt_mlist {
  r_binfmt_mem_s *head;
  int size;
}r_binfmt_mlist_s;

typedef enum r_binfmt_err {
  R_BINFMT_ERR_OK=0,
  R_BINFMT_ERR_UNRECOGNIZED,
  R_BINFMT_ERR_NOTSUPPORTED,
  R_BINFMT_ERR_MALFORMEDFILE
}r_binfmt_err_e;

typedef enum r_binfmt_type {
  R_BINFMT_TYPE_UNDEF=0,
  R_BINFMT_TYPE_ELF32,
  R_BINFMT_TYPE_ELF64,
  R_BINFMT_TYPE_PE,
  R_BINFMT_TYPE_RAW
}r_binfmt_type_e;

typedef enum r_binfmt_endian {
  R_BINFMT_ENDIAN_UNDEF=0,
  R_BINFMT_ENDIAN_LITTLE,
  R_BINFMT_ENDIAN_BIG
}r_binfmt_endian_e;

typedef enum r_binfmt_arch {
  R_BINFMT_ARCH_UNDEF=0,
  R_BINFMT_ARCH_X86,
  R_BINFMT_ARCH_X86_64
}r_binfmt_arch_e;


typedef struct binfmt {
  r_binfmt_type_e type;
  r_binfmt_endian_e endian;
  r_binfmt_arch_e arch;
  r_binfmt_mlist_s *mlist;

  /* TODO: Symbols list */

  byte_t *mapped;
  size_t mapped_size;
}r_binfmt_s;


r_binfmt_mlist_s* r_binfmt_mlist_new(void);
void r_binfmt_mlist_add(r_binfmt_mlist_s *mlist, addr_t addr, byte_t *start, len_t length, u32 flags);
void r_binfmt_mlist_free(r_binfmt_mlist_s **mlist);
void r_binfmt_mlist_foreach(r_binfmt_mlist_s *mlist, void (*callback)(r_binfmt_mem_s*));
int r_binfmt_mlist_size(r_binfmt_mlist_s *mlist);


r_binfmt_err_e r_binfmt_pe_load(r_binfmt_s *bin);
r_binfmt_err_e r_binfmt_elf64_load(r_binfmt_s *bin);
r_binfmt_err_e r_binfmt_elf32_load(r_binfmt_s *bin);
r_binfmt_err_e r_binfmt_raw_load(r_binfmt_s *bin);

void r_binfmt_free(r_binfmt_s *bin);
void r_binfmt_load(r_binfmt_s *bin, const char *filename, int raw);
void r_binfmt_write(r_binfmt_s *bin, const char *filename);
void r_binfmt_foreach_mem(r_binfmt_s *bin, void (*callback)(r_binfmt_mem_s*), u32 flags);
void r_binfmt_get_mem_flag_str(char str[4], r_binfmt_mem_s *mem);
r_binfmt_arch_e r_binfmt_string_to_arch(const char *str);

u64 r_binfmt_get_int64(byte_t *p, r_binfmt_endian_e endian);
u32 r_binfmt_get_int32(byte_t *p, r_binfmt_endian_e endian);
u16 r_binfmt_get_int16(byte_t *p, r_binfmt_endian_e endian);

#endif
