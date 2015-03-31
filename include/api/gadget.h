#ifndef DEF_API_GADGET_H
#define DEF_API_GADGET_H

#include "api/utils.h"
#include "api/binfmt.h"
#include "api/disassemble.h"

typedef struct r_gadget {
  char *gadget;
  addr_t addr;
}r_gadget_s;

typedef struct r_gadget_handle {
  r_utils_hash_s *g_hash;
  r_disa_s disa;
  int filter;
  int all;
  int depth;
}r_gadget_handle_s;

int r_gadget_handle_init(r_gadget_handle_s *g_handle, r_binfmt_arch_e arch, r_disa_flavor_e flavor, int filter, int depth, int all);
void r_gadget_handle_close(r_gadget_handle_s *g_handle);
void r_gadget_update(r_gadget_handle_s *g_handle, addr_t addr, u8 *code, u32 code_size);

int r_gadget_filter(const char *gadget, r_binfmt_arch_e arch, r_disa_flavor_e flavor);

#endif
