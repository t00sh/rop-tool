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
}r_gadget_handle_s;

#endif
