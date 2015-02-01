#ifndef DEF_API_DISASSEMBLE_H
#define DEF_API_DISASSEMBLE_H

#include "api/utils.h"
#include "api/binfmt.h"
#include <capstone/capstone.h>

typedef csh r_disa_handle_t;
typedef cs_insn r_disa_instr_t;

typedef enum r_disa_flavor {
  R_DISA_FLAVOR_UNDEF=0,
  R_DISA_FLAVOR_INTEL,
  R_DISA_FLAVOR_ATT
}r_disa_flavor_e;

typedef struct r_disa_instr_lst {
  r_disa_instr_t *head;
  size_t count;
  size_t cur;
}r_disa_instr_lst_s;

typedef struct r_disa {
  r_disa_handle_t handle;
  r_disa_instr_lst_s instr_lst;
  r_binfmt_arch_e arch;
  r_disa_flavor_e flavor;
}r_disa_s;



int r_disa_init(r_disa_s *dis, r_binfmt_arch_e arch);
int r_disa_set_flavor(r_disa_s *dis, r_disa_flavor_e flavor);
void r_disa_free_instr_lst(r_disa_s *dis);
void r_disa_close(r_disa_s *dis);
size_t r_disa_code(r_disa_s *dis, byte_t *code, len_t len, addr_t addr, size_t count);
r_disa_instr_t* r_disa_next_instr(r_disa_s *dis);
int r_disa_end_is_call(r_disa_s *dis);
int r_disa_end_is_jmp(r_disa_s *dis);
int r_disa_end_is_ret(r_disa_s *dis);
char* r_disa_instr_lst_to_str(r_disa_s *dis);
r_disa_flavor_e r_disa_string_to_flavor(const char *string);

#endif
