/************************************************************************/
/* rop-tool - A Return Oriented Programming and binary exploitation     */
/*            tool                                                      */
/*                                                                      */
/* Copyright 2013-2015, -TOSH-                                          */
/* File coded by -TOSH-                                                 */
/*                                                                      */
/* This file is part of rop-tool.                                       */
/*                                                                      */
/* rop-tool is free software: you can redistribute it and/or modify     */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.                                  */
/*                                                                      */
/* rop-tool is distributed in the hope that it will be useful,          */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.                         */
/*                                                                      */
/* You should have received a copy of the GNU General Public License    */
/* along with rop-tool.  If not, see <http://www.gnu.org/licenses/>     */
/************************************************************************/
#ifndef DEF_API_DISASSEMBLE_H
#define DEF_API_DISASSEMBLE_H

#include <capstone/capstone.h>

#include "utils.h"
#include "binfmt.h"


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
  r_binfmt_endian_e endian;
  r_disa_flavor_e flavor;
}r_disa_s;



int r_disa_init_from_string(r_disa_s *, const char *);
int r_disa_init(r_disa_s *, r_binfmt_arch_e, r_binfmt_endian_e);
int r_disa_string_to_arch(const char *, r_binfmt_arch_e *, r_binfmt_endian_e *);
int r_disa_set_flavor(r_disa_s *, r_disa_flavor_e);
void r_disa_list_architectures(void);
void r_disa_free_instr_lst(r_disa_s *dis);
void r_disa_close(r_disa_s *dis);
size_t r_disa_code(r_disa_s *dis, byte_t *code, len_t len, addr_t addr, size_t count);
r_disa_instr_t* r_disa_next_instr(r_disa_s *dis);
char* r_disa_instr_lst_to_str(r_disa_s *dis);
r_disa_flavor_e r_disa_string_to_flavor(const char *string);


#endif
