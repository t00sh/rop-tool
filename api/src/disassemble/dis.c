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
#include "disassemble.h"

/* Init the disassembler */
int r_disa_init(r_disa_s *dis, r_binfmt_arch_e arch) {
  int cs_mode;
  int cs_arch;

  assert(dis != NULL);

  memset(dis, 0, sizeof(*dis));

  if(arch == R_BINFMT_ARCH_X86_64) {
    cs_mode = CS_MODE_64;
    cs_arch = CS_ARCH_X86;
  } else if(arch == R_BINFMT_ARCH_X86) {
    cs_mode = CS_MODE_32;
    cs_arch = CS_ARCH_X86;
  }else if(arch == R_BINFMT_ARCH_ARM) {
    cs_mode = CS_MODE_ARM;
    cs_arch = CS_ARCH_ARM;
  } else if(arch == R_BINFMT_ARCH_ARM64) {
    cs_mode = CS_MODE_ARM;
    cs_arch = CS_ARCH_ARM64;
  } else if(arch == R_BINFMT_ARCH_MIPS) {
    cs_mode = CS_MODE_MIPS32;
    cs_arch = CS_ARCH_MIPS;
  } else if(arch == R_BINFMT_ARCH_MIPS64) {
    cs_mode = CS_MODE_MIPS64;
    cs_arch = CS_ARCH_MIPS;
  } else {
    return 0;
  }

  if(cs_open(cs_arch, cs_mode, &dis->handle) != CS_ERR_OK)
    return 0;

  dis->arch = arch;
  dis->flavor = R_DISA_FLAVOR_INTEL;

  return 1;
}

/* Set the disassembler flavor (intel/AT&T) */
int r_disa_set_flavor(r_disa_s *dis, r_disa_flavor_e flavor) {

  assert(dis != NULL);

  dis->flavor = flavor;

  if(flavor == R_DISA_FLAVOR_INTEL)
    return cs_option(dis->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL) == CS_ERR_OK;
  if(flavor == R_DISA_FLAVOR_ATT)
    return cs_option(dis->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) == CS_ERR_OK;

  return 0;
}

/* Free the instruction list */
void r_disa_free_instr_lst(r_disa_s *dis) {

  assert(dis != NULL);

  if(dis->instr_lst.count > 0) {
    cs_free(dis->instr_lst.head, dis->instr_lst.count);
    dis->instr_lst.count = 0;
    dis->instr_lst.head = NULL;
    dis->instr_lst.cur = 0;
  }
}

/* Close the disassembler */
void r_disa_close(r_disa_s *dis) {
  assert(dis != NULL);

  cs_close(&dis->handle);
  r_disa_free_instr_lst(dis);
}

/* Disassemble code */
size_t r_disa_code(r_disa_s *dis, byte_t *code, len_t len, addr_t addr, size_t count) {

  assert(dis != NULL);
  assert(code != NULL);

  r_disa_free_instr_lst(dis);
  dis->instr_lst.count = cs_disasm(dis->handle, code, len, addr, count, &dis->instr_lst.head);

  return dis->instr_lst.count;
}

/* Get the next disassembled instruction */
r_disa_instr_t* r_disa_next_instr(r_disa_s *dis) {
  r_disa_instr_t *instr;

  assert(dis != NULL);

  if(dis->instr_lst.cur >= dis->instr_lst.count)
    return NULL;

  instr = &dis->instr_lst.head[dis->instr_lst.cur];
  dis->instr_lst.cur++;

  return instr;
}

/* Check if the instruction at <index> is a CALL */
int r_disa_is_call(r_disa_s *dis, size_t index) {
  assert(dis != NULL);
  assert(index < dis->instr_lst.count);

  return (!strncmp(dis->instr_lst.head[index].mnemonic, "call", 4));
}

/* Check if the instruction at <index> is a JMP */
int r_disa_is_jmp(r_disa_s *dis, size_t index) {
  assert(dis != NULL);
  assert(index < dis->instr_lst.count);

  return (!strncmp(dis->instr_lst.head[index].mnemonic, "jmp", 3));
}

/* Check if the instruction at <index> is a SYSCALL */
int r_disa_is_syscall(r_disa_s *dis, size_t index) {
  assert(dis != NULL);
  assert(index < dis->instr_lst.count);

  if(!strncmp(dis->instr_lst.head[index].mnemonic, "int", 3) && !strncmp(dis->instr_lst.head[index].op_str, "0x80", 4))
    return 1;

  if(!strncmp(dis->instr_lst.head[index].mnemonic, "syscall", 7))
    return 1;

  return 0;
}

/* Check if the instruction at <index> is a RET */
int r_disa_is_ret(r_disa_s *dis, size_t index) {
  assert(dis != NULL);
  assert(index < dis->instr_lst.count);

  return (!strncmp(dis->instr_lst.head[index].mnemonic, "ret", 3));
}

/* Return 1 if last gadget is jmp/call/ret/syscall */
int r_disa_is_end_gadget(r_disa_s *dis) {

  if(dis->instr_lst.count <= 0)
    return 0;

  return r_disa_is_ret(dis, dis->instr_lst.count - 1)
    || r_disa_is_call(dis, dis->instr_lst.count - 1)
    || r_disa_is_syscall(dis, dis->instr_lst.count - 1)
    || r_disa_is_jmp(dis, dis->instr_lst.count - 1);
}

/* Transform the instr list to string : [INSTR1; [INSTR2];...]
   The string is allocated with malloc, and must be freed by the caller
*/
char* r_disa_instr_lst_to_str(r_disa_s *dis) {
  char *string;
  size_t size, i;

  assert(dis != NULL);

  if(!r_disa_is_end_gadget(dis))
    return NULL;

  size = 0;

  for(i = 0; i < dis->instr_lst.count; i++) {
    size += strlen(dis->instr_lst.head[i].mnemonic);
    size += strlen(dis->instr_lst.head[i].op_str);
    size += 3;
  }

  size++;

  string = r_utils_malloc(size);
  *string = '\0';

  for(i = 0; i < dis->instr_lst.count; i++) {
    strcat(string, dis->instr_lst.head[i].mnemonic);
    strcat(string, " ");
    strcat(string, dis->instr_lst.head[i].op_str);
    strcat(string, "; ");
  }

  return string;
}

/* Get the flavor corresponding to a string */
r_disa_flavor_e r_disa_string_to_flavor(const char *string) {
  if(!strcmp(string, "intel"))
    return R_DISA_FLAVOR_INTEL;
  if(!strcmp(string, "att"))
    return R_DISA_FLAVOR_ATT;

  return R_DISA_FLAVOR_UNDEF;
}
