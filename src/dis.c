#include "ropc.h"

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

/* =========================================================================
   This file implement functions for disassembling x86/x86_64 code
   ======================================================================= */

/* Init the disassembler */
int dis_init(DIS *dis, enum BINFMT_ARCH arch) {
  int cs_mode;

  memset(dis, 0, sizeof(DIS));

  if(arch == BINFMT_ARCH_X86_64)
    cs_mode = CS_MODE_64;
  else
    cs_mode = CS_MODE_32;

  if(cs_open(CS_ARCH_X86, cs_mode, &dis->handle) != CS_ERR_OK)
    return 0;

  if(options_flavor == FLAVOR_ATT)
    cs_option(dis->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

  dis->arch = arch;

  return 1;
}

/* Free the instruction list */
void dis_free_instr_lst(DIS *dis) {
  if(dis->instr_lst.count > 0) {
    cs_free(dis->instr_lst.insn, dis->instr_lst.count);
    dis->instr_lst.count = 0;
    dis->instr_lst.cur_instr = 0;
  }
}
/* Close the disassembler */
void dis_close(DIS *dis) {
  cs_close(&dis->handle);
  dis_free_instr_lst(dis);
}

/* Disassemble code */
int dis_code(DIS *dis, byte_t *code, len_t len, addr_t addr, size_t count) {

  dis_free_instr_lst(dis);
  dis->instr_lst.count = cs_disasm(dis->handle, code, len, addr, count, &dis->instr_lst.insn);

  return dis->instr_lst.count;
}

int dis_next_instr(DIS *dis, INSTR **instr) {
  if(dis->instr_lst.cur_instr >= dis->instr_lst.count)
    return 0;

  *instr = &dis->instr_lst.insn[dis->instr_lst.cur_instr];
  dis->instr_lst.cur_instr++;

  return 1;
}

/* Check if last instruction is a CALL */
int dis_end_is_call(DIS *dis) {
  int end;

  if(dis->instr_lst.count == 0)
    return 0;

  end = dis->instr_lst.count-1;
  return (!strncmp(dis->instr_lst.insn[end].mnemonic, "call", 4));
}

/* Check if last instruction is a JMP */
int dis_end_is_jmp(DIS *dis) {
  int end;

  if(dis->instr_lst.count == 0)
    return 0;

  end = dis->instr_lst.count-1;
  return (!strncmp(dis->instr_lst.insn[end].mnemonic, "jmp", 3));
}

/* Check if last instruction is a RET */
int dis_end_is_ret(DIS *dis) {
  int end;

  if(dis->instr_lst.count == 0)
    return 0;

  end = dis->instr_lst.count-1;
  return (!strncmp(dis->instr_lst.insn[end].mnemonic, "ret", 3));
}
