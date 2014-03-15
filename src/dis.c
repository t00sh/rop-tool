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


int dis_instr(DISASM *dis, byte_t *code, len_t len, enum BINFMT_ARCH arch) {

  memset(dis, 0, sizeof(DISASM));

  if(arch == BINFMT_ARCH_X86_64)
    dis->Archi = 64;
  else
    dis->Archi = 0;

  dis->SecurityBlock = len;
  dis->EIP = (UIntPtr)code;  

  if(options_flavor == FLAVOR_ATT)
    dis->Options = PrefixedNumeral + ATSyntax;
  else if(options_flavor == FLAVOR_INTEL)
    dis->Options = PrefixedNumeral + NasmSyntax;

  return Disasm(dis);
}

int dis_is_call(DISASM *dis) {
  return (dis->Instruction.BranchType == CallType);
}

int dis_is_jmp(DISASM *dis) {
  return (dis->Instruction.BranchType == JmpType);
}

int dis_is_ret(DISASM *dis) {
  return (dis->Instruction.BranchType == RetType);
}
