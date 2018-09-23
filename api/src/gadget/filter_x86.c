/************************************************************************/
/* rop-tool - A Return Oriented Programming and binary exploitation     */
/*            tool                                                      */
/*                                                                      */
/* Copyright 2013-2018, -TOSH-                                          */
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
#include "binfmt.h"

/* =========================================================================
   This file implement filters and registers for intel x86 arch
   ======================================================================= */


const char *r_filter_x86[] = {
  "pop %R",
  "popa",

  "push %R",
  "pusha",

  "add %R, %X",
  "add %R, %R",
  "add %R, %W ptr [%R %S %X]",
  "add %R, %W ptr [%R]",
  "add %W ptr [%R], %R",
  "add %W ptr [%R %S %X], %R",

  "mov %R, %R",
  "mov %W ptr [%R %S %X], %R",
  "mov %W ptr [%R], %R",
  "mov %R, %W ptr [%R]",
  "mov %R, %W ptr [%R %S %X]",

  "xchg %R, %R",
  "inc %R",
  "dec %R",

  NULL
};

const char *r_filter_x86_end[] = {
  "int 0x86",
  "call %R",
  "call %W ptr [%R]",
  "call %W ptr [%R %S %R*%X]",
  "call %W ptr [%R %S %X]",
  "call %W ptr [%R %S %R*%X %S %X]",
  "jmp %R",
  "jmp %W ptr [%R]",
  "jmp %W ptr [%R %S %R*%X %S %X]",
  "jmp %W ptr [%R %S %R*%X]",
  "jmp %W ptr [%R %S %X]",
  "syscall ",
  "leave ",
  "ret ",
  NULL
};

const char *r_filter_x86_att[] = {
  "pop%C %%%R",
  "popa",

  "push%C %%%R",
  "pusha",

  "add%C (%%%R), %%%R",
  "add%C %%%R, (%%%R)",
  "add%C %%%R, $%X",
  "add%C %%%R, %%%R",
  "add%C %%%R, %X(%%%R)",
  "add%C $%X, %%%R",
  "add%C %X, %%%R",
  "add%C %X(%%%R), %%%R",

  "mov%C %%%R, %%%R",
  "mov%C %%%R, (%%%R)",
  "mov%C (%%%R), %%%R",
  "mov%C %X(%%%R), %%%R",
  "mov%C %%%R, %X(%%%R)",

  "xchg%C %%%R, %%%R",
  "inc%C %%%R",
  "dec%C %%%R",
  NULL
};

const char *r_filter_x86_att_end[] = {
  "int $%X",
  "call%C *(%%%R)",
  "call%C *%X(%%%R)",
  "call%C *%X(%%%R, %%%R, %X)",
  "jmp%C *%%%R",
  "jmp%C *%X(%%%R)",
  "jmp%C *%X(%%%R, %%%R, %%%X)",
  "leave ",
  "ret%C ",
  NULL
};

const char *r_filter_x86_registers[] = {
  /* 8bits */
  "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", "al", "ah",
  "bl", "bh", "cl", "ch"
  /* 16bits */
  "dl", "dh", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
  "ax", "bx", "cx", "dx", "sp", "bp", "si", "di",
  /* 32bits */
  "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "eax", "ebx",
  "ecx", "edx", "esp", "ebp", "esi", "edi",
  /* 64bits */
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rax", "rbx", "rcx",
  "rdx", "rsp", "rbp", "rsi", "rdi",
};
