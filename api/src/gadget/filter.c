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
#include "binfmt.h"


/* =========================================================================
   This file implement functions for filter and matching gadgets
   ======================================================================= */

/*
 * %X  : hexadécimal value
 * %R : register
 * %C : a caractere
 * %W : qword, dword, word, byte
 * %S : - or +
 * %% : '%' char
 */

static const char *intel_filters[] = {
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

  "int %X",
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

  "mov %R, %R",
  "mov %W ptr [%R %S %X], %R",
  "mov %W ptr [%R], %R",
  "mov %R, %W ptr [%R]",
  "mov %R, %W ptr [%R %S %X]",

  "xchg %R, %R",
  "inc %R",
  "dec %R",

  "syscall ",
  "leave ",
  "ret ",
  NULL
};

static const char *intel_att_filters[] = {
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

  "int $%X",
  "call%C *(%%%R)",
  "call%C *%X(%%%R)",
  "call%C *%X(%%%R, %%%R, %X)",
  "jmp%C *%%%R",
  "jmp%C *%X(%%%R)",
  "jmp%C *%X(%%%R, %%%R, %%%X)",

  "mov%C %%%R, %%%R",
  "mov%C %%%R, (%%%R)",
  "mov%C (%%%R), %%%R",
  "mov%C %X(%%%R), %%%R",
  "mov%C %%%R, %X(%%%R)",

  "xchg%C %%%R, %%%R",
  "inc%C %%%R",
  "dec%C %%%R",

  "leave ",
  "ret%C ",
  NULL
};

static const char *intel_registers[] = {
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

static int r_gadget_register_length(const char *string, const char **registers) {
  size_t i;

  for(i = 0; registers[i] != NULL; i++) {
    if(!strncmp(string, registers[i], strlen(registers[i])))
      return strlen(registers[i]);
  }
  return 0;
}

/* Return true if the instruction match the filter */
int r_gadget_filter_strncmp(const char *gadget, const char *filter,
                            const char **registers, int len) {
  const char *p1 = filter;
  const char *p2 = gadget;
  int i, length;

  i = 0;
  while((len == 0 || i < len)
        && *p1 != '\0' && p2[i] != '\0') {
    if(*p1 == '%') {

      p1++;
      if(*p1 == '%') {
        if(p2[i] != '%')
          break;
      }
      if(*p1 == 'S') {
        if(p2[i] != '+' && p2[i] != '-') {
          break;
        }
      }
      if(*p1 == 'W') {
        if(!strncmp(p2+i, "qword", 5)) {
          i += 4;
        } else if(!strncmp(p2+i, "dword", 5)) {
          i += 4;
        } else if(!strncmp(p2+i, "word", 4)) {
          i += 3;
        } else if(!strncmp(p2+i, "byte", 4)) {
          i += 3;
        } else {
          break;
        }
      }
      if(*p1 == 'X') {
        if(p2[i] == '-')
          i++;
        if(p2[i] == '0' && p2[i+1] == 'x')
          i += 2;
        while(isxdigit(p2[i]))
          i++;
        i--;
      }
      if(*p1 == 'R') {
        length = r_gadget_register_length(p2 + i, registers);
        if(length > 0) {
          i += length - 1;
        } else {
          break;
        }
      }
    } else {
      if(*p1 != p2[i])
        break;
    }
    p1++;
    i++;
  }
  if(*p1 == '\0' && (i == len || p2[i] == '\0'))
    return 1;

  return 0;
}

/* Return true if the gadget match filters */
int r_gadget_is_filter(const char *gadget, r_binfmt_arch_e arch, r_disa_flavor_e flavor) {
  const char **p_filters;
  const char **p_registers;
  int i;
  const char *p;
  int match;


  /* Check wich filter to use */
  if(arch == R_BINFMT_ARCH_X86 || arch == R_BINFMT_ARCH_X86_64) {
    p_registers = intel_registers;

    if(flavor == R_DISA_FLAVOR_INTEL) {
      p_filters = intel_filters;
    } else {
      p_filters = intel_att_filters;
    }
  } else {
    /* No filter available for this flavor/architecture : don't filter gadget */
    return 1;
  }

  while((p = strchr(gadget, ';')) != NULL) {
    match = 0;
    for(i = 0; p_filters[i] != NULL; i++) {
      if(r_gadget_filter_strncmp(gadget, p_filters[i], p_registers, p-gadget)) {
        match = 1;
      }
    }

    if(!match)
      return 0;

    gadget = p+2;
  }
  return 1;
}
