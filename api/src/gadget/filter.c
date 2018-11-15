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
#include "gadget.h"

/* =========================================================================
   This file implement functions for filter and matching gadgets
   ======================================================================= */

typedef struct r_filter {
  r_binfmt_arch_e arch;
  r_disa_flavor_e flavor;
  const char **filters;
  const char **filters_end;
  const char **registers;
} r_filter_t;

static r_filter_t r_filter_list[] = {
  { /* intel x86 intel */
    R_BINFMT_ARCH_X86, R_DISA_FLAVOR_INTEL,
    r_filter_x86, r_filter_x86_end, r_filter_x86_registers
  },
  { /* intel x86 AT&T */
    R_BINFMT_ARCH_X86, R_DISA_FLAVOR_ATT,
    r_filter_x86_att, r_filter_x86_att_end, r_filter_x86_registers
  },
  { /* intel x86-64 intel */
    R_BINFMT_ARCH_X86_64, R_DISA_FLAVOR_INTEL,
    r_filter_x86, r_filter_x86_end, r_filter_x86_registers
  },
  { /* intel x86-64 AT&T */
    R_BINFMT_ARCH_X86_64, R_DISA_FLAVOR_ATT,
    r_filter_x86_att, r_filter_x86_att_end, r_filter_x86_registers
  },
  { /* ARM  */
    R_BINFMT_ARCH_ARM, R_DISA_FLAVOR_UNDEF,
    r_filter_arm, r_filter_arm_end, r_filter_arm_registers
  },
  { /* ARM64  */
    R_BINFMT_ARCH_ARM64, R_DISA_FLAVOR_UNDEF,
    r_filter_arm64, r_filter_arm64_end, r_filter_arm64_registers
  },
  { /* MIPS */
    R_BINFMT_ARCH_MIPS, R_DISA_FLAVOR_UNDEF,
    r_filter_mips, r_filter_mips_end, r_filter_mips_registers
  },

  {
    R_BINFMT_ARCH_UNDEF, R_DISA_FLAVOR_UNDEF, NULL, NULL, NULL
  }
};

static int r_gadget_register_length(const char *string, const char **registers) {
  size_t i;

  for(i = 0; registers[i] != NULL; i++) {
    if(!strncmp(string, registers[i], strlen(registers[i])))
      return strlen(registers[i]);
  }
  return 0;
}

/* Return true if the instruction match the filter
 * %X : hexadecimal or decimal value
 * %R : register
 * %C : caracter
 * %W : qword, dword, word, byte
 * %S : - or +
 * %% : '%' char
 */
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

/*
 * Return 0 -> reject gadget
 * Return 1 -> accept gadget unfiltered
 * Return 2 -> accept gadget filtered
 */
int r_gadget_is_filter(const char *gadget, r_binfmt_arch_e arch,
                       r_disa_flavor_e flavor) {
  const char **p_filters = NULL;
  const char **p_filters_end = NULL;
  const char **p_registers = NULL;
  int i, is_end, match;
  const char *p;

  for(i = 0; r_filter_list[i].arch != R_BINFMT_ARCH_UNDEF; i++) {
    if(r_filter_list[i].arch == arch &&
       (r_filter_list[i].flavor == flavor ||
        flavor == R_DISA_FLAVOR_UNDEF)) {
      p_filters = r_filter_list[i].filters;
      p_filters_end = r_filter_list[i].filters_end;
      p_registers = r_filter_list[i].registers;
      break;
    }
  }

  if(p_filters == NULL) {
    return 0;
  }

  match = 1;
  is_end = 0;

  while((p = strchr(gadget, ';')) != NULL) {
    is_end = 0;
    for(i = 0; p_filters_end[i] != NULL; i++) {
      if(r_gadget_filter_strncmp(gadget, p_filters_end[i], p_registers, p-gadget)) {
        is_end = 1;
        break;
      }
    }

    if(p_filters_end[i] == NULL) {
      for(i = 0; p_filters[i] != NULL; i++) {
        if(r_gadget_filter_strncmp(gadget, p_filters[i], p_registers, p-gadget)) {
          break;
        }
      }
      if(p_filters[i] == NULL) {
        match = 0;
      }
    }

    gadget = p+2;
  }

  if(!is_end) {
    return 0;
  }
  return is_end + match;
}
