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


typedef struct {
  const char *name;
  const char *comment;
  r_binfmt_arch_e arch;
  r_binfmt_endian_e endian;
  int cs_arch;
  int cs_mode;
} r_disa_arch_s;

static const r_disa_arch_s g_available_architectures[] = {
  {
    "x86", "x86 architecture",
    R_BINFMT_ARCH_X86, R_BINFMT_ENDIAN_LITTLE,
    CS_ARCH_X86, CS_MODE_32,
  },
  {
    "x86-64", "x86-64 architecture",
    R_BINFMT_ARCH_X86_64, R_BINFMT_ENDIAN_LITTLE,
    CS_ARCH_X86, CS_MODE_64,
  },
  {
    "arm", "ARM architecture",
    R_BINFMT_ARCH_ARM, R_BINFMT_ENDIAN_LITTLE,
    CS_ARCH_ARM, CS_MODE_32,
  },
  {
    "arm64", "ARM 64bits architecture",
    R_BINFMT_ARCH_ARM64, R_BINFMT_ENDIAN_LITTLE,
    CS_ARCH_ARM, CS_MODE_64,
  },
  {
    "mipsel", "MIPS 32bits little endian architecture",
    R_BINFMT_ARCH_MIPS, R_BINFMT_ENDIAN_LITTLE,
    CS_ARCH_MIPS, CS_MODE_32 | CS_MODE_LITTLE_ENDIAN,
  },
  {
    "mips", "MIPS 32bits big endian architecture",
    R_BINFMT_ARCH_MIPS, R_BINFMT_ENDIAN_BIG,
    CS_ARCH_MIPS, CS_MODE_32 | CS_MODE_BIG_ENDIAN,
  },
  {NULL, NULL, 0, 0, 0, 0}
};

void r_disa_list_architectures(void) {
  int i;

  printf("Architectures :\n");
  for(i = 0; g_available_architectures[i].name != NULL; i++) {
    printf("  - %-25s %s\n", g_available_architectures[i].name,
           g_available_architectures[i].comment);
  }
}

int r_disa_string_to_arch(const char *string, r_binfmt_arch_e *arch,
                          r_binfmt_endian_e *endian) {
  int i;

  assert(string != NULL);
  assert(arch != NULL);
  assert(endian != NULL);

  for(i = 0; g_available_architectures[i].name != NULL; i++) {
    if(!strcmp(string, g_available_architectures[i].name)) {
      *arch = g_available_architectures[i].arch;
      *endian = g_available_architectures[i].endian;
      return 1;
    }
  }
  return 0;
}

int r_disa_init(r_disa_s *dis, r_binfmt_arch_e arch,
                       r_binfmt_endian_e endian) {
  int cs_arch = 0, cs_mode = 0, i;

  for(i = 0; g_available_architectures[i].name != NULL; i++) {
    if(g_available_architectures[i].arch == arch &&
       g_available_architectures[i].endian == endian) {
      cs_arch = g_available_architectures[i].cs_arch;
      cs_mode = g_available_architectures[i].cs_mode;
      break;
    }
  }

  if(g_available_architectures[i].name == NULL)
    return 0;

  memset(dis, 0, sizeof(r_disa_s));

  if(cs_open(cs_arch, cs_mode, &dis->handle) != CS_ERR_OK) {
    return 0;
  }

  dis->arch = arch;
  dis->endian = endian;
  dis->flavor = R_DISA_FLAVOR_UNDEF;

  return 1;
}

int r_disa_set_flavor(r_disa_s *dis, r_disa_flavor_e flavor) {
  dis->flavor = flavor;
  switch(flavor) {
  case R_DISA_FLAVOR_INTEL:
    return cs_option(dis->handle, CS_OPT_SYNTAX,
                     CS_OPT_SYNTAX_INTEL) == CS_ERR_OK;
  case R_DISA_FLAVOR_ATT:
    return cs_option(dis->handle, CS_OPT_SYNTAX,
                     CS_OPT_SYNTAX_ATT) == CS_ERR_OK;
  default:
    return 1;
  }
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

/* Transform the instr list to string : [INSTR1; [INSTR2];...]
   The string is allocated with malloc, and must be freed by the caller
*/
char* r_disa_instr_lst_to_str(r_disa_s *dis) {
  char *string;
  size_t size, i;

  assert(dis != NULL);
  size = 0;

  if(dis->instr_lst.count <= 0) {
    return NULL;
  }

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
