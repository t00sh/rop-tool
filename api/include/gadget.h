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
#ifndef DEF_API_GADGET_H
#define DEF_API_GADGET_H

#include "utils.h"
#include "binfmt.h"
#include "disassemble.h"

typedef struct r_gadget {
  char *gadget;
  int addr_size;
  addr_t addr;
}r_gadget_s;

typedef struct r_gadget_handle {
  r_utils_linklist_s g_list;
  r_disa_s disa;
  u32 depth;
}r_gadget_handle_s;


/* X86 filters */
extern const char *r_filter_x86_att[];
extern const char *r_filter_x86_att_end[];
extern const char *r_filter_x86[];
extern const char *r_filter_x86_end[];
extern const char *r_filter_x86_att[];
extern const char *r_filter_x86_att_end[];
extern const char *r_filter_x86_registers[];

/* ARM filters */
extern const char *r_filter_arm[];
extern const char *r_filter_arm_end[];
extern const char *r_filter_arm_registers[];
extern const char *r_filter_arm64[];
extern const char *r_filter_arm64_end[];
extern const char *r_filter_arm64_registers[];

/* gadget.c */
int r_gadget_handle_init(r_gadget_handle_s *g_handle, r_binfmt_arch_e arch, r_disa_flavor_e flavor, int depth);
void r_gadget_handle_close(r_gadget_handle_s *g_handle);
void r_gadget_update(r_gadget_handle_s *g_handle, addr_t addr, u8 *code, u32 code_size);

/* filter.c */
int r_gadget_is_filter(const char *gadget, r_binfmt_arch_e arch, r_disa_flavor_e flavor);

#endif
