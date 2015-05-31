/************************************************************************/
/* rop-tool - A Return Oriented Programming and binary exploitation     */
/*            tool                                                      */
/* 								        */
/* Copyright 2013-2015, -TOSH-					        */
/* File coded by -TOSH-						        */
/* 								        */
/* This file is part of rop-tool.	       			        */
/* 								        */
/* rop-tool is free software: you can redistribute it and/or modif      */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* rop-tool is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with rop-tool.  If not, see <http://www.gnu.org/licenses/>     */
/************************************************************************/
#include "api/binfmt.h"


/* =========================================================================
   This file contain some functions about binary symbols
   ======================================================================= */

r_binfmt_sym_s* r_binfmt_sym_new(void) {
  return r_utils_malloc(sizeof(r_binfmt_sym_s));
}

void r_binfmt_syms_free(r_binfmt_s *bin) {
  r_utils_list_free(&bin->syms, free);
}

static int r_binfmt_syms_cmp(const void* s1, const void* s2) {
  const r_binfmt_sym_s* const *_s1 = s1;
  const r_binfmt_sym_s* const *_s2 = s2;

  if((*_s1)->addr < (*_s2)->addr)
    return -1;
  if((*_s1)->addr > (*_s2)->addr)
    return 1;

  return 0;
}

/* Dichotomy research - symbols must be sorted in ascending order */
const char* r_binfmt_get_sym_by_addr(r_binfmt_s *bin, addr_t addr) {
  size_t start, end, cur;
  r_binfmt_sym_s *sym;

  if(addr == 0)
    return NULL;

  if(bin->syms.head == 0)
    return NULL;

  start = 0;
  end = bin->syms.head-1;

  while(start <= end) {
    cur = (start + end) / 2;

    sym = r_utils_list_access(&bin->syms, cur);

    if(sym == NULL)
      break;

    if(sym->addr == addr) {
      return sym->name;
    } else if(addr > sym->addr) {
      start = cur+1;
    } else {
      if(cur == 0)
	break;
      end = cur-1;
    }
  }

  return NULL;
}

void r_binfmt_syms_sort(r_binfmt_s *bin) {
  r_utils_list_sort(&bin->syms, r_binfmt_syms_cmp);
}
