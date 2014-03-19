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
   This file implement functions for searching strings in a binary
   ======================================================================= */

static addr_t sfind_get_addr(MEM *mem, byte_t *start, len_t length) {
  addr_t addr;
  addr_t off, index;

  off = 0;

  do {
    index = memsearch(mem->start+off, mem->length-off, start, length);

    if(index == NOT_FOUND)
      return 0;

    addr = mem->addr + off + index;
    off += index + 1;

  }while(!is_good_addr(addr, &options_bad));

  return addr;
}

static void sfind_in_mem(SLIST *slist, MEM *mem, BLIST *blist) {
  addr_t i, j, addr;
  char *tmp;
  BLIST op;
  int found;

  for(i = 0; i < blist->length; i++) {
    found = 0;

    for(j = blist->length-i; j > 0; j--) {
      addr = sfind_get_addr(mem, blist->start+i, j);

      if(addr != 0) {
	op.start = blist->start+i;
	op.length = j;

	tmp = blist_to_opcodes(&op);
	slist_add(slist, tmp, addr);
	i += j - 1;
	found = 1;
	break;
      }
    }
    if(!found) {
      op.start = blist->start+i;
      op.length = 1;
      tmp = blist_to_opcodes(&op);
      slist_add(slist, tmp, NOT_FOUND);
    }
  }  
}

void sfind_in_bin(SLIST *slist, BINFMT *bin, BLIST *blist) {
  MEM *m;

  for(m = bin->mlist->head; m != NULL; m = m->next) {
    /* TODO: search in all +R mem */
    if(m->flags & MEM_FLAG_PROT_R && m->flags & MEM_FLAG_PROT_X)
      sfind_in_mem(slist, m, blist);
  }
}
