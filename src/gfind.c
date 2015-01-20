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
   This file implement function for finding gadget in binary
   ======================================================================= */

/* Get the gadget composed of <count> instructions which start at <start> */
static GADGET gfind_extract_gadget(MEM *mem, off_t start, size_t count, DIS *dis) {
  char buffer[GADGET_COMMENT_LEN];
  char cur_gadget[GADGET_COMMENT_LEN];
  GADGET g;
  INSTR *instr;

  /* Some inits */
  memset(buffer, 0, sizeof(buffer));
  g.addr = NOT_FOUND;


  count = dis_code(dis, mem->start + start, mem->length - start, mem->addr, count);

  if(dis_end_is_ret(dis) || ((dis_end_is_call(dis) || dis_end_is_jmp(dis)) && count == 1)) {

    while(dis_next_instr(dis, &instr)) {
      snprintf(cur_gadget, GADGET_COMMENT_LEN, "%s %s", instr->mnemonic, instr->op_str);

      if(options_filter && !gfilter_gadget(cur_gadget, dis->arch))
	return g;

      if(strlen(cur_gadget) + strlen(buffer) + 4 < GADGET_COMMENT_LEN) {
	strcat(buffer, cur_gadget);
	strcat(buffer, " ; ");
      }
    }

    g.addr = mem->addr + start;
    strcpy(g.comment, buffer);
  }

  return g;
}

/* Find gadgets in memory */
static void gfind_in_mem(GLIST *glist, MEM *mem, DIS *dis) {
  addr_t start;
  GADGET g;
  int i;

  for(start = 0; start < mem->length; start++) {
    for(i = 1; i <= options_depth; i++) {

      if(is_good_addr(mem->addr + start, &options_bad)) {
	g = gfind_extract_gadget(mem, start, i, dis);

	/* If we found a gadget and if gadget don't exist */
	if(g.addr != NOT_FOUND && !glist_exist(glist, g.comment)) {
	  glist_add(glist, &g);
	}
      }
    }
  }
}

/* search gadget in binary file */
void gfind_in_bin(GLIST *glist, BINFMT *bin) {
  MEM *m;
  DIS dis;

  if(!dis_init(&dis, bin->arch)) {
    fprintf(stderr, "[-] Can't init the disassembler.\n");
    exit(EXIT_FAILURE);
  }

  for(m = bin->mlist->head; m != NULL; m = m->next) {
    if(m->flags & MEM_FLAG_PROT_X)
      gfind_in_mem(glist, m, &dis);
  }

  dis_close(&dis);
}
