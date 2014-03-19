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

/* Search the first instruction which finish a gadget, and return the offset */
static addr_t gfind_end(MEM *mem, off_t off) {
  DISASM dis;
  int len;
  len_t i;

  /* Itere the entire memory */
  for(i = off; i < mem->length; i++) {
    len = dis_instr(&dis, mem->start+i, mem->length-i, 0);

    /* Check if it's a valid instruction and a ret/call/jmp */
    if(len != UNKNOWN_OPCODE && len !=  OUT_OF_BLOCK) {
      if(dis_is_ret(&dis) || dis_is_call(&dis) || dis_is_jmp(&dis))
	return i;      
    }
  }

  return NOT_FOUND;
}

/* Get the gadget which start at <start> and finish at <end> */
static GADGET gfind_extract_gadget(MEM *mem, off_t start, off_t end, enum BINFMT_ARCH arch) {
  char buffer[GADGET_COMMENT_LEN];
  DISASM dis;
  GADGET g;
  int len;
  off_t i;
  int depth;

  /* Some inits */
  memset(buffer, 0, sizeof(buffer));
  depth = len = 0;
  g.addr = NOT_FOUND;
  
  for(i = start; i <= end; i += len) {
    len = dis_instr(&dis, mem->start + i, mem->length - i, arch);

    /* Return false if is an invalid instruction */
    if(len == UNKNOWN_OPCODE || len == OUT_OF_BLOCK)
      return g;

    /* Filter gadget if option is set */
    if(options_filter && !gfilter_gadget(dis.CompleteInstr, arch))
      return g;

    /* Concatene the instruction to the current gadget string (check overflow) */
    if(strlen(buffer) + strlen(dis.CompleteInstr) < sizeof(buffer) - 4) {
      strcat(buffer, dis.CompleteInstr);
      strcat(buffer, " ; ");
    }
    depth++;
  }

  /* Check if the last instruction is ret
     If it's a call or jmp, add to GLIST
     only if the gadget contain one instruction
     (the call or jmp) */
  if(dis_is_ret(&dis) 
     || ((dis_is_call(&dis) || dis_is_jmp(&dis))
	 && depth == 1)) {
    g.addr = mem->addr + start;
    strcpy(g.comment, buffer);
  }

  return g;
}

/* Find gadgets in memory */
static void gfind_in_mem(GLIST *glist, MEM *mem, enum BINFMT_ARCH arch) {
  addr_t end;
  addr_t i;
  addr_t start;
  GADGET g;

  end = 0;

  /* First, find the end of the next gadget */
  while((end = gfind_end(mem, end)) != NOT_FOUND) {

    /* Some checks :) */
    if(end < options_depth)
      start = 0;
    else
      start = end - options_depth;

    /* Extract gadgets between [start ; end] */
    for(i = start; i <= end; i++) {
      if(is_good_addr(mem->addr + i, &options_bad)) {
	g = gfind_extract_gadget(mem, i, end, arch);
	/* If we found a gadget and if gadget don't exist */
	if(g.addr != NOT_FOUND && !glist_exist(glist, g.comment)) {
	  glist_add(glist, &g);
	}           
      }
    }  
    end++;
  }
}

/* search gadget in binary file */
void gfind_in_bin(GLIST *glist, BINFMT *bin) {
  MEM *m;

  for(m = bin->mlist->head; m != NULL; m = m->next) {
    if(m->flags & MEM_FLAG_PROT_X)
      gfind_in_mem(glist, m, bin->arch);
  }
}

