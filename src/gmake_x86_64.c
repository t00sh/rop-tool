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
   This file implement functions for building custom gadgets for x86_64
   ======================================================================= */

/* Set register to specified value */
void gmake_x86_64_setreg(const GLIST *src, PAYLOAD *dst, const char *reg, addr_t value) {
  gmake_x86_setreg(src, dst, reg, value);
}

/* Stack pivot */
void gmake_x86_64_swapstack(const GLIST *src, PAYLOAD *dst, addr_t addr) {
  char gadget[GADGET_COMMENT_LEN];
  GADGET *g;

  gmake_x86_64_setreg(src, dst, "rbp", addr+4);
  strcpy(gadget, "leave  ; ret  ; ");

  if((g = gfilter_search(src, gadget)) != NULL) {
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }
}

/* Set memory to specified value */
void gmake_x86_64_setmem(const GLIST *src, PAYLOAD *dst, addr_t addr, addr_t value) {
  char gadget[GADGET_COMMENT_LEN];
  char r1[4], r2[4];
  GADGET *g;


  strcpy(gadget, "mov  [%Q], %Q ; ret  ; ");
  if((g = gfilter_search(src, gadget)) != NULL) {
    strncpy(r1, g->comment+6, 3);
    strncpy(r2, g->comment+12, 3);
    r1[3] = r2[3] = '\0';

    gmake_x86_64_setreg(src, dst, r1, addr);
    gmake_x86_64_setreg(src, dst, r2, value);
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }
}

/* Copy string in memory */
void gmake_x86_64_strcp(const GLIST *src, PAYLOAD *dst, addr_t addr, const char *str) {
  byte_t *p = (byte_t*)str;
  int len = strlen(str);
  addr_t cur = addr;
  addr_t val;
  int i;

  while(len >= 8) {
    gmake_x86_64_setmem(src, dst, cur, *((uint64_t*)p));
    len -= 8;
    p += 8;
    cur += 8;
  }

  val = 0;
  for(i = 0; i < len; i++) {
    val <<= 8;
    val |= p[i];
  }

  gmake_x86_64_setmem(src, dst, cur, val);
}

/* Call syscall */
void gmake_x86_64_syscall(const GLIST *src, PAYLOAD *dst) {
  char gadget[GADGET_COMMENT_LEN];
  GADGET *g;

  strcpy(gadget, "syscall  ; ret  ; ");

  if((g = gfilter_search(src, gadget)) != NULL) {
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }
}
