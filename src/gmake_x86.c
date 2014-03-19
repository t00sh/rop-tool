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
   This file implement functions for building custom gadgets for x86
   ======================================================================= */

/* Set register to specified value */
void gmake_x86_setreg(const GLIST *src, PAYLOAD *dst, const char *reg, addr_t value) {
  char gadget[GADGET_COMMENT_LEN];
  GADGET *g;

  snprintf(gadget, GADGET_COMMENT_LEN, "pop %s ; ret  ; ", reg);

  if((g = gfilter_search(src, gadget)) != NULL) {
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }

  snprintf(gadget, GADGET_COMMENT_LEN, "set %s to value %.8llx", reg, value);
  payload_add(dst, gadget, value);
}

/* Stack pivot */
void gmake_x86_swapstack(const GLIST *src, PAYLOAD *dst, addr_t addr) {
  char gadget[GADGET_COMMENT_LEN];
  GADGET *g;

  gmake_x86_setreg(src, dst, "ebp", addr+4);
  strcpy(gadget, "leave  ; ret  ; ");

  if((g = gfilter_search(src, gadget)) != NULL) {
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }
}

/* Set memory to specified value */
void gmake_x86_setmem(const GLIST *src, PAYLOAD *dst, addr_t addr, addr_t value) {
  char gadget[GADGET_COMMENT_LEN];
  char r1[4], r2[4];
  GADGET *g;


  strcpy(gadget, "mov  [%D], %D ; ret  ; ");
  if((g = gfilter_search(src, gadget)) != NULL) {
    strncpy(r1, g->comment+6, 3);
    strncpy(r2, g->comment+12, 3);
    r1[3] = r2[3] = '\0';

    gmake_x86_setreg(src, dst, r1, addr);
    gmake_x86_setreg(src, dst, r2, value);
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }
}

/* Copy string in memory */
void gmake_x86_strcp(const GLIST *src, PAYLOAD *dst, addr_t addr, const char *str) {
  byte_t *p = (byte_t*)str;
  int len = strlen(str);
  addr_t cur = addr;

  while(len >= 4) {
    gmake_x86_setmem(src, dst, cur, *((uint32_t*)p));
    len -= 4;
    p += 4;
    cur += 4;
  }

  switch(len) {
  case 3:
    gmake_x86_setmem(src, dst, cur, (p[2] << 16) | (p[1] << 8) | p[0]);
    break;
  case 2:
    gmake_x86_setmem(src, dst, cur, (p[1] << 8) | p[0]);
    break;
  case 1:
    gmake_x86_setmem(src, dst, cur, p[0]);
    break;
  case 0:
    gmake_x86_setmem(src, dst, cur, 0);
  }
}

/* Call syscall */
void gmake_x86_syscall(const GLIST *src, PAYLOAD *dst) {
  char gadget[GADGET_COMMENT_LEN];
  GADGET *g;

  strcpy(gadget, "int 0x80 ; ret  ; ");

  if((g = gfilter_search(src, gadget)) != NULL) {
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }
}
