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
   ======================================================================= */

static void print_addr(addr_t addr) {
  if(addr > 0xFFFFFFFF && addr != NOT_FOUND)
    printf("0x%.8llx", addr);
  else
    printf("0x%.8x", (uint32_t)addr);
}

/* print a gadget */
static void print_gadget(GADGET *g) {

  if(options_color) {
    printf(COLOR_BLACK COLOR_BG_WHITE);
    print_addr(g->addr);
    printf(COLOR_RESET 
	   "  ->  " 
	   "%s%s" COLOR_RESET "\n", 
	   g->addr == NOT_FOUND ? COLOR_RED : COLOR_GREEN,
	   g->comment);
  } else {
    print_addr(g->addr);
    printf("  ->  %s %s\n", 
	   g->comment,
	   g->addr == NOT_FOUND ? "(NOT FOUND)" : "");
  }
}

/* print a gadget list */
void print_glist(GLIST *glist) {
  glist_foreach(glist, print_gadget);
  printf("\n  *** %d gadgets found ***\n\n", glist_size(glist));
}

/* =========================================================================
   ======================================================================= */

static void print_string(STRING *s) {
  if(options_color) {
    printf(COLOR_BLACK COLOR_BG_WHITE);
    print_addr(s->addr);
    printf(COLOR_RESET 
	   "  ->  " 
	   "%s%s" COLOR_RESET "\n",
	   s->addr == NOT_FOUND ? COLOR_RED : COLOR_GREEN,
	   s->string);

  } else {
    print_addr(s->addr);
    printf("  ->  %s %s\n", 
	   s->string, 
	   s->addr == NOT_FOUND ? "(NOT FOUND)" : "");
  }
}

void print_slist(SLIST *slist) {
  slist_foreach(slist, print_string);
  printf("\n  *** %d strings found ***\n\n", slist_size(slist));
}

/* =========================================================================
   ======================================================================= */

void print_payload(PAYLOAD *payload) {
  payload_foreach(payload, print_gadget);
  printf("\n  *** %d gadgets found ***\n\n", payload_size(payload));
}
