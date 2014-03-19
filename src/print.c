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
   This file implement functions for printing some objects (slist, glist,
   payloads...)
   ======================================================================= */

/* Macro for printing colored string */
#define PRINT(c,...) do {			\
    if(options_color) {				\
      printf(c);				\
      printf(__VA_ARGS__);			\
      printf(COLOR_RESET);			\
    } else {					\
      printf(__VA_ARGS__);			\
    }						\
  }while(0);

/* =========================================================================
   ======================================================================= */

/* Format the addr_t NON REENTRENT function */
static const char* format_addr(addr_t addr) {
  static char format[20];

  if(addr > 0xFFFFFFFF && addr != NOT_FOUND)
    sprintf(format, "0x%.16llx", addr);
  else
    sprintf(format, "0x%.8x", (uint32_t)addr);

  return format;
}

/* Print a gadget */
static void print_gadget(GADGET *g) {

  PRINT(COLOR_BLACK COLOR_BG_WHITE, format_addr(g->addr));
  PRINT(COLOR_WHITE COLOR_BG_BLACK, " -> ");
  PRINT(COLOR_GREEN COLOR_BG_BLACK, "%s\n", g->comment);
}

/* Print a Glist */
void print_glist(GLIST *glist) {
  glist_foreach(glist, print_gadget);
  printf("\n  *** %d gadgets found ***\n\n", glist_size(glist));
}

/* =========================================================================
   ======================================================================= */

/* Print a string */
static void print_string(STRING *s) {
  PRINT(COLOR_BLACK COLOR_BG_WHITE, format_addr(s->addr));
  PRINT(COLOR_WHITE COLOR_BG_BLACK, " -> ");
  
  if(s->addr == NOT_FOUND) {
    PRINT(COLOR_RED COLOR_BG_BLACK, "%s\n", s->string);
  } else {
    PRINT(COLOR_GREEN COLOR_BG_BLACK, "%s\n", s->string);
  }
}

/* Print a Slist */
void print_slist(SLIST *slist) {
  slist_foreach(slist, print_string);
}

/* =========================================================================
   ======================================================================= */

/* PERL */
void print_payload_start_perl(void) {
  PRINT(COLOR_RED COLOR_BG_BLACK, "#!/usr/bin/perl\n\n");
  PRINT(COLOR_MAGENTA COLOR_BG_BLACK, "use strict;\n");
  PRINT(COLOR_MAGENTA COLOR_BG_BLACK, "use warnings;\n\n");
  PRINT(COLOR_GREEN COLOR_BG_BLACK, "my $payload;\n\n");
}

void print_payload_part_perl(GADGET *g) {
  PRINT(COLOR_RED COLOR_BG_BLACK, "$payload");
  PRINT(COLOR_WHITE COLOR_BG_BLACK, " .= ");
  PRINT(COLOR_YELLOW COLOR_BG_BLACK, "pack('L', %s);", format_addr(g->addr));
  if(g->addr == NOT_FOUND) {
    PRINT(COLOR_RED COLOR_BG_BLACK," # %s\n", g->comment);
  } else {
    PRINT(COLOR_GREEN COLOR_BG_BLACK," # %s\n", g->comment);
  }
}

/* =========================================================================
   ======================================================================= */

/* Print the beginning of the payload */
void print_payload_start(void) {
  if(options_output == OUTPUT_PERL)
    print_payload_start_perl();
}

/* Finish the payload */
void print_payload_end(void) {
}

/* Print a gadget */
void print_payload_part(GADGET *g) {
  if(options_output == OUTPUT_PERL)
    print_payload_part_perl(g);
}

/* Print a payload */
void print_payload(PAYLOAD *payload) {
  print_payload_start();
  payload_foreach(payload, print_payload_part);
  print_payload_end();
}
