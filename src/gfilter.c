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
   This file implement functions for filter and matching gadgets
   ======================================================================= */

/*
 * %X  : hexadécimal value
 * %Q : qword (64bits) register (rax, rbx, rcx, rdx, rsi, rdi, rsp);
 * %D : dword (32bits) register (eax, ebx, ecx, edx, esi, edi, esp, ebp)
 * %W : word (16bits) register (ax, bx, cx, dx, si, di)
 * %B : byte (8bits) register (al, bl, cl, dl)
 * %% : '%' char
 */

static const char *intel_x86_filters[] = {
  "pop %D",
  "popa",

  "push %D",
  "pusha",

  "add %D, dword ptr [%X]",
  "add %D, dword ptr [%D + %X]",
  "add %D, dword ptr [%D - %X]",
  "add %D, dword ptr [%D]",
  "add %D, %X",
  "add %D, %D",
  "add dword ptr [%D], %D",
  "add dword ptr [%D + %X], %D",
  "add dword ptr [%D - %X], %D",

  "int %X",
  "call %D",
  "call dword ptr [%D]",
  "jmp dword ptr [%D]",
  "jmp %D",

  "mov %D, %D",
  "mov dword ptr [%D + %X], %D",
  "mov dword ptr [%D - %X], %D",
  "mov dword ptr [%D], %D",
  "mov %D, dword ptr [%D]",
  "mov %D, dword ptr [%D + %X]",
  "mov %D, dword ptr [%D - %X]",
  "mov %b, %b",

  "add byte ptr [%D], %B",
  "add byte ptr [%D + %X], %B",
  "add byte ptr [%D - %X], %B",

  "xchg %D, %D",

  "inc %D",
  "inc %W",
  "inc %B",

  "dec %D",
  "dec %W",
  "dec %B",

  "leave ",
  "ret ",
  NULL
};

static const char *intel_x86_64_filters[] = {
  "pop %D",
  "pop %Q",
  "popa",

  "push %D",
  "push %Q",
  "pusha",

  "add %D, dword ptr [%X]",
  "add %D, dword ptr [%D + %X]",
  "add %D, dword ptr [%D - %X]",
  "add %D, dword ptr [%D]",
  "add %D, %X",
  "add %D, %D",
  "add dword ptr [%D], %D",
  "add dword ptr [%D + %X], %D",
  "add dword ptr [%D - %X], %D",

  "add %Q, dword ptr [%X]",
  "add %Q, qword ptr [%Q+%X]",
  "add %Q, qword ptr [%Q - %X]",
  "add %Q, qword ptr [%Q]",
  "add %Q, %X",
  "add %Q, %Q",
  "add qword ptr [%Q], %Q",
  "add qword ptr [%Q + %X], %Q",
  "add qword ptr [%Q - %X], %Q",

  "int %X",
  "call %D",
  "call %Q",
  "call dword ptr [%D]",
  "call qword ptr [%Q]",
  "jmp dword ptr [%D]",
  "jmp qword ptr [%Q]",
  "jmp %D",
  "jmp %Q",

  "mov %D, %D",
  "mov dword ptr [%D + %X], %D",
  "mov dword ptr [%D - %X], %D",
  "mov dword ptr [%D], %D",
  "mov %D, dword ptr [%D]",
  "mov %D, dword ptr [%D + %X]",
  "mov %D, dword ptr [%D - %X]",

  "mov %Q, %Q",
  "mov qword ptr [%Q + %X], %Q",
  "mov qword ptr [%Q - %X], %Q",
  "mov qword ptr [%Q], %Q",
  "mov %Q, qword ptr [%Q]",
  "mov %Q, qword ptr [%Q + %X]",
  "mov %Q, qword ptr [%Q - %X]",

  "mov %B, %B",

  "add byte ptr [%D], %B",
  "add byte ptr [%D + %X], %B",
  "add byte ptr [%D - %X], %B",

  "add byte ptr [%Q], %B",
  "add byte ptr [%Q + %X], %B",
  "add byte ptr [%Q - %X], %B",

  "xchg %D, %D",
  "xchg %Q, %Q",

  "inc %Q",
  "inc %D",
  "inc %W",
  "inc %B",

  "dec %Q",
  "dec %D",
  "dec %W",
  "dec %B",

  "syscall ",
  "leave ",
  "ret ",
  NULL
};

static const char *att_x86_filters[] = {
  "popl %%%D",
  "popa",

  "pushl %%%D",
  "pusha",

  "addl %%%D, (%%%D)",
  "addl %%%D, $%X",
  "addl %%%D, %%%D",
  "addl %%%D, (%%%D)",

  "intb $%X",
  "calll *(%%%D)",
  "jmpl *(%%%D)",

  "mov %%%D, %%%D",
  "movl %%%D, (%%%D)",
  "mov (%%%D), %%%D",
  "movb %%%b, %%%b",

  "xchg %%%D, %%%D",

  "incl %%%D",
  "incb %%%b",

  "decl %%%D",
  "decb %%%b",

  "leavel ",
  "retl ",
  NULL
};

/* Return true if the instruction match the filter */
static int gfilter_strcmp(char *instr, const char *filter) {
  const char *p1 = filter;
  char *p2 = instr;

  while(*p1 != '\0' && *p2 != '\0') {
    if(*p1 == '%') {

      p1++;
      if(*p1 == '%') {
	if(*p2 != '%')
	  break;
      }
      if(*p1 == 'X') {
	if(*p2 != '0')
	  break;
	strtoll(p2, &p2, 0);
	p2--;
      }
      if(*p1 == 'Q') {
	if(strncmp("rax", p2, 3) &&
	   strncmp("rbx", p2, 3) &&
	   strncmp("rcx", p2, 3) &&
	   strncmp("rdx", p2, 3) &&
	   strncmp("rsp", p2, 3) &&
	   strncmp("rbp", p2, 3) &&
	   strncmp("rsi", p2, 3) &&
	   strncmp("rdi", p2, 3))
	  break;
	p2 += 2;
      }
      if(*p1 == 'D') {
	if(strncmp("eax", p2, 3) &&
	   strncmp("ebx", p2, 3) &&
	   strncmp("ecx", p2, 3) &&
	   strncmp("edx", p2, 3) &&
	   strncmp("esp", p2, 3) &&
	   strncmp("ebp", p2, 3) &&
	   strncmp("esi", p2, 3) &&
	   strncmp("edi", p2, 3))
	  break;
	p2 += 2;
      }
      if(*p1 == 'W') {
	if(strncmp("ax", p2, 2) &&
	   strncmp("bx", p2, 2) &&
	   strncmp("cx", p2, 2) &&
	   strncmp("dx", p2, 2) &&
	   strncmp("di", p2, 2) &&
	   strncmp("si", p2, 2))
	  break;
	p2++;
      }

      if(*p1 == 'B') {
	if(strncmp("al", p2, 2) &&
	   strncmp("bl", p2, 2) &&
	   strncmp("cl", p2, 2) &&
	   strncmp("dl", p2, 2))
	  break;
	p2++;

      }
    } else {
      if(*p1 != *p2)
	break;
    }
    p1++;
    p2++;
  }
  if(*p1 == '\0' && *p2 == '\0')
    return 1;

  return 0;
}

/* Return true if the gadget match filters */
int gfilter_gadget(char *instr, enum BINFMT_ARCH arch) {
  const char **p_filters;
  int i;

  /* Check wich filter to use */
  if(options_flavor == FLAVOR_INTEL && arch == BINFMT_ARCH_X86) {
    p_filters = intel_x86_filters;
  }  else if(options_flavor == FLAVOR_ATT && arch == BINFMT_ARCH_X86) {
    p_filters = att_x86_filters;
  } else if(options_flavor == FLAVOR_INTEL && arch == BINFMT_ARCH_X86_64) {
    p_filters = intel_x86_64_filters;
  } else {
    /* No filter available for this flavor/architecture : don't filter gadget */
    return 1;
  }

  for(i = 0; p_filters[i] != NULL; i++) {
    if(gfilter_strcmp(instr, p_filters[i])) {
      return 1;
    }
  }
  return 0;
}

/* Compare a gadget with a filter */
static int gfilter_compare(GADGET *g, const void *user) {
  if(gfilter_strcmp(g->comment, user))
    return 1;
  return 0;
}

/* search a gadget in a glist with a filter */
GADGET* gfilter_search(const GLIST *glist, const char *gadget) {
  return glist_find(glist, gfilter_compare, gadget);
}
