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
   This file implement functions for manipulate payloads
   ======================================================================= */

typedef struct PAYLOAD_INFO {
  const char *name;
  void (*make)(BINFMT*, const GLIST*, PAYLOAD*);
  enum BINFMT_ARCH arch;
  const char *descr;  
}PAYLOAD_INFO;


/* ALL payloads */
static PAYLOAD_INFO payloads[] = {
  {"x86-linux-bin-sh", payload_x86_execve_bin_sh, BINFMT_ARCH_X86, "execve(\"/bin/sh\") with <int 0x80> instruction"},
  {"x86_64-linux-bin-sh", payload_x86_64_execve_bin_sh, BINFMT_ARCH_X86_64, "execve(\"/bin/sh\") with <int 0x80> instruction"},
  {NULL, NULL, 0, NULL}
};


/* List available payloads (--list option) */
void payload_list(void) {
  int i;

  for(i = 0; payloads[i].name != NULL; i++) {
    if(options_color)
      printf("  * " COLOR_RED "%-20s " COLOR_GREEN "%s" COLOR_RESET "\n", payloads[i].name, payloads[i].descr);
    else
      printf("  * %-20s %s\n", payloads[i].name, payloads[i].descr);
  }
}

/* Build a payload */
void payload_make(BINFMT *bin, const GLIST *src, PAYLOAD *dst, const char *payload) {
  int i;

  for(i = 0; payloads[i].name != NULL; i++) {
    if(!strcmp(payloads[i].name, payload)) {
      if(payloads[i].arch != bin->arch)
	FATAL_ERROR("%s generator is not for this architecture !", payload);
      payloads[i].make(bin, src, dst);
      return;
    }
  }
  FATAL_ERROR("Bad payload generator <%s> !", payload);
}

/* =========================================================================
   ======================================================================= */

/* Allocate a payload */
PAYLOAD* payload_new(void) {
  PAYLOAD *payload;

  payload = xcalloc(1, sizeof(PAYLOAD)); 

  return payload;
}

/* Add a gadget to the tail */
void payload_add(PAYLOAD *payload, const char *comment, addr_t addr) {
  GADGET *new;

  new = xmalloc(sizeof(GADGET));

  strcpy(new->comment, comment);
  new->addr = addr;
  new->next = NULL;

  if(payload->tail != NULL) {
   payload->tail->next = new;
  }
  payload->tail = new;

  if(payload->head == NULL) {
    payload->head = new;
  }
 
  payload->size++;
}

/* Free the payload */
void payload_free(PAYLOAD **payload) {
  GADGET *g, *tmp;

  g = (*payload)->head;
  while(g != NULL) {
    tmp = g->next;
    free(g);
    g = tmp;
  }

  free(*payload);
  *payload = NULL;
}

/* Call the callback for each gadget contained in the payload */
void payload_foreach(PAYLOAD *payload, void (*callback)(GADGET*)) {
  GADGET *g;

  for(g = payload->head; g != NULL; g = g->next) {
    callback(g);
  }
}

/* Return the payload size */
int payload_size(PAYLOAD *payload) {
  return payload->size;
}
