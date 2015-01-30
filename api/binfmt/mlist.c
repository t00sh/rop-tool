#include "api/binfmt.h"

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

/* ============================================================
   This file implement functions for manipulate mlist objects
   (memory segments)
   ============================================================ */

/* Allocate a mlist */
r_binfmt_mlist_s* r_binfmt_mlist_new(void) {
  return r_utils_calloc(1, sizeof(r_binfmt_mlist_s));
}

/* Add a mlist to the head */
void r_binfmt_mlist_add(r_binfmt_mlist_s *mlist, addr_t addr, byte_t *start, len_t length, u32 flags) {
  r_binfmt_mem_s *new;

  new = r_utils_malloc(sizeof(*new));

  new->addr = addr;
  new->start = start;
  new->length = length;
  new->flags = flags;

  new->next = mlist->head;

  mlist->head = new;

  mlist->size++;
}

/* Free the mlist */
void r_binfmt_mlist_free(r_binfmt_mlist_s **mlist) {
  r_binfmt_mem_s *m, *tmp;

  m = (*mlist)->head;
  while(m != NULL) {
    tmp = m->next;
    free(m);
    m = tmp;
  }

  free(*mlist);
  *mlist = NULL;
}

/* Call the callback for each element in the mlist */
void r_binfmt_mlist_foreach(r_binfmt_mlist_s *mlist, void (*callback)(r_binfmt_mem_s*)) {
  r_binfmt_mem_s *m;

  for(m = mlist->head; m != NULL; m = m->next) {
    callback(m);
  }
}

/* Return the mlist size */
int r_binfmt_mlist_size(r_binfmt_mlist_s *mlist) {
  return mlist->size;
}
