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


MLIST* mlist_new(void) {
  MLIST *mlist;

  mlist = xcalloc(1, sizeof(MLIST)); 

  return mlist;
}

void mlist_add(MLIST *mlist, addr_t addr, byte_t *start, len_t length, uint32_t flags) {
  MEM *new;

  new = xmalloc(sizeof(MEM));

  new->addr = addr;
  new->start = start;
  new->length = length;
  new->flags = flags;

  new->next = mlist->head;

  mlist->head = new;
 
  mlist->size++;
}

void mlist_free(MLIST **mlist) {
  MEM *m, *tmp;

  m = (*mlist)->head;
  while(m != NULL) {
    tmp = m->next;
    free(m);
    m = tmp;
  }

  free(*mlist);
  *mlist = NULL;
}

void mlist_foreach(MLIST *mlist, void (*callback)(MEM*)) {
  MEM *m;

  for(m = mlist->head; m != NULL; m = m->next) {
    callback(m);
  }
}

int mlist_size(MLIST *mlist) {
  return mlist->size;
}
