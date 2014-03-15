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


/* Alloc a new SLIST object */
SLIST* slist_new(void) {
  SLIST *slist;

  slist = xcalloc(1, sizeof(SLIST)); 

  return slist;
}

/* Add a new element to the tail */
void slist_add(SLIST *slist, char *string, addr_t addr) {
  STRING *new;

  new = xmalloc(sizeof(STRING));

  new->string = string;
  new->addr = addr;
  new->next = NULL;

  if(slist->tail != NULL) {
    slist->tail->next = new;
  }
  slist->tail = new;

  if(slist->head == NULL) {
    slist->head = new;
  }
 
  slist->size++;
}

void slist_free(SLIST **slist) {
  STRING *s, *tmp;

  s = (*slist)->head;
  while(s != NULL) {
    tmp = s->next;
    free(s->string);
    free(s);
    s = tmp;
  }

  free(*slist);
  *slist = NULL;
}

void slist_foreach(SLIST *slist, void (*callback)(STRING*)) {
  STRING *s;

  for(s = slist->head; s != NULL; s = s->next) {
    callback(s);
  }
}

int slist_size(SLIST *slist) {
  return slist->size;
}
