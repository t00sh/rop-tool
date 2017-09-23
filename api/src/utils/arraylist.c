/************************************************************************/
/* rop-tool - A Return Oriented Programming and binary exploitation     */
/*            tool                                                      */
/*                                                                      */
/* Copyright 2013-2015, -TOSH-                                          */
/* File coded by -TOSH-                                                 */
/*                                                                      */
/* This file is part of rop-tool.                                       */
/*                                                                      */
/* rop-tool is free software: you can redistribute it and/or modify     */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.                                  */
/*                                                                      */
/* rop-tool is distributed in the hope that it will be useful,          */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.                         */
/*                                                                      */
/* You should have received a copy of the GNU General Public License    */
/* along with rop-tool.  If not, see <http://www.gnu.org/licenses/>     */
/************************************************************************/
#include "utils.h"

void r_utils_arraylist_init(r_utils_arraylist_s *l, size_t nelem) {
  assert(l != NULL);
  assert(nelem > 0);

  memset(l, 0, sizeof(*l));

  l->list = r_utils_realloc(l->list, nelem*sizeof(void*));
  l->num = nelem;
}

void r_utils_arraylist_push(r_utils_arraylist_s *l, void *e) {
  assert(l != NULL);
  assert(e != NULL);

  if(l->head >= l->num) {
    l->list = r_utils_realloc(l->list, (l->num)*2*sizeof(void*));
    l->num = (l->num)*2;
  }

  l->list[l->head++] = e;
}

void* r_utils_arraylist_pop(r_utils_arraylist_s *l) {
  assert(l != NULL);

  if(l->head == 0)
    return NULL;

  return l->list[--l->head];
}

void *r_utils_arraylist_access(r_utils_arraylist_s *l, size_t i) {
  assert(l != NULL);

  if(i >= l->head)
    return NULL;

  return l->list[i];
}

size_t r_utils_arraylist_size(r_utils_arraylist_s *l) {
  assert(l != NULL);

  return l->head;
}

void r_utils_arraylist_free(r_utils_arraylist_s *l, void (*free_cb)(void*)) {
  size_t i;

  assert(l != NULL);

  if(free_cb != NULL) {
    for(i = 0; i < l->head; i++) {
      free_cb(l->list[i]);
    }
  }
  free(l->list);
  l->list = NULL;
  l->head = 0;
  l->num = 0;
}

void r_utils_arraylist_sort(r_utils_arraylist_s *l, int (*cmp)(const void*, const void*)) {
  assert(l != NULL);
  assert(cmp != NULL);

  if(l->head > 0)
    qsort(l->list, l->head, sizeof(void*), cmp);
}

void r_utils_arraylist_foreach(r_utils_arraylist_s *l, void (*cb)(void*)) {
  size_t i;

  for(i = 0; i < l->head; i++) {
    cb(r_utils_arraylist_access(l, i));
  }
}
