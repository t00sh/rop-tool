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
#include "api/utils.h"

void r_utils_linklist_init(r_utils_linklist_s *l) {
  assert(l != NULL);

  l->head = NULL;
  l->tail = NULL;
  l->iterator = NULL;
  l->num = 0;
}

static r_utils_linklist_cell_s* r_utils_linklist_alloc_cell(void *e) {
  r_utils_linklist_cell_s *cell;

  cell = r_utils_malloc(sizeof(r_utils_linklist_cell_s));
  cell->next = NULL;
  cell->prev = NULL;
  cell->elem = e;

  return cell;
}

void r_utils_linklist_delete_cur(r_utils_linklist_s *l, void (*free_cb)(void*)) {
  r_utils_linklist_cell_s *cell;

  if(l->iterator != NULL) {
    cell = l->iterator;
    l->iterator = cell->next;

    if(cell->next != NULL) {
      cell->next->prev = cell->prev;
    }

    if(cell->prev != NULL) {
      cell->prev->next = cell->next;
    }

    if(l->head == cell) {
      l->head = cell->next;
    }

    if(l->tail == cell) {
      l->tail = cell->prev;
    }

    l->num--;

    if(l->num == 0) {
      l->head = l->tail = NULL;
    }

    free_cb(cell->elem);
    free(cell);
  }
}

void r_utils_linklist_push(r_utils_linklist_s *l, void *e) {
  r_utils_linklist_cell_s *cell;

  assert(l != NULL);
  assert(e != NULL);

  cell = r_utils_linklist_alloc_cell(e);

  if(l->head == NULL) {
    l->head = cell;
    l->tail = cell;
  } else {
    cell->prev = l->tail;
    l->tail->next = cell;
    l->tail = cell;
  }

  l->num++;
}

void* r_utils_list_pop(r_utils_linklist_s *l) {
  r_utils_linklist_cell_s *c;
  void *elem;

  assert(l != NULL);

  if(l->head == NULL)
    return NULL;

  c = l->tail;
  elem = c->elem;
  l->tail = c->prev;

  if(l->tail == NULL)
    l->head = NULL;

  free(c);
  l->num--;

  return elem;
}


size_t r_utils_linklist_size(r_utils_linklist_s *l) {
  assert(l != NULL);

  return l->num;
}

void r_utils_linklist_free(r_utils_linklist_s *l, void (*free_cb)(void*)) {
  r_utils_linklist_cell_s *c, *tmp;

  assert(l != NULL);

  c = l->head;
  while(c != NULL) {
    tmp = c->next;
    if(free_cb != NULL)
      free_cb(c->elem);
    free(c);
    c = tmp;
  }

  l->head = NULL;
  l->tail = NULL;
  l->iterator = NULL;
  l->num = 0;
}

void r_utils_linklist_foreach(r_utils_linklist_s *l, void (*cb)(void*)) {
  r_utils_linklist_cell_s *c;

  for(c = l->head; c != NULL; c = c->next) {
    cb(c->elem);
  }
}

void r_utils_linklist_iterator_init(r_utils_linklist_s *l) {
  l->iterator = l->head;
}

int r_utils_linklist_hasnext(r_utils_linklist_s *l) {
  return l->iterator != NULL;
}

void* r_utils_linklist_getcur(r_utils_linklist_s *l) {
  if(!r_utils_linklist_hasnext(l))
    return NULL;

  return l->iterator->elem;
}

void* r_utils_linklist_next(r_utils_linklist_s *l) {
  void *e;

  if(l->iterator == NULL)
    return NULL;

  e = l->iterator->elem;
  l->iterator = l->iterator->next;

  return e;
}
