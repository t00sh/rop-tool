/************************************************************************/
/* rop-tool - A Return Oriented Programming and binary exploitation     */
/*            tool                                                      */
/* 								        */
/* Copyright 2013-2015, -TOSH-					        */
/* File coded by -TOSH-						        */
/* 								        */
/* This file is part of rop-tool.	       			        */
/* 								        */
/* rop-tool is free software: you can redistribute it and/or modif      */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* rop-tool is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with rop-tool.  If not, see <http://www.gnu.org/licenses/>     */
/************************************************************************/
#include "api/gadget.h"

/* =========================================================================
   This file implement operations on r_gadget_list_s
   ======================================================================= */

void r_gadget_list_init(r_gadget_list_s *l) {
  assert(l != NULL);

  memset(l, 0, sizeof(*l));
}

void r_gadget_list_alloc(r_gadget_list_s *l, size_t n) {
  assert(l != NULL);
  assert(n > 0);

  l->num = n;
  l->list = r_utils_calloc(n, sizeof(r_gadget_s*));
}

void r_gadget_list_realloc(r_gadget_list_s *l, size_t n) {
  assert(l != NULL);
  assert(n > 0);

  l->num = n;
  l->list = r_utils_realloc(l->list, n*sizeof(r_gadget_s*));
}

void r_gadget_list_push(r_gadget_list_s *l, r_gadget_s *g) {
  assert(l != NULL);
  assert(g != NULL);

  if(l->head >= l->num) {
    r_gadget_list_realloc(l, l->num+1);
  }

  l->list[l->head++] = g;
}

r_gadget_s* r_gadget_list_pop(r_gadget_list_s *l) {
  r_gadget_s *g;

  assert(l != NULL);

  if(l->head == 0) {
    g = NULL;
  } else {
    g = l->list[--l->head];
  }

  return g;
}

void r_gadget_list_free(r_gadget_list_s *l) {
  assert(l != NULL);

  if(l->num > 0)
    free(l->list);
}
