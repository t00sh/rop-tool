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

#ifndef DEF_API_UTILS_LINKLIST_H
#define DEF_API_UTILS_LINKLIST_H

typedef struct r_utils_linklist_cell {
	void *elem;
	struct r_utils_linklist_cell *next;
	struct r_utils_linklist_cell *prev;
}r_utils_linklist_cell_s;

typedef struct {
	r_utils_linklist_cell_s *head;
	r_utils_linklist_cell_s *tail;
	r_utils_linklist_cell_s *iterator;
	size_t num;
}r_utils_linklist_s;

void r_utils_linklist_init(r_utils_linklist_s *l);
void r_utils_linklist_push(r_utils_linklist_s *l, void *e);
void* r_utils_linklist_pop(r_utils_linklist_s *l);
size_t r_utils_linklist_size(r_utils_linklist_s *l);
void r_utils_linklist_free(r_utils_linklist_s *l, void (*free_cb)(void*));
void r_utils_linklist_sort(r_utils_linklist_s *l, int (*cmp)(const void*, const void*));
void r_utils_linklist_foreach(r_utils_linklist_s *l, void (*cb)(void*));
void r_utils_linklist_iterator_init(r_utils_linklist_s *l);
void* r_utils_linklist_next(r_utils_linklist_s *l);
int r_utils_linklist_hasnext(r_utils_linklist_s *l);
void r_utils_linklist_delete_cur(r_utils_linklist_s *l, void (*free_cb)(void*));
void* r_utils_linklist_getcur(r_utils_linklist_s *l);


#endif
