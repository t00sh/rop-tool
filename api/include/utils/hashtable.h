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

#ifndef DEF_API_UTILS_HASHTABLE_H
#define DEF_API_UTILS_HASHTABLE_H

typedef struct r_utils_hash_elem {
  void *val;
  u8 *key;
  u32 key_len;
  struct r_utils_hash_elem *next;
}r_utils_hash_elem_s;

typedef struct r_utils_hash {
  r_utils_hash_elem_s **elems;
  u32 size;
  u32 colisions;
  void (*elem_destructor)(void*);
	size_t entries;
}r_utils_hash_s;


void r_utils_hash_foreach(r_utils_hash_s *h, void (*callback)(r_utils_hash_elem_s*));
void r_utils_hash_free(r_utils_hash_s **h);
r_utils_hash_elem_s* r_utils_hash_elem_new(void *elem, u8 *key, u32 key_len);
r_utils_hash_s* r_utils_hash_new(size_t entries, void(*destructor)(void*));
void r_utils_hash_insert(r_utils_hash_s *h, r_utils_hash_elem_s *elem);
r_utils_hash_elem_s* r_utils_hash_find_elem(const r_utils_hash_s *h, int (*cmp)(r_utils_hash_elem_s*, const void*), const void *user);
int r_utils_hash_elem_exist(r_utils_hash_s *h, u8 *key, u32 key_len);
u32 r_utils_hash_size(r_utils_hash_s *h);


#endif
