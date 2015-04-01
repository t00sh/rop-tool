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
#include "api/utils.h"

/* Convert 'a' -> 10 */
int r_utils_hexchar_to_dec(int c) {
  assert((c >= '0' && c <= '9') ||
	 (c >= 'a' && c <= 'f') ||
	 (c >= 'A' && c <= 'F'));

  if(isdigit(c))
    return c - '0';
  if(c >= 'a' && c <= 'f')
    return (c - 'a') + 10;

  return (c - 'A') + 10;
}

/* Convert 10 -> 'a' */
int r_utils_dec_to_hexchar(int c) {
  assert(c >= 0 && c < 16);
  return "0123456789abcdef"[c];
}

void* r_utils_memsearch(void *src, u64 src_len, void *dst, u64 dst_len) {
  u8 *src_ptr = src;

  assert(src != NULL);
  assert(dst != NULL);

  while(src_len >= dst_len) {
    if(!memcmp(src_ptr, dst, dst_len))
      return src_ptr;
    src_ptr++;
    src_len--;
  }
  return NULL;
}
