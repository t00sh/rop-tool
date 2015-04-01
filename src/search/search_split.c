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
#include "rop_search.h"



int search_print_bytes_in_mem(r_binfmt_s *bin, byte_t *bytes, u64 len) {
  r_binfmt_mem_s *m;
  r_utils_bytes_s b;
  char *string;
  u64 off;
  byte_t *ptr;
  char flag_str[4];

  for(m = bin->mlist->head; m != NULL; m = m->next) {
    if(m->flags & R_BINFMT_MEM_FLAG_PROT_R) {
      if((ptr = r_utils_memsearch(m->start, m->length, bytes, len)) != NULL) {
	off = ptr - m->start;
	b.bytes = bytes;
	b.len = len;
	string = r_utils_bytes_hexlify(&b);
	r_binfmt_get_mem_flag_str(flag_str, m);
	R_UTILS_PRINT_BLACK_BG_WHITE(search_options_color, " %s ", flag_str);
	R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %.16" PRIx64 " ", m->addr + off);
	R_UTILS_PRINT_WHITE_BG_BLACK(search_options_color, "-> ");
	R_UTILS_PRINT_RED_BG_BLACK(search_options_color, "%s\n", string);
	free(string);
	return 1;
      }
    }
  }

  return 0;
}
void search_print_split_rec(r_binfmt_s *bin, byte_t *bytes, u64 len) {
  u64 max_len;

  if(!len)
    return;

  max_len = len;

  while(max_len && !search_print_bytes_in_mem(bin, bytes, max_len)) {
    if(max_len == 1) {
      R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %.16" PRIx64 " ", R_BINFMT_BAD_ADDR);
      R_UTILS_PRINT_WHITE_BG_BLACK(search_options_color, "-> ");
      R_UTILS_PRINT_BLACK_BG_WHITE(search_options_color, "\\x%2x (NOT FOUND)\n", *bytes);
      return;
    }

    max_len--;
  }

  search_print_split_rec(bin, bytes+max_len, len-max_len);
}

void search_print_split_string_in_bin(r_binfmt_s *bin, r_utils_bytes_s *bytes) {
  search_print_split_rec(bin, bytes->bytes, bytes->len);
}
