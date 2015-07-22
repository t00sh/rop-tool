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

static void search_print_all_strings(r_binfmt_s *bin, r_binfmt_segment_s *seg) {
  u64 i;
  int cur_len;
  char flag_str[4];
  int found = 0;
  int addr_size;

  cur_len = 0;
  r_binfmt_get_segment_flag_str(flag_str, seg);
  addr_size = r_binfmt_addr_size(bin->arch);

  for(i = 0; i < seg->length; i++) {
    if(isprint(seg->start[i])) {
      cur_len++;
    } else {
	if(cur_len >= search_options_strlen) {
	  if(!r_binfmt_is_bad_addr(search_options_bad, (seg->addr+i)-cur_len, bin->arch)) {

	    R_UTILS_PRINT_BLACK_BG_WHITE(search_options_color, " %s ", flag_str);
	    if(addr_size == 4) {
	      R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %#.8" PRIx32 " ", (u32)((seg->addr + i) - cur_len));
	    } else {
	      R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %#.16" PRIx64 " ", (seg->addr + i) - cur_len);
	    }
	    R_UTILS_PRINT_WHITE_BG_BLACK(search_options_color, "-> ");
	    R_UTILS_PRINT_RED_BG_BLACK(search_options_color, "%.*s\n", cur_len, (char*)&seg->start[i-cur_len]);
	    found++;
	  }
	}
	cur_len = 0;
    }
  }
  R_UTILS_PRINT_YELLOW_BG_BLACK(search_options_color, " %d strings found.\n", found);
}

void search_print_all_string_in_bin(r_binfmt_s *bin) {
  r_binfmt_segment_s *seg;
  size_t i, num;

  num = r_utils_list_size(&bin->segments);

  for(i = 0; i < num; i++) {

    seg = r_utils_list_access(&bin->segments, i);

    if(seg->flags & R_BINFMT_MEM_FLAG_PROT_R) {

      search_print_all_strings(bin, seg);
    }
  }
}
