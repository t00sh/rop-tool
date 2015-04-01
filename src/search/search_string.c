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

void search_print_string(r_binfmt_mem_s *mem, r_utils_bytes_s *bytes) {
   char flag_str[4];
   u64 i;
   int found = 0;
   char *string;

   r_binfmt_get_mem_flag_str(flag_str, mem);

   if(mem->length >= bytes->len) {
     for(i = 0; i < mem->length - bytes->len; i++) {
       if(!memcmp(mem->start+i, bytes->bytes, bytes->len)) {
	 string = r_utils_bytes_hexlify(bytes);

	 R_UTILS_PRINT_BLACK_BG_WHITE(search_options_color, " %s ", flag_str);
	 R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %.16" PRIx64 " ", (mem->addr + i));
	 R_UTILS_PRINT_WHITE_BG_BLACK(search_options_color, "-> ");
	 R_UTILS_PRINT_RED_BG_BLACK(search_options_color, "%s\n", string);

	 free(string);
	 found++;
       }
     }
   }
   R_UTILS_PRINT_YELLOW_BG_BLACK(search_options_color, " %d strings found.\n", found);
}

void search_print_string_in_bin(r_binfmt_s *bin, r_utils_bytes_s *bytes) {
  r_binfmt_mem_s *m;

  for(m = bin->mlist->head; m; m = m->next) {
    if(m->flags & R_BINFMT_MEM_FLAG_PROT_R)
      search_print_string(m, bytes);
  }
}
