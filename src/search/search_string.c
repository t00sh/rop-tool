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
#include "rop_search.h"

static void search_print_string(r_binfmt_s *bin, r_binfmt_segment_s *seg, r_utils_bytes_s *bytes) {
   char flag_str[4];
   u64 i;
   int found = 0;
   char *string;
   int addr_size;

   r_binfmt_get_segment_flag_str(flag_str, seg);
   addr_size = r_binfmt_addr_size(bin->arch);

   if(seg->length >= bytes->len) {
     for(i = 0; i < seg->length - bytes->len; i++) {
       if(!r_binfmt_is_bad_addr(search_options_bad, seg->addr+i, bin->arch)) {
   if(!memcmp(seg->start+i, bytes->bytes, bytes->len)) {
     string = r_utils_bytes_hexlify(bytes);

     R_UTILS_PRINT_BLACK_BG_WHITE(search_options_color, " %s ", flag_str);
     if(addr_size == 4) {
       R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %#.8" PRIx32 " ", (u32)(seg->addr + i));
     } else {
       R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %#.16" PRIx64 " ", (seg->addr + i));
     }
     R_UTILS_PRINT_WHITE_BG_BLACK(search_options_color, "-> ");
     R_UTILS_PRINT_RED_BG_BLACK(search_options_color, "%s\n", string);

     free(string);
     found++;
   }
       }
     }
   }
   R_UTILS_PRINT_YELLOW_BG_BLACK(search_options_color, " %d strings found.\n", found);
}

void search_print_string_in_bin(r_binfmt_s *bin, r_utils_bytes_s *bytes) {
  r_binfmt_segment_s *seg;


  r_utils_linklist_iterator_init(&bin->segments);

  while((seg = r_utils_linklist_next(&bin->segments)) != NULL) {

    if(seg->flags & R_BINFMT_SEGMENT_FLAG_PROT_R)
      search_print_string(bin, seg, bytes);
  }
}
