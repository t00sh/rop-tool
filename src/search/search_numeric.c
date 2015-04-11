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

void search_print_numeric_in_bin(r_binfmt_s *bin, u64 n, size_t size_of) {
  r_binfmt_mem_s *mem;
  char flag_str[4];
   u64 i;
   int found = 0;
   u64 value;
   int addr_size;
   const char *format;


   addr_size = r_binfmt_addr_size(bin->arch);

   for(mem = bin->mlist->head; mem; mem = mem->next) {
     if(mem->flags & R_BINFMT_MEM_FLAG_PROT_R) {
       r_binfmt_get_mem_flag_str(flag_str, mem);

       if(mem->length >= size_of) {
	 for(i = 0; i < mem->length - size_of; i += size_of) {
	   if(size_of == 1) {
	     value = mem->start[i];
	     format = " %#.2x \n";
	   } else if(size_of == 2) {
	     value = r_binfmt_get_int16(mem->start+i, bin->endian);
	     format = " %#.4x \n";
	   } else if(size_of == 4) {
	     value = r_binfmt_get_int32(mem->start+i, bin->endian);
	     format = " %#.8x \n";
	   } else {
	     value = r_binfmt_get_int64(mem->start+i, bin->endian);
	     format = " %.16" PRIx64 " \n";
	   }

	   if(!r_binfmt_is_bad_addr(search_options_bad, mem->addr+i, bin->arch)) {
	     if(value == n) {
	       R_UTILS_PRINT_BLACK_BG_WHITE(search_options_color, " %s ", flag_str);
	       if(addr_size == 4) {
		 R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %#.8" PRIx32 " ", (u32)(mem->addr + i));
	       } else {
		 R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %#.16" PRIx64 " ", (mem->addr + i));
	       }
	       R_UTILS_PRINT_WHITE_BG_BLACK(search_options_color, "-> ");
	       R_UTILS_PRINT_RED_BG_BLACK(search_options_color, format, value);
	       found++;
	     }
	   }
	 }
       }
     }
   }
   R_UTILS_PRINT_YELLOW_BG_BLACK(search_options_color, " %d values found.\n", found);
}
