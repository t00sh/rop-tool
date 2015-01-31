#include "ropc_search.h"

void search_print_numeric_in_bin(r_binfmt_s *bin, u64 n, size_t size_of) {
  r_binfmt_mem_s *mem;
  char flag_str[4];
   u64 i;
   int found = 0;
   u64 value;
   const char *format;


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

	   if(value == n) {
	     R_UTILS_PRINT_BLACK_BG_WHITE(search_options_color, " %s ", flag_str);
	     R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %.16" PRIx64 " ", (mem->addr + i));
	     R_UTILS_PRINT_WHITE_BG_BLACK(search_options_color, "-> ");
	     R_UTILS_PRINT_RED_BG_BLACK(search_options_color, format, value);
	     found++;
	   }
	 }
       }
     }
   }
   R_UTILS_PRINT_YELLOW_BG_BLACK(search_options_color, " %d values found.\n", found);
}
