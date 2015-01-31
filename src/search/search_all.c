#include "ropc_search.h"

static void search_print_all_strings(r_binfmt_mem_s *mem) {
  u64 i;
  int cur_len;
  char flag_str[4];


  cur_len = 0;
  r_binfmt_get_mem_flag_str(flag_str, mem);

  for(i = 0; i < mem->length; i++) {
    if(isgraph(mem->start[i])) {
      cur_len++;
    } else {
      if(cur_len >= search_options_strlen) {
	R_UTILS_PRINT_BLACK_BG_WHITE(search_options_color, " %s ", flag_str);
	R_UTILS_PRINT_GREEN_BG_BLACK(search_options_color, " %.16" PRIx64 " ", (mem->addr + i) - cur_len);
	R_UTILS_PRINT_WHITE_BG_BLACK(search_options_color, "-> ");
	R_UTILS_PRINT_RED_BG_BLACK(search_options_color, "%.*s\n", cur_len, (char*)&mem->start[i-cur_len]);
      }
      cur_len = 0;
    }
  }
}

void search_print_all_string_in_bin(r_binfmt_s *bin) {
  r_binfmt_foreach_mem(bin, search_print_all_strings, R_BINFMT_MEM_FLAG_PROT_R);
}
