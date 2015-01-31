#include "ropc_search.h"



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
