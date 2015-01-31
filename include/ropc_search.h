#ifndef DEF_ROPC_SEARCH_H
#define DEF_ROPC_SEARCH_H

#include "api/ropc.h"


typedef enum search_mode {
  SEARCH_MODE_UNDEF=0,
  SEARCH_MODE_BYTE,
  SEARCH_MODE_WORD,
  SEARCH_MODE_DWORD,
  SEARCH_MODE_QWORD,
  SEARCH_MODE_STRING_ALL,
  SEARCH_MODE_STRING_SPLIT,
  SEARCH_MODE_STRING

}search_mode_e;


extern search_mode_e search_options_mode;
extern u64 search_options_numeric;
extern r_utils_bytes_s *search_options_string;
extern r_utils_bytes_s *search_options_bad;
extern int search_options_raw;
extern int search_options_color;
extern const char *search_options_filename;
extern int search_options_strlen;

void search_print_all_string_in_bin(r_binfmt_s *bin);
void search_print_split_string_in_bin(r_binfmt_s *bin, r_utils_bytes_s *bytes);
void search_print_string_in_bin(r_binfmt_s *bin, r_utils_bytes_s *bytes);
void search_print_numeric_in_bin(r_binfmt_s *bin, u64 n, size_t size_of);

#endif
