#ifndef DEF_ROPC_SEARCH_H
#define DEF_ROPC_SEARCH_H

#include "api/ropc.h"

extern u8 gadget_options_depth;
extern int gadget_options_raw;
extern int gadget_options_filter;
extern int gadget_options_all;
extern int gadget_options_color;
extern r_binfmt_arch_e gadget_options_arch;
extern r_disa_flavor_e gadget_options_flavor;
extern r_utils_bytes_s *gadget_options_bad;
extern const char *gadget_options_filename;

void gadget_print_search(r_binfmt_s *bin);

#endif
