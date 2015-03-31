#include "ropc_gadget.h"

void gadget_print_gadget(r_utils_hash_elem_s *elem) {
  r_gadget_s *g = elem->val;

  R_UTILS_PRINT_GREEN_BG_BLACK(gadget_options_color, " %.16" PRIx64 " ", g->addr);
  R_UTILS_PRINT_WHITE_BG_BLACK(gadget_options_color, "-> ");
  R_UTILS_PRINT_RED_BG_BLACK(gadget_options_color, "%s\n", g->gadget);
}

void gadget_print_search(r_binfmt_s *bin) {
  r_binfmt_mem_s *m;
  r_gadget_handle_s g_handle;

  if(!r_gadget_handle_init(&g_handle, bin->arch, gadget_options_flavor, gadget_options_filter, gadget_options_depth, gadget_options_all))
    R_UTILS_ERR("Can't init gadget handle !");

  for(m = bin->mlist->head; m; m = m->next) {
    if(m->flags & R_BINFMT_MEM_FLAG_PROT_X) {
      r_gadget_update(&g_handle, m->addr, m->start, m->length);
    }
  }

  r_utils_hash_foreach(g_handle.g_hash, gadget_print_gadget);
  R_UTILS_PRINT_WHITE_BG_BLACK(gadget_options_color, "%" PRId32 " gadgets found.\n", r_utils_hash_size(g_handle.g_hash));

  r_gadget_handle_close(&g_handle);
}
