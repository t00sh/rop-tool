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
#include "rop_gadget.h"

void gadget_print_gadget(r_utils_hash_elem_s *elem) {
  r_gadget_s *g = elem->val;

  if(g->addr_size == 4) {
    R_UTILS_PRINT_GREEN_BG_BLACK(gadget_options_color, " %#.8" PRIx32 " ", (u32)g->addr);
  } else {
    R_UTILS_PRINT_GREEN_BG_BLACK(gadget_options_color, " %#.16" PRIx64 " ", g->addr);
  }
  R_UTILS_PRINT_WHITE_BG_BLACK(gadget_options_color, "-> ");
  R_UTILS_PRINT_RED_BG_BLACK(gadget_options_color, "%s\n", g->gadget);
}

void gadget_print_search(r_binfmt_s *bin) {
  r_binfmt_mem_s *m;
  r_gadget_handle_s g_handle;

  if(!r_gadget_handle_init(&g_handle, bin->arch, gadget_options_flavor, gadget_options_filter, gadget_options_depth, gadget_options_all, gadget_options_bad))
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
