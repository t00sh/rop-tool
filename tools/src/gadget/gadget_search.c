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
#include "rop_gadget.h"

void gadget_print_gadget(void *gadget) {
  r_gadget_s *g = gadget;

  if(g->addr_size == 4) {
    R_UTILS_PRINT_GREEN_BG_BLACK(gadget_options_color, " %#.8" PRIx32 " ", (u32)g->addr);
  } else {
    R_UTILS_PRINT_GREEN_BG_BLACK(gadget_options_color, " %#.16" PRIx64 " ", g->addr);
  }
  R_UTILS_PRINT_WHITE_BG_BLACK(gadget_options_color, "-> ");
  R_UTILS_PRINT_RED_BG_BLACK(gadget_options_color, "%s\n", g->gadget);
}


void gadget_print_gadgets(r_binfmt_s *bin, r_gadget_handle_s *g_handle) {
  r_utils_hash_s *hash;
  r_gadget_s *gadget;
  int ret;

  hash = r_utils_hash_new(r_utils_linklist_size(&g_handle->g_list)*5, NULL);

  r_utils_linklist_iterator_init(&g_handle->g_list);

  while((gadget = r_utils_linklist_next(&g_handle->g_list)) != NULL) {

    /* Filter gadget */
    ret = r_gadget_is_filter(gadget->gadget,
                             g_handle->disa.arch,
                             g_handle->disa.flavor);

    if(ret == 0 || (gadget_options_filter && ret != 2)) {
      continue;
    }

    /* All option */
    if(!gadget_options_all) {
      if(r_utils_hash_elem_exist(hash,
                                 (u8*)gadget->gadget,
                                 strlen(gadget->gadget)))
        continue;
    }

    /* Bad option */
    if(gadget_options_bad != NULL) {
      if(r_binfmt_is_bad_addr(gadget_options_bad,
                              gadget->addr,
                              bin->arch))
        continue;
    }

    r_utils_hash_insert(hash, r_utils_hash_elem_new(gadget,
                                                    (u8*)gadget->gadget,
                                                    strlen(gadget->gadget)));
    gadget_print_gadget(gadget);

  }

  R_UTILS_PRINT_WHITE_BG_BLACK(gadget_options_color, "%" PRId32 " gadgets found.\n", r_utils_hash_size(hash));
  r_utils_hash_free(&hash);
}

void gadget_print_search(r_binfmt_s *bin) {
  r_binfmt_segment_s *seg;
  r_gadget_handle_s g_handle;

  if(!r_gadget_handle_init(&g_handle, bin->arch, gadget_options_flavor, gadget_options_depth))
    R_UTILS_ERR("Can't init gadget handle !");

  r_utils_linklist_iterator_init(&bin->segments);

  while((seg = r_utils_linklist_next(&bin->segments)) != NULL) {

    if(seg->flags & R_BINFMT_SEGMENT_FLAG_PROT_X) {
      r_gadget_update(&g_handle, seg->addr, seg->start, seg->length);
    }
  }

  gadget_print_gadgets(bin, &g_handle);
  r_gadget_handle_close(&g_handle);
}
