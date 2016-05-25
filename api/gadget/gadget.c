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
#include "api/gadget.h"

/* =========================================================================
   This file implement functions for gadget searching
   ======================================================================= */

r_gadget_s* r_gadget_new(void) {
  return r_utils_calloc(1, sizeof(r_gadget_s));
}

static void r_gadget_free(void* g) {
  r_gadget_s* gadget = g;

  free(gadget->gadget);
  free(gadget);
}
int r_gadget_handle_init(r_gadget_handle_s *g_handle, r_binfmt_arch_e arch, r_disa_flavor_e flavor, int depth) {
  assert(g_handle != NULL);
  assert(depth > 0);

  if(!r_disa_init(&g_handle->disa, arch))
    return 0;
  if(!r_disa_set_flavor(&g_handle->disa, flavor)) {
    r_disa_close(&g_handle->disa);
    return 0;
  }

  g_handle->depth = depth;
  r_utils_linklist_init(&g_handle->g_list);

  return 1;
}


void r_gadget_handle_close(r_gadget_handle_s *g_handle) {
  assert(g_handle != NULL);

  r_disa_close(&g_handle->disa);
  r_utils_linklist_free(&g_handle->g_list, r_gadget_free);
}

void r_gadget_add_current(r_gadget_handle_s *g_handle) {
  r_gadget_s *gadget;
  char *g_string;

  g_string = r_disa_instr_lst_to_str(&g_handle->disa);

  if(g_string != NULL) {
    gadget = r_gadget_new();
    gadget->addr_size = r_binfmt_addr_size(g_handle->disa.arch);
    gadget->addr = g_handle->disa.instr_lst.head[0].address;
    gadget->gadget = g_string;
    r_utils_linklist_push(&g_handle->g_list, gadget);
  }
}


void r_gadget_update(r_gadget_handle_s *g_handle, addr_t addr, u8 *code, u32 code_size) {
  u32 i;

  assert(g_handle != NULL);

  for(i = 0; i < code_size; i++) {
    r_disa_code(&g_handle->disa, code+i, code_size-i, addr+i, g_handle->depth);
    r_gadget_add_current(g_handle);
  }
}
