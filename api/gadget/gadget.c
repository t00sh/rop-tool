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
#include "api/gadget.h"

r_gadget_s* r_gadget_new(void) {
  return r_utils_calloc(1, sizeof(r_gadget_s));
}

int r_gadget_handle_init(r_gadget_handle_s *g_handle, r_binfmt_arch_e arch, r_disa_flavor_e flavor, int filter, int depth, int all, r_utils_bytes_s *bad) {
  assert(g_handle != NULL);
  assert(depth > 0);

  if(!r_disa_init(&g_handle->disa, arch))
    return 0;
  if(!r_disa_set_flavor(&g_handle->disa, flavor)) {
    r_disa_close(&g_handle->disa);
    return 0;
  }

  g_handle->bad = bad;
  g_handle->depth = depth;
  g_handle->filter = filter;
  g_handle->all = all;
  g_handle->g_hash = r_utils_hash_new(free);

  return 1;
}

void r_gadget_handle_close(r_gadget_handle_s *g_handle) {
  assert(g_handle != NULL);
  assert(g_handle->g_hash != NULL);

  r_disa_close(&g_handle->disa);
  r_utils_hash_free(&g_handle->g_hash);
}

void r_gadget_update(r_gadget_handle_s *g_handle, addr_t addr, u8 *code, u32 code_size) {
  r_gadget_s *gadget;
  r_utils_hash_elem_s *h_elem;
  u32 i;
  int j;

  assert(g_handle != NULL);
  assert(g_handle->g_hash != NULL);

  for(i = 0; i < code_size; i++) {
    for(j = 1; j <= g_handle->depth; j++) {
      r_disa_code(&g_handle->disa, code+i, code_size-i, addr+i, j);

      if(g_handle->disa.instr_lst.count > 0) {
	if(r_disa_end_is_call(&g_handle->disa) ||
	   r_disa_end_is_jmp(&g_handle->disa) ||
	   r_disa_end_is_ret(&g_handle->disa) ||
	   r_disa_end_is_syscall(&g_handle->disa)) {

	  gadget = r_gadget_new();
	  gadget->addr_size = r_binfmt_addr_size(g_handle->disa.arch);
	  gadget->addr = addr+i;
	  gadget->gadget = r_disa_instr_lst_to_str(&g_handle->disa);

	  h_elem = r_utils_hash_elem_new(gadget, (u8*)gadget->gadget, strlen(gadget->gadget));

	  if((!g_handle->filter || r_gadget_filter(gadget->gadget, g_handle->disa.arch, g_handle->disa.flavor)) &&
	     (g_handle->all || !r_utils_hash_elem_exist(g_handle->g_hash, h_elem->key, h_elem->key_len)) &&
	     (!r_binfmt_is_bad_addr(g_handle->bad, gadget->addr, g_handle->disa.arch))) {
	    r_utils_hash_insert(g_handle->g_hash, h_elem);
	  } else {
	    free(gadget->gadget);
	    free(gadget);
	    free(h_elem);
	  }
	}
      }
    }
  }
}
