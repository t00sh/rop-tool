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
#include "api/binfmt.h"
#include "api/binfmt/elf.h"

/* =========================================================================
   This file implement generic ELF functions
   ======================================================================= */

/* Check if the symbol __stack_chk_fail is present to detect Stack Smashing Protector.
   Must be called when symbols are already loaded
*/
r_binfmt_ssp_e r_binfmt_elf_check_ssp(r_binfmt_s *bin) {
  if(r_utils_list_size(&bin->syms) == 0)
    return R_BINFMT_SSP_UNKNOWN;

  if(r_binfmt_get_sym_by_name(bin, "__stack_chk_fail") != R_BINFMT_BAD_ADDR)
    return R_BINFMT_SSP_ENABLED;

  return R_BINFMT_SSP_DISABLED;
}
