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
#include "api/binfmt.h"
#include "api/binfmt/elf.h"

/* =========================================================================
   This file implement generic ELF functions
   ======================================================================= */

/* Check if the symbol __stack_chk_fail is present to detect Stack Smashing Protector.
   Must be called when symbols are already loaded
*/
r_binfmt_ssp_e r_binfmt_elf_check_ssp(r_binfmt_s *bin) {
  if(r_utils_arraylist_size(&bin->syms) == 0)
    return R_BINFMT_SSP_UNKNOWN;

  if(r_binfmt_get_sym_by_name(bin, "__stack_chk_fail") != R_BINFMT_BAD_ADDR)
    return R_BINFMT_SSP_ENABLED;

  return R_BINFMT_SSP_DISABLED;
}

/* Get the type of the binary (ELF32 or ELF64) */
r_binfmt_type_e r_binfmt_elf_type(r_binfmt_s *bin) {

  if(bin->mapped_size < EI_NIDENT)
     return R_BINFMT_TYPE_UNDEF;

  if(memcmp(bin->mapped, ELFMAG, SELFMAG))
    return R_BINFMT_TYPE_UNDEF;

  if(bin->mapped[EI_CLASS] == ELFCLASS32)
    return R_BINFMT_TYPE_ELF32;

  if(bin->mapped[EI_CLASS] == ELFCLASS64)
    return R_BINFMT_TYPE_ELF64;

  return R_BINFMT_TYPE_UNDEF;
}
