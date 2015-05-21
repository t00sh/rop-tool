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


/* =========================================================================
   This file contain the functions for the RAW binary
   ======================================================================= */

r_binfmt_err_e r_binfmt_raw_load(r_binfmt_s *bin, r_binfmt_arch_e arch) {
  bin->mlist = r_binfmt_mlist_new();

  r_binfmt_mlist_add(bin->mlist,
		 0,
		 bin->mapped,
		 bin->mapped_size,
		 R_BINFMT_MEM_FLAG_PROT_X | R_BINFMT_MEM_FLAG_PROT_R | R_BINFMT_MEM_FLAG_PROT_W);

  bin->type = R_BINFMT_TYPE_RAW;
  bin->arch = arch;
  bin->endian = R_BINFMT_ENDIAN_LITTLE;

  return R_BINFMT_ERR_OK;
}
