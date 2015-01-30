#include "api/binfmt.h"

/************************************************************************/
/* RopC - A Return Oriented Programming tool			        */
/* 								        */
/* Copyright 2013-2014, -TOSH-					        */
/* File coded by -TOSH-						        */
/* 								        */
/* This file is part of RopC.					        */
/* 								        */
/* RopC is free software: you can redistribute it and/or modify	        */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* RopC is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with RopC.  If not, see <http://www.gnu.org/licenses/>	        */
/************************************************************************/

/* =========================================================================
   This file contain the functions for the RAW binary
   ======================================================================= */

r_binfmt_arch_e r_binfmt_raw_get_arch(void) {

  return R_BINFMT_ARCH_X86;
}

r_binfmt_err_e r_binfmt_raw_load(r_binfmt_s *bin) {
  bin->mlist = r_binfmt_mlist_new();

  r_binfmt_mlist_add(bin->mlist,
		 0,
		 bin->mapped,
		 bin->mapped_size,
		 R_BINFMT_MEM_FLAG_PROT_X | R_BINFMT_MEM_FLAG_PROT_R | R_BINFMT_MEM_FLAG_PROT_X);

  bin->type = R_BINFMT_TYPE_RAW;
  bin->arch = r_binfmt_raw_get_arch();
  bin->endian = R_BINFMT_ENDIAN_LITTLE;

  return R_BINFMT_ERR_OK;
}
