#include "ropc.h"

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

enum BINFMT_ARCH raw_get_arch(void) {
  if(options_arch == ARCH_X86)
    return BINFMT_ARCH_X86;
  if(options_arch == ARCH_X86_64)
    return BINFMT_ARCH_X86_64;

  return BINFMT_ARCH_UNDEF;
}

enum BINFMT_ERR raw_load(BINFMT *bin) {
  bin->mlist = mlist_new();

  mlist_add(bin->mlist,
	    0,
	    bin->mapped,
	    bin->mapped_size,
	    MEM_FLAG_PROT_X | MEM_FLAG_PROT_R | MEM_FLAG_PROT_X);

  bin->type = BINFMT_TYPE_RAW;
  bin->arch = raw_get_arch();
  bin->endian = BINFMT_ENDIAN_LITTLE;

  return BINFMT_ERR_OK;
}
