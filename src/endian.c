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
   This file implement functions for extracting big/little endian integers
   ======================================================================= */

uint64_t endian_get64(byte_t *p, enum BINFMT_ENDIAN endian) {
  if(endian == BINFMT_ENDIAN_BIG)
    return ((uint64_t)p[0] << 56 |
	    (uint64_t)p[1] << 48 |
	    (uint64_t)p[2] << 40 |
	    (uint64_t)p[3] << 32 |
	    (uint64_t)p[4] << 24 |
	    (uint64_t)p[5] << 16 |
	    (uint64_t)p[6] << 8  |
	    (uint64_t)p[7]);

  return ((uint64_t)p[7] << 56 |
	  (uint64_t)p[6] << 48 |
	  (uint64_t)p[5] << 40 |
	  (uint64_t)p[4] << 32 |
	  (uint64_t)p[3] << 24 |
	  (uint64_t)p[2] << 16 |
	  (uint64_t)p[1] << 8  |
	  (uint64_t)p[0]);
}

uint32_t endian_get32(byte_t *p, enum BINFMT_ENDIAN endian) {
  if(endian == BINFMT_ENDIAN_BIG)
    return ((uint32_t)p[0] << 24 |
	    (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8  |
	    (uint32_t)p[3]);

  return ((uint32_t)p[3] << 24 |
	  (uint32_t)p[2] << 16 |
	  (uint32_t)p[1] << 8  |
	  (uint32_t)p[0]);
}

uint16_t endian_get16(byte_t *p, enum BINFMT_ENDIAN endian) {
  if(endian == BINFMT_ENDIAN_BIG)
    return ((uint16_t)p[0] << 8 |
	    (uint16_t)p[1]);
  return ((uint16_t)p[1] << 8 |
	  (uint16_t)p[0]);
}

