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
#include "binfmt.h"




/* =========================================================================
   This file implement functions for extracting big/little endian integers
   ======================================================================= */

u64 r_binfmt_get_int64(byte_t *p, r_binfmt_endian_e endian) {
  if(endian == R_BINFMT_ENDIAN_BIG)
    return ((u64)p[0] << 56 |
      (u64)p[1] << 48 |
      (u64)p[2] << 40 |
      (u64)p[3] << 32 |
      (u64)p[4] << 24 |
      (u64)p[5] << 16 |
      (u64)p[6] << 8  |
      (u64)p[7]);

  return ((u64)p[7] << 56 |
    (u64)p[6] << 48 |
    (u64)p[5] << 40 |
    (u64)p[4] << 32 |
    (u64)p[3] << 24 |
    (u64)p[2] << 16 |
    (u64)p[1] << 8  |
    (u64)p[0]);
}

u32 r_binfmt_get_int32(byte_t *p, r_binfmt_endian_e endian) {
  if(endian == R_BINFMT_ENDIAN_BIG)
    return ((u32)p[0] << 24 |
      (u32)p[1] << 16 |
      (u32)p[2] << 8  |
      (u32)p[3]);

  return ((u32)p[3] << 24 |
    (u32)p[2] << 16 |
    (u32)p[1] << 8  |
    (u32)p[0]);
}

u16 r_binfmt_get_int16(byte_t *p, r_binfmt_endian_e endian) {
  if(endian == R_BINFMT_ENDIAN_BIG)
    return ((u16)p[0] << 8 |
      (u16)p[1]);
  return ((u16)p[1] << 8 |
    (u16)p[0]);
}
