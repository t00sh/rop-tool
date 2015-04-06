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
#include "api/utils.h"



/* =========================================================================
   This file implement functions for preventing integer overflow when
   add, sub or mul two integers
   ======================================================================= */

int r_utils_add64(u64 *r, u64 a, u64 b) {
  if(UINT64_MAX - a < b)
    return 0;

  if(r != NULL)
    *r = a + b;

  return 1;
}

int r_utils_add32(u32 *r, u32 a, u32 b) {
  if(UINT32_MAX - a < b)
    return 0;

  if(r != NULL)
    *r = a + b;

  return 1;
}

int r_utils_add16(u16 *r, u16 a, u16 b) {
  if(UINT16_MAX - a < b)
    return 0;

  if(r != NULL)
    *r = a + b;

  return 1;
}

int r_utils_mul64(u64 *r, u64 a, u64 b) {
  if(a && UINT64_MAX / a < b)
    return 0;

  if(r != NULL)
    *r = a * b;

  return 1;
}

int r_utils_mul32(u32 *r, u32 a, u32 b) {
  if(a && UINT32_MAX / a < b)
    return 0;

  if(r != NULL)
    *r = a * b;

  return 1;
}

int r_utils_mul16(u16 *r, u16 a, u16 b) {
  if(a && UINT16_MAX / a < b)
    return 0;

  if(r != NULL)
    *r = a * b;

  return 1;
}

int r_utils_sub64(u64 *r, u64 a, u64 b) {
  if(b > a)
    return 0;

  if(r != NULL)
    *r = a - b;

  return 1;
}

int r_utils_sub32(u32 *r, u32 a, u32 b) {
  if(b > a)
    return 0;

  if(r != NULL)
    *r = a - b;

  return 1;
}

int r_utils_sub16(u16 *r, u16 a, u16 b) {
  if(b > a)
    return 0;

  if(r != NULL)
    *r = a - b;

  return 1;
}
