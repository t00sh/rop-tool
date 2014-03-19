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


#include <stdint.h>
#include <stdlib.h>

int safe_add64(uint64_t *r, uint64_t a, uint64_t b) {
  if(UINT64_MAX - a < b)
    return 0;
    
  if(r != NULL)
    *r = a + b;

  return 1;
}

int safe_add32(uint32_t *r, uint32_t a, uint32_t b) {
  if(UINT32_MAX - a < b)
    return 0;

  if(r != NULL)
    *r = a + b;

  return 1;
}

int safe_add16(uint16_t *r, uint16_t a, uint16_t b) {
  if(UINT16_MAX - a < b)
    return 0;

  if(r != NULL)
    *r = a + b;

  return 1;
}

int safe_mul64(uint64_t *r, uint64_t a, uint64_t b) {
  if(UINT64_MAX / a < b)
    return 0;

  if(r != NULL)
    *r = a * b;

  return 1;
}

int safe_mul32(uint32_t *r, uint32_t a, uint32_t b) {
  if(UINT32_MAX / a < b)
    return 0;

  if(r != NULL)
    *r = a * b;

  return 1;
}

int safe_mul16(uint16_t *r, uint16_t a, uint16_t b) {
  if(UINT16_MAX / a < b)
    return 0;

  if(r != NULL)
    *r = a * b;

  return 1;
}

int safe_sub64(uint64_t *r, uint64_t a, uint64_t b) {
  if(b > a)
    return 0;

  if(r != NULL)
    *r = a - b;
  
  return 1;
}

int safe_sub32(uint32_t *r, uint32_t a, uint32_t b) {
  if(b > a)
    return 0;

  if(r != NULL)
    *r = a - b;
  
  return 1;
}

int safe_sub16(uint16_t *r, uint16_t a, uint16_t b) {
  if(b > a)
    return 0;

  if(r != NULL)
    *r = a - b;
  
  return 1;
}
