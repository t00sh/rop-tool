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
#ifndef DEF_API_BINFMT_ENDIAN_H
#define DEF_API_BINFMT_ENDIAN_H

u64 r_binfmt_get_int64(byte_t *p, r_binfmt_endian_e endian);
u32 r_binfmt_get_int32(byte_t *p, r_binfmt_endian_e endian);
u16 r_binfmt_get_int16(byte_t *p, r_binfmt_endian_e endian);

#define R_BINFMT_GET_INT(store,field,endian) do {           \
    if(sizeof(field) == 2)                                  \
      store = r_binfmt_get_int16((byte_t*)&field, endian);  \
    else if(sizeof(field) == 4)                             \
      store = r_binfmt_get_int32((byte_t*)&field, endian);  \
    else if(sizeof(field) == 8)                             \
      store = r_binfmt_get_int64((byte_t*)&field, endian);  \
    else                                                    \
      R_UTILS_ERR("Bad field size in R_BINFMT_GET_INT()");  \
  } while(0)


#endif
