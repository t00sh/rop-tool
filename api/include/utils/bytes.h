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

#ifndef DEF_API_UTILS_BYTES_H
#define DEF_API_UTILS_BYTES_H

/* Raw bytes sequence structure */
typedef struct r_utils_bytes {
  u64 len;
  u8 *bytes;
}r_utils_bytes_s;

r_utils_bytes_s* r_utils_bytes_unhexlify(const char *string);
char* r_utils_bytes_hexlify(r_utils_bytes_s *bytes);
void r_utils_free_bytes_seq(r_utils_bytes_s **bytes);
r_utils_bytes_s* r_utils_new_bytes_seq(size_t len);
int r_utils_bytes_are_in_addr32(r_utils_bytes_s *bytes, u32 addr);
int r_utils_bytes_are_in_addr64(r_utils_bytes_s *bytes, u64 addr);

#endif
