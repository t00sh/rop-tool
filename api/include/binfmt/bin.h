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
#ifndef DEF_API_BINFMT_BIN_H
#define DEF_API_BINFMT_BIN_H

void r_binfmt_free(r_binfmt_s *bin);
void r_binfmt_load(r_binfmt_s *, const char *, r_binfmt_arch_e, r_binfmt_endian_e);
void r_binfmt_write(r_binfmt_s *bin, const char *filename);
r_binfmt_arch_e r_binfmt_string_to_arch(const char *str);
const char* r_binfmt_arch_to_string(r_binfmt_arch_e arch);
const char* r_binfmt_type_to_string(r_binfmt_type_e type);
int r_binfmt_addr_size(r_binfmt_arch_e arch);
int r_binfmt_is_bad_addr(r_utils_bytes_s *bad, u64 addr, r_binfmt_arch_e arch);
void r_binfmt_print_segments(r_binfmt_s *bin, int color);
void r_binfmt_print_sections(r_binfmt_s *bin, int color);
void r_binfmt_print_syms(r_binfmt_s *bin, int color);
void r_binfmt_print_infos(r_binfmt_s *bin, int color);


#endif
