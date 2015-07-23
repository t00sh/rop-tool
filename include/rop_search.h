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
#ifndef DEF_ROP_SEARCH_H
#define DEF_ROP_SEARCH_H

#include "api/rop.h"


typedef enum search_mode {
  SEARCH_MODE_UNDEF=0,
  SEARCH_MODE_BYTE,
  SEARCH_MODE_WORD,
  SEARCH_MODE_DWORD,
  SEARCH_MODE_QWORD,
  SEARCH_MODE_STRING_ALL,
  SEARCH_MODE_STRING_SPLIT,
  SEARCH_MODE_STRING

}search_mode_e;


extern search_mode_e search_options_mode;
extern u64 search_options_numeric;
extern r_utils_bytes_s *search_options_string;
extern r_utils_bytes_s *search_options_bad;
extern r_binfmt_arch_e search_options_arch;
extern int search_options_color;
extern const char *search_options_filename;
extern int search_options_strlen;

void search_print_all_string_in_bin(r_binfmt_s *bin);
void search_print_split_string_in_bin(r_binfmt_s *bin, r_utils_bytes_s *bytes);
void search_print_string_in_bin(r_binfmt_s *bin, r_utils_bytes_s *bytes);
void search_print_numeric_in_bin(r_binfmt_s *bin, u64 n, size_t size_of);

#endif
