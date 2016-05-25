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

extern u32 gadget_options_depth;
extern int gadget_options_filter;
extern int gadget_options_all;
extern int gadget_options_color;
extern r_binfmt_arch_e gadget_options_arch;
extern r_disa_flavor_e gadget_options_flavor;
extern r_utils_bytes_s *gadget_options_bad;
extern const char *gadget_options_filename;

void gadget_print_search(r_binfmt_s *bin);

#endif
