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
#include "api/binfmt.h"


/* =========================================================================
   This file contain some functions on various binary lists
   ======================================================================= */

r_binfmt_sym_s* r_binfmt_sym_new(void) {
  return r_utils_malloc(sizeof(r_binfmt_sym_s));
}

r_binfmt_section_s* r_binfmt_section_new(void) {
  return r_utils_malloc(sizeof(r_binfmt_section_s));
}

void r_binfmt_sections_free(r_binfmt_s *bin) {
  r_utils_list_free(&bin->sections, free);
}

void r_binfmt_syms_free(r_binfmt_s *bin) {
  r_utils_list_free(&bin->syms, free);
}
