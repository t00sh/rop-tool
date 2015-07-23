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
#include "api/binfmt.h"


/* =========================================================================
   This file contain some functions about binary segments
   ======================================================================= */

r_binfmt_segment_s* r_binfmt_segment_new(void) {
  return r_utils_malloc(sizeof(r_binfmt_segment_s));
}

void r_binfmt_segments_free(r_binfmt_s *bin) {
  r_utils_list_free(&bin->segments, free);
}

/* Get memory flags as a string */
void r_binfmt_get_segment_flag_str(char str[4], r_binfmt_segment_s *seg) {
  int i;

  assert(seg != NULL);

  i = 0;
  if(seg->flags & R_BINFMT_MEM_FLAG_PROT_R)
    str[i++] = 'R';
  else
    str[i++] = '-';
  if(seg->flags & R_BINFMT_MEM_FLAG_PROT_W)
    str[i++] = 'W';
  else
    str[i++] = '-';
  if(seg->flags & R_BINFMT_MEM_FLAG_PROT_X)
    str[i++] = 'X';
  else
    str[i++] = '-';

  str[i] = '\0';
}
