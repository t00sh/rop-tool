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

#define R_UTILS_HEXDUMP_BLOCK      8
#define R_UTILS_HEXDUMP_NUM_BLOCK  2
#define R_UTILS_HEXDUMP_BYTES_PER_LINE (R_UTILS_HEXDUMP_BLOCK*R_UTILS_HEXDUMP_NUM_BLOCK)

/* Note: %12 can print offset up to 256 Tera-bytes (2^48 bytes). I hope it will be enough for all cases... */

void r_utils_hexdump(FILE *stream, int color, u8 *code, u64 length, u64 offset) {
  u64 i, j, k;
  u32 reminder;

  assert(stream != NULL);
  assert(code != NULL);

  reminder = length % R_UTILS_HEXDUMP_BYTES_PER_LINE;

  for(i = 0; i < length-reminder; i += R_UTILS_HEXDUMP_BYTES_PER_LINE) {
    R_UTILS_FPRINT_RED_BG_BLACK(stream, color, "%.12" PRIx64 "  ", i+offset);

    for(k = 0; k < R_UTILS_HEXDUMP_NUM_BLOCK; k++) {
      for(j = k*R_UTILS_HEXDUMP_BLOCK; j < (k+1)*R_UTILS_HEXDUMP_BLOCK; j++) {
        R_UTILS_FPRINT_GREEN_BG_BLACK(stream, color, "%.2x ", code[i+j]);
      }

      fprintf(stream, " ");
    }

    fprintf(stream, "|");

    for(j = 0; j < R_UTILS_HEXDUMP_BYTES_PER_LINE; j++) {
      R_UTILS_FPRINT_YELLOW_BG_BLACK(stream, color, "%c", isprint(code[i+j]) ? code[i+j] : '.');
    }

    fprintf(stream, "|\n");
  }

  /* Print length reminder */

  if(reminder) {
    R_UTILS_FPRINT_RED_BG_BLACK(stream, color, "%.12" PRIx64 "  ", length - reminder + offset);

    for(k = 0; k < R_UTILS_HEXDUMP_NUM_BLOCK; k++) {
      for(i = k*R_UTILS_HEXDUMP_BLOCK; i < (k+1)*R_UTILS_HEXDUMP_BLOCK; i++) {
        if(reminder > i) {
          R_UTILS_FPRINT_GREEN_BG_BLACK(stream, color, "%.2x ", code[length - reminder + i]);
        } else {
          fprintf(stream, "   ");
        }
      }
      fprintf(stream, " ");
    }

    fprintf(stream, "|");

    for(i = 0; i < reminder; i++) {
      R_UTILS_FPRINT_YELLOW_BG_BLACK(stream, color, "%c", isprint(code[length - reminder + i]) ? code[length - reminder + i] : '.');
    }
    fprintf(stream, "|\n");
  }
}


/* Unit test */

#if 0
int main(void) {
  unsigned char code[R_UTILS_HEXDUMP_BYTES_PER_LINE*10];
  size_t r;
  u64 tot_read = 0;

  while((r = fread(code, 1, sizeof(code), stdin)) > 0) {
    r_utils_hexdump(stdout, 1, code, r, tot_read);
    tot_read += r;
  }

  return 0;
}
#endif
