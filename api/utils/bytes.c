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
#include "api/utils.h"

/* The function do NOT initialize the bytes array */
r_utils_bytes_s* r_utils_new_bytes_seq(size_t len) {
  r_utils_bytes_s *new;

  new = r_utils_calloc(1, sizeof(r_utils_bytes_s));
  new->bytes = r_utils_malloc(len);
  new->len = len;

  return new;
}

void r_utils_free_bytes_seq(r_utils_bytes_s **bytes) {
  if((*bytes)->bytes) {
    free((*bytes)->bytes);
    (*bytes)->bytes = NULL;
  }

  if(*bytes) {
    free(*bytes);
    *bytes = NULL;
  }
}


char* r_utils_bytes_hexlify(r_utils_bytes_s *bytes) {
  char *string;
  u32 i;
  char *p;

  assert(bytes != NULL);
  assert(bytes->len < SIZE_MAX/4 - 1);

  string = r_utils_malloc(bytes->len*4 + 1);

  p = string;

  for(i = 0; i < bytes->len; i++) {
    if(!isgraph(bytes->bytes[i])) {
      *(p++) = '\\';
      *(p++) = 'x';
      *(p++) = r_utils_dec_to_hexchar(bytes->bytes[i] / 16);
      *(p++) = r_utils_dec_to_hexchar(bytes->bytes[i] % 16);
    } else {
      *(p++) = bytes->bytes[i];
    }
  }

  *p = '\0';

  return string;
}

r_utils_bytes_s* r_utils_bytes_unhexlify(const char *string) {

  int len;
  size_t i;
  r_utils_bytes_s *bytes;

  assert(string != NULL);

  len = strlen(string);
  i = 0;

  bytes = r_utils_new_bytes_seq(len+1);

 while(*string != '\0') {
   if(string[0] == '\\' && string[1] == 'x' &&
      isxdigit(string[2]) && isxdigit(string[3])) {
     bytes->bytes[i] = r_utils_hexchar_to_dec(string[2]) * 16;
     bytes->bytes[i] += r_utils_hexchar_to_dec(string[3]);
     string += 3;
   } else {
     bytes->bytes[i] = *string;
   }
   string++;
   i++;
 }

 bytes->len = i;
 return bytes;
}

int r_utils_bytes_are_in_addr32(r_utils_bytes_s *bytes, u32 addr) {
  size_t i;

  if(bytes != NULL) {
    for(i = 0; i < bytes->len; i++) {
      if((bytes->bytes[i] == ((addr)       & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 8)  & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 16) & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 24) & 0xFF)))
  return 1;
    }
  }
  return 0;

}


int r_utils_bytes_are_in_addr64(r_utils_bytes_s *bytes, u64 addr) {
  size_t i;

  if(bytes != NULL) {
    for(i = 0; i < bytes->len; i++) {
      if((bytes->bytes[i] == ((addr)       & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 8)  & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 16) & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 24) & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 32) & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 40) & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 48) & 0xFF)) ||
   (bytes->bytes[i] == ((addr >> 56) & 0xFF)))
  return 1;
    }
  }

  return 0;

}
