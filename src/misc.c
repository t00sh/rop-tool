#include "ropc.h"

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


/* Test if the 32 bits address don't contains bad chars */
/* Ex : addr=0x0804800a, bad="\x0a" -> BAD */
/* Ex : addr=0x0804800a, bad="\x48" -> GOOD */
int is_good_addr(addr_t addr, BLIST *bad) {
  uint32_t i;

  for(i = 0; i < bad->length; i++) {
    if(((addr >> 24) & 0xFF) == bad->start[i]) {
      return 0;
    }
    if(((addr >> 16) & 0xFF) == bad->start[i]) {
      return 0;
    }
    if(((addr >> 8) & 0xFF) == bad->start[i]) {
      return 0;
    }
    if(((addr) & 0xFF) == bad->start[i]) {
      return 0;
    }
  }
  return 1;
}

/* Convert 'a' -> 10 */
int hex_to_dec(int c) {
  if(isdigit(c))
    return c - '0';
  if(c >= 'a' && c <= 'f')
    return (c - 'a') + 10;
  if(c >= 'A' && c <= 'F')
    return (c - 'A') + 10;
  
  return -1;
}

/* Convert 10 -> 'a' */
int dec_to_hex(int c) {
  return "0123456789abcdef"[c];
}

/* Convert raw data, to opcodes representation : "\x3a\x2e..." */
/* char* returned must be free by the caller */
char* blist_to_opcodes(BLIST *blist) {
  char *string;
  uint32_t i;
  char *p;

  string = xmalloc(blist->length*4 + 1);

  p = string;

  for(i = 0; i < blist->length; i++) {
    if(!isgraph(blist->start[i])) {
      *(p++) = '\\';
      *(p++) = 'x';
      *(p++) = dec_to_hex(blist->start[i] / 16);
      *(p++) = dec_to_hex(blist->start[i] % 16);
    } else {
      *(p++) = blist->start[i];
    }
  }
  *p = '\0';

  return string;
}

/* Convert "\x0a\x2c..." to raw data */
/* DATA.data returned must be free by the caller */
BLIST opcodes_to_blist(char *str) {
  int len, i;
  BLIST blist;

 len = strlen(str);
 i = 0;

 blist.start = xmalloc(len + 1);

 while(*str != '\0') {
   if(str[0] == '\\' && str[1] == 'x') {
     if(isxdigit(str[2]) && isxdigit(str[3])) {
       blist.start[i] = hex_to_dec(str[2]) * 16;
       blist.start[i] += hex_to_dec(str[3]);
       str += 3;
     }
   } else {
     blist.start[i] = *str;
   }
   str++;
   i++;
 }
 blist.length = i;
 return blist;
}

addr_t memsearch(void *s1, len_t s1_len, void *s2, len_t s2_len) {
  len_t i;

  if(s1_len < s2_len)
    return 0;

  for(i = 0; i < s1_len - s2_len; i++) {
    if(!memcmp((byte_t*)(s1)+i, s2, s2_len))
       return i;
  }
  return NOT_FOUND;
}

