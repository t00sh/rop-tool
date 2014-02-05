#include "ropc.h"

/* Test if the 32 bits address don't contains bad chars */
/* Ex : addr=0x0804800a, bad="\x0a" -> BAD */
/* Ex : addr=0x0804800a, bad="\x48" -> GOOD */
int is_good_addr(uint32_t addr, DATA *bad) {
  uint32_t i;

  for(i = 0; i < bad->length; i++) {
    if(((addr >> 24) & 0xFF) == bad->data[i]) {
      return 0;
    }
    if(((addr >> 16) & 0xFF) == bad->data[i]) {
      return 0;
    }
    if(((addr >> 8) & 0xFF) == bad->data[i]) {      
      return 0;
    }
    if(((addr) & 0xFF) == bad->data[i]) {
      return 0;
    }
  }
  return 1;
}

DATA memdup(DATA *data) {
  DATA ret;

  ret.data = malloc(data->length);
  if(ret.data == NULL)
    FATAL_ERROR("OUT of memory");

  ret.length = data->length;
  ret.addr   = data->addr;
  memcpy(ret.data, data->data, data->length);

  return ret;
}

/* Test if char is in range [0-9a-fA-F] */
int is_hexa_char(int c) {
  return (isdigit(c) 
	  || (c >= 'a' && c <= 'f') 
	  || (c >= 'A' && c <= 'F'));
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
char* data_to_opcodes(DATA *data) {
  char *string;
  uint32_t i;

  string = malloc(data->length*4 + 1);
  if(string == NULL)
    FATAL_ERROR("OUT of memory");

  for(i = 0; i < data->length; i++) {
    string[i*4] = '\\';
    string[i*4+1] = 'x';
    string[i*4+2] = dec_to_hex(data->data[i] / 16);
    string[i*4+3] = dec_to_hex(data->data[i] % 16);
  }
  string[i*4] = '\0';

  return string;
}

/* Convert "\x0a\x2c..." to raw data */
/* DATA.data returned must be free by the caller */
DATA opcodes_to_data(char *str) {
int len, i;
 DATA data;

 len = strlen(str);
 i = 0;

 data.data = malloc(len + 1);

 while(*str != '\0') {
   if(str[0] == '\\' && str[1] == 'x') {
     if(is_hexa_char(str[2]) && is_hexa_char(str[3])) {
       data.data[i] = hex_to_dec(str[2]) * 16;
       data.data[i] += hex_to_dec(str[3]);
       str += 3;
     }
   } else {
     data.data[i] = *str;
   }
   str++;
   i++;
 }
 data.length = i;
 return data;
}

/* Search src in dst. Start searching at specified offset */
uint32_t memsearch(DATA *dst, DATA *src, uint32_t offset) {
  uint32_t i, j;
  
  for(i = offset; i < dst->length-src->length; i++) {
    for(j = 0; j < src->length; j++) {
      if(dst->data[i+j] != src->data[j])
	break;
    }
    if(j == src->length)
      return i;
  }
  return (uint32_t)(-1);
} 
