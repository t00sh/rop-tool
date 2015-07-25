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
#ifndef DEF_API_UTILS_H
#define DEF_API_UTILS_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>

#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <assert.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#endif

/* =========================================================================
   R_UTILS_COLOR_RESET   : a constant used to recover color state
   R_UTILS_FG_COLOR_*    : foreground colors
   R_UTILS_BG_COLOR_*    : background colors
   R_UTILS_PRINT_COLORED : a macro used to print colored (or not) strings
   ======================================================================= */

#define R_UTILS_COLOR_RESET    "\033[m"

#define R_UTILS_FG_COLOR_BLACK    "\033[30m"
#define R_UTILS_FG_COLOR_RED      "\033[31m"
#define R_UTILS_FG_COLOR_GREEN    "\033[32m"
#define R_UTILS_FG_COLOR_YELLOW   "\033[33m"
#define R_UTILS_FG_COLOR_BLUE     "\033[34m"
#define R_UTILS_FG_COLOR_MAGENTA  "\033[35m"
#define R_UTILS_FG_COLOR_CYAN     "\033[36m"
#define R_UTILS_FG_COLOR_WHITE    "\033[37m"

#define R_UTILS_BG_COLOR_BLACK    "\033[40m"
#define R_UTILS_BG_COLOR_RED      "\033[41m"
#define R_UTILS_BG_COLOR_GREEN    "\033[42m"
#define R_UTILS_BG_COLOR_YELLOW   "\033[43m"
#define R_UTILS_BG_COLOR_BLUE     "\033[44m"
#define R_UTILS_BG_COLOR_MAGENTA  "\033[45m"
#define R_UTILS_BG_COLOR_CYAN     "\033[46m"
#define R_UTILS_BG_COLOR_WHITE    "\033[47m"

#define R_UTILS_FPRINT_COLORED(stream,color,c_str,...) do {	\
    if(color) {							\
      fprintf(stream, c_str);					\
      fprintf(stream,__VA_ARGS__);				\
      fprintf(stream, R_UTILS_COLOR_RESET);			\
    } else {							\
      fprintf(stream,__VA_ARGS__);				\
    }								\
  }while(0);

#define R_UTILS_PRINT_COLORED(color,c_str,...) do { R_UTILS_FPRINT_COLORED(stdout, color, c_str, __VA_ARGS__); } while(0)



#define R_UTILS_PRINT_WHITE_BG_BLACK(c,...) R_UTILS_PRINT_COLORED(c, R_UTILS_FG_COLOR_WHITE R_UTILS_BG_COLOR_BLACK, __VA_ARGS__)
#define R_UTILS_PRINT_BLACK_BG_WHITE(c,...) R_UTILS_PRINT_COLORED(c, R_UTILS_FG_COLOR_BLACK R_UTILS_BG_COLOR_WHITE, __VA_ARGS__)
#define R_UTILS_PRINT_RED_BG_BLACK(c,...) R_UTILS_PRINT_COLORED(c, R_UTILS_FG_COLOR_RED R_UTILS_BG_COLOR_BLACK, __VA_ARGS__)
#define R_UTILS_PRINT_GREEN_BG_BLACK(c,...) R_UTILS_PRINT_COLORED(c, R_UTILS_FG_COLOR_GREEN R_UTILS_BG_COLOR_BLACK, __VA_ARGS__)
#define R_UTILS_PRINT_YELLOW_BG_BLACK(c,...) R_UTILS_PRINT_COLORED(c, R_UTILS_FG_COLOR_YELLOW R_UTILS_BG_COLOR_BLACK, __VA_ARGS__)
#define R_UTILS_PRINT_BLUE_BG_WHITE(c,...) R_UTILS_PRINT_COLORED(c, R_UTILS_FG_COLOR_BLUE R_UTILS_BG_COLOR_WHITE, __VA_ARGS__)

#define R_UTILS_FPRINT_WHITE_BG_BLACK(s,c,...) R_UTILS_FPRINT_COLORED(s,c, R_UTILS_FG_COLOR_WHITE R_UTILS_BG_COLOR_BLACK, __VA_ARGS__)
#define R_UTILS_FPRINT_BLACK_BG_WHITE(s,c,...) R_UTILS_FPRINT_COLORED(s,c, R_UTILS_FG_COLOR_BLACK R_UTILS_BG_COLOR_WHITE, __VA_ARGS__)
#define R_UTILS_FPRINT_RED_BG_BLACK(s,c,...) R_UTILS_FPRINT_COLORED(s,c, R_UTILS_FG_COLOR_RED R_UTILS_BG_COLOR_BLACK, __VA_ARGS__)
#define R_UTILS_FPRINT_GREEN_BG_BLACK(s,c,...) R_UTILS_FPRINT_COLORED(s,c, R_UTILS_FG_COLOR_GREEN R_UTILS_BG_COLOR_BLACK, __VA_ARGS__)
#define R_UTILS_FPRINT_YELLOW_BG_BLACK(s,c,...) R_UTILS_FPRINT_COLORED(s,c, R_UTILS_FG_COLOR_YELLOW R_UTILS_BG_COLOR_BLACK, __VA_ARGS__)
#define R_UTILS_FPRINT_BLUE_BG_WHITE(s,c,...) R_UTILS_FPRINT_COLORED(s,c, R_UTILS_FG_COLOR_BLUE R_UTILS_BG_COLOR_WHITE, __VA_ARGS__)


/* =========================================================================
   WARN display an error message,
   WARNX display an error message, and the error associed to errno
   ERR display an error message & exit
   ERRX display an error message, the error associed to errno & exit
   ======================================================================= */

#define R_UTILS_WARNX(...) do {					\
    fprintf(stderr, "[-] ");					\
    fprintf(stderr, __VA_ARGS__);				\
    fprintf(stderr, " : %s\n", strerror(errno));		\
  }while(0)

#define R_UTILS_WARN(...) do {					\
    fprintf(stderr, "[-] ");					\
    fprintf(stderr, __VA_ARGS__);				\
    fprintf(stderr, "\n");					\
  }while(0)

#define R_UTILS_ERRX(...) do {					\
    R_UTILS_WARNX(__VA_ARGS__);					\
    exit(EXIT_FAILURE);						\
  }while(0)


#define R_UTILS_ERR(...) do {					\
    R_UTILS_WARN(__VA_ARGS__);					\
    exit(EXIT_FAILURE);						\
  }while(0)

#ifndef NDEBUG
#define R_UTILS_DEBUG(...) do {			\
    fprintf(stderr, "[DEBUG] ");		\
    fprintf(stderr, __VA_ARGS__);		\
    fprintf(stderr, "\n");			\
  }while(0)
#else
#define DEBUG(...)
#endif


/* =========================================================================
   ======================================================================= */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef u8 byte_t;
typedef u64 addr_t;
typedef u64 len_t;

/* %zu seem to not be standard */
#ifdef __WINDOWS__
#define SIZE_T_FMT_X "Ix"
#define SIZE_T_FMT_D "Id"
#define SIZE_T_FMT_U "Iu"
#else
#define SIZE_T_FMT_X "zx"
#define SIZE_T_FMT_D "zd"
#define SIZE_T_FMT_U "zu"
#endif

void* r_utils_malloc(size_t size);
void* r_utils_calloc(size_t nmemb, size_t size);
void* r_utils_realloc(void *ptr, size_t size);
char* r_utils_strdup(const char *s);
FILE* r_utils_fopen(const char *path, const char *mode);
int r_utils_fseek(FILE *stream, long offset, int whence);
long r_utils_ftell(FILE *stream);

#ifdef __linux__
int r_utils_open(const char *path, int oflag);
ssize_t r_utils_read(int fd, void *buf, size_t count);
ssize_t r_utils_write(int fd, const void *buf, size_t count);
void* r_utils_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
int r_utils_close(int fildes);
int r_utils_fstat(int fildes, struct stat *buf);
pid_t r_utils_fork(void);
int r_utils_execve(const char *path, char *const argv[], char *const envp[]);
#endif


/* =========================================================================
   safe_int.c
   ======================================================================= */

int r_utils_add64(u64 *r, u64 a, u64 b);
int r_utils_add32(u32 *r, u32 a, u32 b);
int r_utils_add16(u16 *r, u16 a, u16 b);
int r_utils_mul64(u64 *r, u64 a, u64 b);
int r_utils_mul32(u32 *r, u32 a, u32 b);
int r_utils_mul16(u16 *r, u16 a, u16 b);
int r_utils_sub64(u64 *r, u64 a, u64 b);
int r_utils_sub32(u32 *r, u32 a, u32 b);
int r_utils_sub16(u16 *r, u16 a, u16 b);

/* =========================================================================
   bytes.c
   ======================================================================= */

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

/* =========================================================================
   misc.c
   ======================================================================= */

int r_utils_dec_to_hexchar(int c);
int r_utils_hexchar_to_dec(int c);
void* r_utils_memsearch(void *src, u64 src_len, void *dst, u64 dst_len);
char* r_utils_alea_filename(char *file, int len);


/* =========================================================================
   hashtable.c
   ======================================================================= */

typedef struct r_utils_hash_elem {
  void *val;
  u8 *key;
  u32 key_len;
  struct r_utils_hash_elem *next;
}r_utils_hash_elem_s;

typedef struct r_utils_hash {
  r_utils_hash_elem_s **elems;
  u32 size;
  u32 colisions;
  void (*elem_destructor)(void*);
}r_utils_hash_s;


void r_utils_hash_foreach(r_utils_hash_s *h, void (*callback)(r_utils_hash_elem_s*));
void r_utils_hash_free(r_utils_hash_s **h);
r_utils_hash_elem_s* r_utils_hash_elem_new(void *elem, u8 *key, u32 key_len);
r_utils_hash_s* r_utils_hash_new(void(*destructor)(void*));
void r_utils_hash_insert(r_utils_hash_s *h, r_utils_hash_elem_s *elem);
r_utils_hash_elem_s* r_utils_hash_find_elem(const r_utils_hash_s *h, int (*cmp)(r_utils_hash_elem_s*, const void*), const void *user);
int r_utils_hash_elem_exist(r_utils_hash_s *h, u8 *key, u32 key_len);
u32 r_utils_hash_size(r_utils_hash_s *h);


/* =========================================================================
   list.c
   ======================================================================= */

typedef struct {
  void **list;
  size_t num;
  size_t head;
}r_utils_list_s;

void r_utils_list_init(r_utils_list_s *l);
void r_utils_list_push(r_utils_list_s *l, void *e);
void* r_utils_list_pop(r_utils_list_s *l);
void *r_utils_list_access(r_utils_list_s *l, size_t i);
size_t r_utils_list_size(r_utils_list_s *l);
void r_utils_list_free(r_utils_list_s *l, void (*free_cb)(void*));
void r_utils_list_sort(r_utils_list_s *l, int (*cmp)(const void*, const void*));


#endif
