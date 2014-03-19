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


#define SYSCALL_FATAL_ERROR(...) do {				\
    fprintf(stderr, "[-] ");					\
    fprintf(stderr, __VA_ARGS__);				\
    fprintf(stderr, " : %s\n", strerror(errno));		\
    exit(EXIT_FAILURE);						\
  }while(0)

void *xmalloc(size_t size) {
  void *p;

  if((p = malloc(size)) == NULL)
    SYSCALL_FATAL_ERROR("malloc(%zu)", size);

  return p;
}

void* xcalloc(size_t nmemb, size_t size) {
  void *p;

  if((p = calloc(nmemb, size)) == NULL)
    SYSCALL_FATAL_ERROR("calloc(%zu,%zu)", nmemb, size);

  return p;
}

char* xstrdup(const char *s) {
  char *p;

  if((p = strdup(s)) == NULL)
    SYSCALL_FATAL_ERROR("strdup(\"%s\")", s);

  return p;
}

FILE* xfopen(const char *path, const char *mode) {
  FILE *ret;

  if((ret = fopen(path, mode)) == NULL)
    SYSCALL_FATAL_ERROR("fopen(\"%s\", \"%s\")", path, mode);

  return ret;
}

void* xrealloc(void *ptr, size_t size) {
  void *p;

  if((p = realloc(ptr, size)) == NULL)
    SYSCALL_FATAL_ERROR("realloc(%p, %zu)", ptr, size);

  return p;
}

int xfseek(FILE *stream, long offset, int whence) {
  int ret;

  if((ret = fseek(stream, offset, whence)) == -1)
    SYSCALL_FATAL_ERROR("fseek(%p, %ld, %d)", stream, offset, whence);

  return ret;
}

long xftell(FILE *stream) {
  long ret;

  if((ret = ftell(stream)) == -1)
    SYSCALL_FATAL_ERROR("ftell(%p)", stream);

  return ret;
}
