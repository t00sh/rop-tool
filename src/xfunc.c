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

int xopen(const char *path, int oflag) {
  int f;

  if((f = open(path, oflag)) < 0)
    SYSCALL_FATAL_ERROR("open(\"%s\", %d)", path, oflag);

  return f;
}

ssize_t xread(int fd, void *buf, size_t count) {
  ssize_t ret;

  if((ret = read(fd, buf, count)) == -1)
    SYSCALL_FATAL_ERROR("read(%d, %p, %zu)", fd, buf, count);

  return ret;
}

ssize_t xwrite(int fd, const void *buf, size_t count) {
  ssize_t ret;

  if((ret = write(fd, buf, count)) == -1)
    SYSCALL_FATAL_ERROR("write(%d, %p, %zu)", fd, buf, count);

  return ret;
}

void* xrealloc(void *ptr, size_t size) {
  void *p;

  if((p = realloc(ptr, size)) == NULL)
    SYSCALL_FATAL_ERROR("realloc(%p, %zu)", ptr, size);

  return p;
}

void* xmmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off) {
  void *p;

  if((p = mmap(addr, len, prot, flags, fildes, off)) == MAP_FAILED)
    SYSCALL_FATAL_ERROR("mmap(%p, %zu, %d, %d, %d, %ld)", addr, len, prot, flags, fildes, off);

  return p;
}

int xclose(int fildes) {
  int ret;

  if((ret = close(fildes)) == -1)
    SYSCALL_FATAL_ERROR("close(%d)", fildes);

  return ret;
}

int xfstat(int fildes, struct stat *buf) {
  int ret;

  if((ret = fstat(fildes, buf)) == -1)
    SYSCALL_FATAL_ERROR("fstat(%d, %p)", fildes, buf);

  return ret;
}
