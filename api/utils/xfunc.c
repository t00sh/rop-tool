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


void* r_utils_malloc(size_t size) {
  void *p;

  if((p = malloc(size)) == NULL)
    R_UTILS_ERRX("malloc(%zu)", size);

  return p;
}

void* r_utils_calloc(size_t nmemb, size_t size) {
  void *p;

  if((p = calloc(nmemb, size)) == NULL)
    R_UTILS_ERRX("calloc(%zu,%zu)", nmemb, size);

  return p;
}

void* r_utils_realloc(void *ptr, size_t size) {
  void *p;

  if((p = realloc(ptr, size)) == NULL)
    R_UTILS_ERRX("realloc(%p, %zu)", ptr, size);

  return p;
}

char* r_utils_strdup(const char *s) {
  char *p;

  if((p = strdup(s)) == NULL)
    R_UTILS_ERRX("strdup(\"%s\")", s);

  return p;
}

FILE* r_utils_fopen(const char *path, const char *mode) {
  FILE *ret;

  if((ret = fopen(path, mode)) == NULL)
    R_UTILS_ERRX("fopen(\"%s\", \"%s\")", path, mode);

  return ret;
}

int r_utils_fseek(FILE *stream, long offset, int whence) {
  int ret;

  if((ret = fseek(stream, offset, whence)) == -1)
    R_UTILS_ERRX("fseek(%p, %ld, %d)", stream, offset, whence);

  return ret;
}

long r_utils_ftell(FILE *stream) {
  long ret;

  if((ret = ftell(stream)) == -1)
    R_UTILS_ERRX("ftell(%p)", stream);

  return ret;
}

int r_utils_open(const char *path, int oflag) {
  int f;

  if((f = open(path, oflag)) < 0)
    R_UTILS_ERRX("open(\"%s\", %d)", path, oflag);

  return f;
}

ssize_t r_utils_read(int fd, void *buf, size_t count) {
  ssize_t ret;

  if((ret = read(fd, buf, count)) == -1)
    R_UTILS_ERRX("read(%d, %p, %zu)", fd, buf, count);

  return ret;
}

ssize_t r_utils_write(int fd, const void *buf, size_t count) {
  ssize_t ret;

  if((ret = write(fd, buf, count)) == -1)
    R_UTILS_ERRX("write(%d, %p, %zu)", fd, buf, count);

  return ret;
}

void* r_utils_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off) {
  void *p;

  if((p = mmap(addr, len, prot, flags, fildes, off)) == MAP_FAILED)
    R_UTILS_ERRX("mmap(%p, %zu, %d, %d, %d, %ld)", addr, len, prot, flags, fildes, off);

  return p;
}

int r_utils_close(int fildes) {
  int ret;

  if((ret = close(fildes)) == -1)
    R_UTILS_ERRX("close(%d)", fildes);

  return ret;
}

int r_utils_fstat(int fildes, struct stat *buf) {
  int ret;

  if((ret = fstat(fildes, buf)) == -1)
    R_UTILS_ERRX("fstat(%d, %p)", fildes, buf);

  return ret;
}

pid_t r_utils_fork(void) {
  pid_t ret;

  if((ret = fork()) == -1)
    R_UTILS_ERRX("fork()");

  return ret;
}

int r_utils_execve(const char *path, char *const argv[], char *const envp[]) {
  int ret;

  if((ret = execve(path, argv, envp)) == -1)
    R_UTILS_ERRX("execve(%s, %p, %p)", path, argv, envp);

  return ret;
}
