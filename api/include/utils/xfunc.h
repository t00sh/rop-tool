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

#ifndef DEF_API_UTILS_XFUNC_H
#define DEF_API_UTILS_XFUNC_H

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

#endif
