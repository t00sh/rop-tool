#ifndef DEF_XFUNC_H
#define DEF_XFUNC_H

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

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#endif

void *xmalloc(size_t size);
void* xcalloc(size_t nmemb, size_t size);
void* xrealloc(void *ptr, size_t size);
char* xstrdup(const char *s);
FILE* xfopen(const char *path, const char *mode);
int xfseek(FILE *stream, long offset, int whence);
long xftell(FILE *stream);

#ifdef __linux__

int xopen(const char *path, int oflag);
ssize_t xread(int fd, void *buf, size_t count);
ssize_t xwrite(int fd, const void *buf, size_t count);
void* xmmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
int xclose(int fildes);
int xfstat(int fildes, struct stat *buf);
pid_t xfork(void);
int xexecve(const char *path, char *const argv[], char *const envp[]);

#endif // __linux__


#endif
