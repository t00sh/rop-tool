/************************************************************************/
/* rop-tool - A Return Oriented Programming and binary exploitation     */
/*            tool                                                      */
/* 								        */
/* Copyright 2013-2015, -TOSH-					        */
/* File coded by -TOSH-						        */
/* 								        */
/* This file is part of rop-tool.	       			        */
/* 								        */
/* rop-tool is free software: you can redistribute it and/or modify     */
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
#define _GNU_SOURCE
#include "rop.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void* (*heap_fun_malloc)(size_t);
void* (*heap_fun_realloc)(void*, size_t);
void* (*heap_fun_calloc)(size_t, size_t);
void* (*heap_fun_free)(void*);

struct malloc_chunk_header {
  size_t prev_size;
  size_t size;
};

static int libc_initialized = 0;
static int initialize = 0;

#define TMP_HEAP_SIZE 0x1000

static u8 tmp_heap[TMP_HEAP_SIZE];
static size_t tmp_heap_allocated = 0;

#define PREV_INUSE 0x1
#define IS_MMAPED 0x2
#define NON_MAIN_ARENA 0x4

#define CHUNK_CHECK_FLAG(c,f) (c->size & f)
#define CHUNK_SIZE(c) (c->size & ~(PREV_INUSE|IS_MMAPED|NON_MAIN_ARENA))
#define GET_CHUNK(ptr) ((struct malloc_chunk_header*)(ptr - 2*sizeof(size_t)))

#define DUMP_HEAP(...) do {dump_heap();printf(__VA_ARGS__);}while(0)


static struct malloc_chunk_header *first_chunk = NULL;
static struct malloc_chunk_header *last_chunk = NULL;

void dump_chunk(struct malloc_chunk_header *chunk) {
  printf("+++++++++++++++++++++++++++++++++++++++++++++\n");
  printf("+ ADDR: %-36p+\n", chunk);
  printf("+ USER_ADDR: %-31p+\n", ((u8*)(chunk)) + 2*sizeof(size_t));

  if(!CHUNK_CHECK_FLAG(chunk, IS_MMAPED) &&
     !CHUNK_CHECK_FLAG(chunk, PREV_INUSE))
    printf("+ PREV_SIZE: %-31" SIZE_T_FMT_X "+\n", chunk->prev_size);
  else
    printf("+ PREV_SIZE: UNUSED                         +\n");
  printf("+ SIZE: %-36" SIZE_T_FMT_X "+\n", CHUNK_SIZE(chunk));
  printf("+ FLAGS: %c%c                                 +\n",
	 CHUNK_CHECK_FLAG(chunk, IS_MMAPED) ? 'M' : '-',
	 CHUNK_CHECK_FLAG(chunk, PREV_INUSE) ? 'P' : '-');

  printf("+++++++++++++++++++++++++++++++++++++++++++++\n");
}

void dump_heap(void) {
  struct malloc_chunk_header *chunk;

  printf("\n\n######################\n");
  printf("#       HEAP         #\n");
  printf("######################\n");

  chunk = first_chunk;

  while(chunk != NULL) {
    dump_chunk(chunk);

    if(((u8*)(chunk))+CHUNK_SIZE(chunk) > (u8*)last_chunk) {
      chunk = NULL;
    } else {
      chunk = (struct malloc_chunk_header*)(((u8*)(chunk))+CHUNK_SIZE(chunk));
    }
  }
}

void update_chunk(u8 *ptr) {
  if(!CHUNK_CHECK_FLAG(GET_CHUNK(ptr), IS_MMAPED)) {
    if(first_chunk == NULL) {
      first_chunk = last_chunk = GET_CHUNK(ptr);
    } else {
      if(GET_CHUNK(ptr) > last_chunk)
	last_chunk = GET_CHUNK(ptr);
    }
  }
}

void initialize_libc(void) {
  dlerror();

  if((heap_fun_malloc = dlsym(RTLD_NEXT, "malloc")) == NULL) {
    fprintf(stderr, "Can't resolve malloc: %s\n", dlerror());
    exit(EXIT_FAILURE);
  }

  dlerror();

  if((heap_fun_realloc = dlsym(RTLD_NEXT, "realloc")) == NULL) {
    fprintf(stderr, "Can't resolve realloc: %s\n", dlerror());
    exit(EXIT_FAILURE);
  }

  dlerror();

  if((heap_fun_calloc = dlsym(RTLD_NEXT, "calloc")) == NULL) {
    fprintf(stderr, "Can't resolve calloc: %s\n", dlerror());
    exit(EXIT_FAILURE);
  }

  dlerror();

  if((heap_fun_free = dlsym(RTLD_NEXT, "free")) == NULL) {
    fprintf(stderr, "Can't resolve free: %s\n", dlerror());
    exit(EXIT_FAILURE);
  }

  libc_initialized = 1;
}

void* malloc(size_t s) {
  void *p;

  if(!libc_initialized) {
    if(!initialize) {
      initialize = 1;
      initialize_libc();
      initialize = 0;
      p = heap_fun_malloc(s);
    } else {
      if(s > TMP_HEAP_SIZE || s+tmp_heap_allocated > TMP_HEAP_SIZE) {
	fprintf(stderr, "Temporary heap too small for initialization !\n");
	exit(EXIT_FAILURE);
      }

      p = tmp_heap + tmp_heap_allocated;
      tmp_heap_allocated += s;
    }
  } else {
    p = heap_fun_malloc(s);
  }

  if(!initialize) {
    update_chunk(p);
    DUMP_HEAP("malloc(%" SIZE_T_FMT_X ") = %p\n", s, p);
  }
  return p;
}

void* realloc(void *ptr, size_t s) {
  void *p;

  if(!libc_initialized) {
    p = malloc(s);
    if(p && ptr)
      memmove(p, ptr, s);
  } else {
    p = heap_fun_realloc(ptr, s);
  }

  if(!initialize) {
    update_chunk(p);
    DUMP_HEAP("realloc(%p,%" SIZE_T_FMT_X ") = %p\n", ptr, s, p);
  }

  return p;
}

void* calloc(size_t nmemb, size_t size) {
  void *p;

  if(!libc_initialized) {
    p = malloc(nmemb*size);
    if(p)
      memset(p, 0, nmemb*size);
  } else {
    p = heap_fun_calloc(nmemb, size);
  }

  if(!initialize) {
    update_chunk(p);
    DUMP_HEAP("calloc(%" SIZE_T_FMT_X ",%" SIZE_T_FMT_X ") = %p\n", nmemb, size, p);
  }
  return p;
}

void free(void *ptr) {

  if(initialize)
    return;

  if(!libc_initialized)
    initialize_libc();

  heap_fun_free(ptr);
  DUMP_HEAP("free(%p)\n", ptr);
}
