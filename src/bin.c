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


typedef struct BINFMT_LIST {
  const char *name;
  enum BINFMT_ERR (*load)(BINFMT*);
}BINFMT_LIST;

static BINFMT_LIST bin_list[] = {
  {"elf32", elf32_load},
  {"elf64", elf64_load},
  {NULL,    NULL}
};

static const char* bin_get_err(enum BINFMT_ERR err) {
  switch(err) {
  case BINFMT_ERR_OK:
    return "OK";
  case BINFMT_ERR_UNRECOGNIZED:
    return "unrecognized file format";
  case BINFMT_ERR_NOTSUPPORTED:
    return "not yet supported";
  case BINFMT_ERR_MALFORMEDFILE:
    return "malformed file (3vil or offuscated file ?!)";
  }
  return "Unknown error";
}

static void bin_check(BINFMT *bin) {
  if(bin->endian == BINFMT_ENDIAN_UNDEF)
    FATAL_ERROR("Endianess not supported");

  if(bin->arch == BINFMT_ARCH_UNDEF)
    FATAL_ERROR("Arch not supported");

  if(bin->type == BINFMT_TYPE_UNDEF)
    FATAL_ERROR("File format not recognized");
}

void bin_load(BINFMT *bin, const char *filename) {
  struct stat st;
  int i, fd;
  enum BINFMT_ERR err;

  fd = xopen(filename, O_RDONLY);  
  xfstat(fd, &st);

  bin->mapped = xmmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  bin->mapped_size = st.st_size;

  if(options_raw) {
    raw_load(bin);
    return;
  }

  for(i = 0; bin_list[i].load != NULL; i++) {
    err = bin_list[i].load(bin);
    if(err == BINFMT_ERR_OK) {
      bin_check(bin);
      return;
    }
    if(err != BINFMT_ERR_UNRECOGNIZED)
      FATAL_ERROR("Error in %s loader : %s", bin_list[i].name, bin_get_err(err));
  }
  FATAL_ERROR("Format not supported");
}

void bin_free(BINFMT *bin) {
  mlist_free(&bin->mlist);
  munmap(bin->mapped, bin->mapped_size);
}

MEM* bin_getmem(BINFMT *bin, uint32_t flags) {
  MEM *m;

  for(m = bin->mlist->head; m != NULL; m = m->next) {
    if(m->flags == flags)
      return m;
  }
  return NULL;
}
