#include "api/binfmt.h"

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


/* =========================================================================
   This file contain generic binary loading function
   ======================================================================= */

typedef struct r_binfmt_loader {
  const char *name;
  r_binfmt_err_e (*load)(r_binfmt_s*);
}r_binfmt_loader_s;

/* List of supported binary formats */
static r_binfmt_loader_s r_binfmt_loaders[] = {
  {"elf32", r_binfmt_elf32_load},
  //  {"elf64", r_binfmt_elf64_load},
  //  {"pe",    r_binfmt_pe_load},
  {NULL,    NULL}
};

/* Convert errors to string */
static const char* r_binfmt_get_err(r_binfmt_err_e err) {
  switch(err) {
  case R_BINFMT_ERR_OK:
    return "OK";
  case R_BINFMT_ERR_UNRECOGNIZED:
    return "unrecognized file format";
  case R_BINFMT_ERR_NOTSUPPORTED:
    return "not yet supported";
  case R_BINFMT_ERR_MALFORMEDFILE:
    return "malformed file (3vil or offuscated file ?!)";
  }
  return "Unknown error";
}

/* Check some fields of the R_BINFMT */
static void r_binfmt_check(r_binfmt_s *bin) {
  if(bin->endian == R_BINFMT_ENDIAN_UNDEF)
    R_UTILS_ERR("Endianess not supported");

  if(bin->arch == R_BINFMT_ARCH_UNDEF)
    R_UTILS_ERR("Arch not supported");

  if(bin->type == R_BINFMT_TYPE_UNDEF)
    R_UTILS_ERR("File format not recognized");
}

/* Get the size of the file */
static long r_binfmt_get_size(FILE* file) {
  long ret;

  r_utils_fseek(file, 0, SEEK_END);
  ret = r_utils_ftell(file);
  r_utils_fseek(file, 0, SEEK_SET);

  return ret;
}

/* Load binary in memory */
void r_binfmt_load(r_binfmt_s *bin, const char *filename) {
  FILE *fd;
  long size;
  int i;
  r_binfmt_err_e err;

  fd = r_utils_fopen(filename, "r");
  size = r_binfmt_get_size(fd);

  /* Load binary in memory */
  bin->mapped = r_utils_malloc(size);
  bin->mapped_size = size;

  if(fread(bin->mapped, 1, (size_t)size, fd) != (size_t)size)
    R_UTILS_ERR("Error while read binary file");

  /* Raw mode */
  //  if(options_raw) {
  //  r_binfmt_raw_load(bin);
  //  return;
  //}

  /* Call each binary loader to check what file is it */
  for(i = 0; r_binfmt_loaders[i].load != NULL; i++) {
    err = r_binfmt_loaders[i].load(bin);
    if(err == R_BINFMT_ERR_OK) {
      r_binfmt_check(bin);
      break;
    }

    if(err != R_BINFMT_ERR_UNRECOGNIZED)
      R_UTILS_ERR("Error in %s loader : %s", r_binfmt_loaders[i].name, r_binfmt_get_err(err));
  }

  if(r_binfmt_loaders[i].load == NULL)
    R_UTILS_ERR("Format not supported");

  fclose(fd);
}

/* Free the r_binfmt structure */
void r_binfmt_free(r_binfmt_s *bin) {
  r_binfmt_mlist_free(&bin->mlist);
  free(bin->mapped);
}

/* Get the first memory segment which match flags */
r_binfmt_mem_s* r_binfmt_getmem(r_binfmt_s *bin, u32 flags) {
  r_binfmt_mem_s *m;

  for(m = bin->mlist->head; m != NULL; m = m->next) {
    if(m->flags == flags)
      return m;
  }
  return NULL;
}
