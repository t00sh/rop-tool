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
#include "api/binfmt.h"



/* =========================================================================
   This file contain generic binary loading function
   ======================================================================= */

typedef struct r_binfmt_loader {
  const char *name;
  r_binfmt_err_e (*load)(r_binfmt_s*);
}r_binfmt_loader_s;

/* List of supported binary formats */
static r_binfmt_loader_s r_binfmt_loaders[] = {
  {"elf32",   r_binfmt_elf32_load},
  {"elf64",   r_binfmt_elf64_load},
  {"pe",      r_binfmt_pe_load},
  {"macho32", r_binfmt_macho32_load},
  {"macho64", r_binfmt_macho64_load},
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
    return "malformed file (3vil or obfuscated file ?!)";
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

/* Load binary in memory
 * If arch != R_BINFMT_ARCH_UNDEF then the binary is loaded in 'raw mode'
 */
void r_binfmt_load(r_binfmt_s *bin, const char *filename, r_binfmt_arch_e arch) {
  FILE *fd;
  long size;
  int i;
  r_binfmt_err_e err;

  assert(bin != NULL);
  assert(filename != NULL);

  memset(bin, 0, sizeof(*bin));

  fd = r_utils_fopen(filename, "r");
  size = r_binfmt_get_size(fd);

  if(size == LONG_MAX)
    R_UTILS_ERR("File seem to be a directory");

  /* Load binary in memory */
  bin->mapped = r_utils_malloc(size);
  bin->mapped_size = size;
  bin->filename = filename;

  if(fread(bin->mapped, 1, (size_t)size, fd) != (size_t)size)
    R_UTILS_ERR("Error while read binary file");

  if(arch != R_BINFMT_ARCH_UNDEF) {
    r_binfmt_raw_load(bin, arch);
    return;
  }

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

void r_binfmt_write(r_binfmt_s *bin, const char *filename) {
  FILE *fd;

    fd = r_utils_fopen(filename, "w");

    if(fwrite(bin->mapped, 1, bin->mapped_size, fd) != bin->mapped_size) {
      fclose(fd);
      R_UTILS_ERRX("Error while writing on file %s !", filename);
    }
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

/* Apply callback to each binary segment, which match flags */
void r_binfmt_foreach_mem(r_binfmt_s *bin, void (*callback)(r_binfmt_mem_s*), u32 flags) {
  r_binfmt_mem_s *m;

  assert(bin != NULL);
  assert(callback != NULL);

  for(m = bin->mlist->head; m != NULL; m = m->next) {
    if(m->flags & flags)
      callback(m);
  }
}

/* Get memory flags as a string */
void r_binfmt_get_mem_flag_str(char str[4], r_binfmt_mem_s *mem) {
  int i;

  assert(mem != NULL);

  i = 0;
  if(mem->flags & R_BINFMT_MEM_FLAG_PROT_R)
    str[i++] = 'R';
  else
    str[i++] = '-';
  if(mem->flags & R_BINFMT_MEM_FLAG_PROT_W)
    str[i++] = 'W';
  else
    str[i++] = '-';
  if(mem->flags & R_BINFMT_MEM_FLAG_PROT_X)
    str[i++] = 'X';
  else
    str[i++] = '-';

  str[i] = '\0';
}

/* Convert string to binary architecture */
r_binfmt_arch_e r_binfmt_string_to_arch(const char *str) {
  assert(str != NULL);

  if(!strcmp(str, "x86"))
    return R_BINFMT_ARCH_X86;
  if(!strcmp(str, "x86-64"))
    return R_BINFMT_ARCH_X86_64;
  if(!strcmp(str, "arm"))
    return R_BINFMT_ARCH_ARM;
  if(!strcmp(str, "arm64"))
    return R_BINFMT_ARCH_ARM64;
  return R_BINFMT_ARCH_UNDEF;
}

/* Convert binary architecture to string */
const char* r_binfmt_arch_to_string(r_binfmt_arch_e arch) {
  switch(arch) {
  case R_BINFMT_ARCH_X86:
    return "x86";
  case R_BINFMT_ARCH_X86_64:
    return "x86-64";
  case R_BINFMT_ARCH_ARM:
    return "arm";
  case R_BINFMT_ARCH_ARM64:
    return "arm64";
  default:
    return "unknown";
  }
  return "unknown";
}

/* Convert binary type to string */
const char* r_binfmt_type_to_string(r_binfmt_type_e type) {
  switch(type) {
  case R_BINFMT_TYPE_ELF32:
    return "ELF32";
  case R_BINFMT_TYPE_ELF64:
    return "ELF64";
  case R_BINFMT_TYPE_PE:
    return "PE";
  case R_BINFMT_TYPE_MACHO32:
    return "Mach-O (32 bits)";
  case R_BINFMT_TYPE_MACHO64:
    return "Mach-O (64 bits)";
  case R_BINFMT_TYPE_RAW:
    return "raw";
  default:
    return "unkown";
  }
  return "unknown";
}

/* Convert binary endianess to string */
const char* r_binfmt_endian_to_string(r_binfmt_endian_e endian) {
  switch(endian) {
  case R_BINFMT_ENDIAN_BIG:
    return "big endian";
  case R_BINFMT_ENDIAN_LITTLE:
    return "little endian";
  default:
    return "unkown";
  }
  return "unknown";
}

/* Get address size of binary architecture */
int r_binfmt_addr_size(r_binfmt_arch_e arch) {
  if(arch == R_BINFMT_ARCH_X86)
    return 4;
  if(arch == R_BINFMT_ARCH_X86_64)
    return 8;
  if(arch == R_BINFMT_ARCH_ARM)
    return 4;
  if(arch == R_BINFMT_ARCH_ARM64)
    return 8;
  return 8;
}

int r_binfmt_is_bad_addr(r_utils_bytes_s *bad, u64 addr, r_binfmt_arch_e arch) {

  switch(r_binfmt_addr_size(arch)) {
  case 4:
    return r_utils_bytes_are_in_addr32(bad, (u32)addr);
  case 8:
    return r_utils_bytes_are_in_addr64(bad, addr);
  }

  return 1;
}

const char *r_binfmt_nx_to_string(r_binfmt_nx_e nx) {
  if(nx == R_BINFMT_NX_ENABLED)
    return "enabled";
  if(nx == R_BINFMT_NX_DISABLED)
    return "disabled";
  return "unknown";
}

void r_binfmt_print_infos(r_binfmt_s *bin, int color) {
  assert(bin != NULL);

  R_UTILS_PRINT_GREEN_BG_BLACK(color, "%-25s", "Filename");
  R_UTILS_PRINT_WHITE_BG_BLACK(color, "%s\n", bin->filename);

  R_UTILS_PRINT_GREEN_BG_BLACK(color, "%-25s", "File format");
  R_UTILS_PRINT_WHITE_BG_BLACK(color, "%s\n", r_binfmt_type_to_string(bin->type));

  R_UTILS_PRINT_GREEN_BG_BLACK(color, "%-25s", "Architecture");
  R_UTILS_PRINT_WHITE_BG_BLACK(color, "%s\n", r_binfmt_arch_to_string(bin->arch));

  R_UTILS_PRINT_GREEN_BG_BLACK(color, "%-25s", "Endianess");
  R_UTILS_PRINT_WHITE_BG_BLACK(color, "%s\n", r_binfmt_endian_to_string(bin->endian));

  R_UTILS_PRINT_GREEN_BG_BLACK(color, "%-25s", "Entry point");
  R_UTILS_PRINT_WHITE_BG_BLACK(color, "%#" PRIx64 "\n", bin->entry);

  R_UTILS_PRINT_GREEN_BG_BLACK(color, "%-25s", "Loadables segments");
  R_UTILS_PRINT_WHITE_BG_BLACK(color, "%d\n", r_binfmt_mlist_size(bin->mlist));

  R_UTILS_PRINT_GREEN_BG_BLACK(color, "%-25s", "NX bit");
  R_UTILS_PRINT_WHITE_BG_BLACK(color, "%s\n", r_binfmt_nx_to_string(bin->nx));

}
