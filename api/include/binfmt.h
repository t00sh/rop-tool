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
#ifndef DEF_API_BINFMT_H
#define DEF_API_BINFMT_H

#include "utils.h"
#include "binfmt/elf.h"

#define R_BINFMT_BAD_ADDR ((u64)-1)
#define R_BINFMT_BAD_OFFSET ((u64)-1)

#define R_BINFMT_ASSERT(expr) do {                                      \
    if(!(expr)) {                                                       \
      R_UTILS_WARN("%s:%d -> assertion failed (malformed file) : `%s`", \
		   __FILE__, __LINE__, #expr);				\
      return;                                                           \
    }                                                                   \
  } while(0)

#define R_BINFMT_ASSERT_RET(ret,expr) do {                              \
    if(!(expr)) {                                                       \
      R_UTILS_WARN("%s:%d -> assertion failed (malformed file) : `%s`", \
		   __FILE__, __LINE__, #expr);				\
      return ret;                                                       \
    }                                                                   \
  } while(0)

typedef enum r_binfmt_segment_flag {
  R_BINFMT_SEGMENT_FLAG_NONE=0,
  R_BINFMT_SEGMENT_FLAG_PROT_X=1,
  R_BINFMT_SEGMENT_FLAG_PROT_R=2,
  R_BINFMT_SEGMENT_FLAG_PROT_W=4,
}r_binfmt_segment_flag_e;

typedef struct r_binfmt_segment {
  addr_t addr;
  len_t length;
  u32 flags;
  byte_t *start;
}r_binfmt_segment_s;

typedef enum r_binfmt_err {
  R_BINFMT_ERR_OK=0,
  R_BINFMT_ERR_UNRECOGNIZED,
  R_BINFMT_ERR_NOTSUPPORTED,
  R_BINFMT_ERR_MALFORMEDFILE
}r_binfmt_err_e;

typedef enum r_binfmt_type {
  R_BINFMT_TYPE_UNDEF=0,
  R_BINFMT_TYPE_ELF32,
  R_BINFMT_TYPE_ELF64,
  R_BINFMT_TYPE_PE,
  R_BINFMT_TYPE_MACHO32,
  R_BINFMT_TYPE_MACHO64,
  R_BINFMT_TYPE_RAW
}r_binfmt_type_e;

typedef enum r_binfmt_endian {
  R_BINFMT_ENDIAN_UNDEF=0,
  R_BINFMT_ENDIAN_LITTLE,
  R_BINFMT_ENDIAN_BIG
}r_binfmt_endian_e;

typedef enum r_binfmt_arch {
  R_BINFMT_ARCH_UNDEF=0,
  R_BINFMT_ARCH_X86,
  R_BINFMT_ARCH_X86_64,
  R_BINFMT_ARCH_ARM,
  R_BINFMT_ARCH_ARM64,
  R_BINFMT_ARCH_MIPS,
  R_BINFMT_ARCH_MIPS64,
}r_binfmt_arch_e;

typedef enum {
  R_BINFMT_NX_UNKNOWN,
  R_BINFMT_NX_ENABLED,
  R_BINFMT_NX_DISABLED
}r_binfmt_nx_e;

typedef enum {
  R_BINFMT_SSP_UNKNOWN,
  R_BINFMT_SSP_ENABLED,
  R_BINFMT_SSP_DISABLED
}r_binfmt_ssp_e;

typedef enum {
  R_BINFMT_RELRO_UNKNOWN,
  R_BINFMT_RELRO_DISABLED,
  R_BINFMT_RELRO_PARTIAL,
  R_BINFMT_RELRO_FULL
}r_binfmt_relro_e;

typedef enum {
  R_BINFMT_PIE_UNKNOWN,
  R_BINFMT_PIE_DISABLED,
  R_BINFMT_PIE_ENABLED,
}r_binfmt_pie_e;

typedef enum {
  R_BINFMT_RPATH_UNKNOWN,
  R_BINFMT_RPATH_DISABLED,
  R_BINFMT_RPATH_ENABLED,
}r_binfmt_rpath_e;

typedef enum {
  R_BINFMT_RUNPATH_UNKNOWN,
  R_BINFMT_RUNPATH_DISABLED,
  R_BINFMT_RUNPATH_ENABLED,
}r_binfmt_runpath_e;


typedef struct {
  const char *name;
  u64 addr;
}r_binfmt_sym_s;

typedef struct {
  const char *name;
  u64 addr;
  u64 size;
}r_binfmt_section_s;

typedef struct binfmt {
  const char *filename;

  addr_t entry;

  r_binfmt_type_e type;
  r_binfmt_endian_e endian;
  r_binfmt_arch_e arch;

  r_utils_linklist_s segments;
  r_utils_arraylist_s syms;
  r_utils_linklist_s sections;

  union {
    struct {
      r_binfmt_nx_e nx;
      r_binfmt_ssp_e ssp;
      r_binfmt_relro_e relro;
      r_binfmt_rpath_e rpath;
      r_binfmt_runpath_e runpath;
      r_binfmt_pie_e pie;
    }elf;

    struct {

    }pe;

    struct {

    }macho;
  };

  byte_t *mapped;
  size_t mapped_size;

}r_binfmt_s;



r_binfmt_err_e r_binfmt_pe_load(r_binfmt_s *bin);
r_binfmt_err_e r_binfmt_elf64_load(r_binfmt_s *bin);
r_binfmt_err_e r_binfmt_elf32_load(r_binfmt_s *bin);
r_binfmt_err_e r_binfmt_macho32_load(r_binfmt_s *bin);
r_binfmt_err_e r_binfmt_macho64_load(r_binfmt_s *bin);
r_binfmt_err_e r_binfmt_raw_load(r_binfmt_s *, r_binfmt_arch_e, r_binfmt_endian_e);

#include "binfmt/bin.h"
#include "binfmt/endian.h"
#include "binfmt/syms.h"
#include "binfmt/sections.h"
#include "binfmt/segments.h"

#endif
