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

#ifndef DEF_BINFMT_MACHO_H
#define DEF_BINFMT_MACHO_H

#include <api/binfmt.h>

/* Mach32-O magics */
#define R_BINFMT_MACHO32_MAGIC 0xFEEDFACE
#define R_BINFMT_MACHO32_CIGAM 0xCEFAEDFE

/* Mach64-O magics */
#define R_BINFMT_MACHO64_MAGIC 0xFEEDFACF
#define R_BINFMT_MACHO64_CIGAM 0xCFFAEDFE

/* Mach32-O header */
typedef struct {
  u32 h_magic;
  u32 h_cpu;
  u32 h_cpu2;
  u32 h_type;
  u32 h_cmd_num;
  u32 h_cmd_size;
  u32 h_flags;
}__attribute__((packed))r_binfmt_macho32_header_s;

/* Mach64-O header */
typedef struct {
  u32 h_magic;
  u32 h_cpu;
  u32 h_cpu2;
  u32 h_type;
  u32 h_cmd_num;
  u32 h_cmd_size;
  u32 h_flags;
  u32 h_reserved;
}__attribute__((packed))r_binfmt_macho64_header_s;

/* Mach-O command structure */
typedef struct {
  u32 type;
  u32 size;
}__attribute__((packed))r_binfmt_macho_cmd_s;

/* Mach32-O segment structure */
typedef struct {
  u32  cmd;
  u32  cmd_size;
  char seg_name[16];
  u32  vm_addr;
  u32  vm_size;
  u32  file_off;
  u32  file_size;
  u32  max_prot;
  u32  init_prot;
  u32  num_sects;
  u32  flags;
}__attribute__((packed))r_binfmt_macho32_segment_s;

/* Mach64-O segment structure */
typedef struct {
  u32  cmd;
  u32  cmd_size;
  char seg_name[16];
  u64  vm_addr;
  u64  vm_size;
  u64  file_off;
  u64  file_size;
  u32  max_prot;
  u32  init_prot;
  u32  num_sects;
  u32  flags;
}__attribute__((packed))r_binfmt_macho64_segment_s;

/* r_binfmt_machoXX_header_s cpu field */
typedef enum {
  R_BINFMT_MACHO_CPU_X86=7,
  R_BINFMT_MACHO_CPU_POWERPC=18,
  R_BINFMT_MACHO_CPU_X86_64=0x01000007,
  R_BINFMT_MACHO_CPU_POWERPC64=0x01000018,
}r_binfmt_macho_cpu_e;

/* r_binfmt_machoXX_header_s type field */
typedef enum {
  R_BINFMT_MACHO_TYPE_OBJECT=1,
  R_BINFMT_MACHO_TYPE_EXEC=2,
  R_BINFMT_MACHO_TYPE_CORE=4,
  R_BINFMT_MACHO_TYPE_DYNLIB=6,
}r_binfmt_macho_type_s;

/* r_binfmt_macho_cmd_s type field */
typedef enum {
  R_BINFMT_MACHO_CMD_TYPE_SEGMENT=0x1,
  R_BINFMT_MACHO_CMD_TYPE_SYMTAB=0x2,
  R_BINFMT_MACHO_CMD_TYPE_UNIXTHREAD=0x5,
  R_BINFMT_MACHO_CMD_TYPE_SEGMENT64=0x19
}r_binfmt_macho_cmd_type_e;

/* r_binfmt_machoXX_segment_s max_prot and init_prot fields */
#define R_BINFMT_MACHO_PROT_R 1
#define R_BINFMT_MACHO_PROT_W 2
#define R_BINFMT_MACHO_PROT_X 4

#endif
