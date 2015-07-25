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
#include "api/binfmt/macho.h"


/* =========================================================================
   This file implement functions for parsing Mach-O (32 bits) binaries
   ======================================================================= */


/* Check if the binary is an Mach-O 32 file */
static int r_binfmt_macho32_is(r_binfmt_s *bin) {
  r_binfmt_macho32_header_s *hdr;

  if(bin->mapped_size < sizeof(*hdr))
     return 0;

  hdr = (r_binfmt_macho32_header_s*)(bin->mapped);

  if(hdr->h_magic == R_BINFMT_MACHO32_MAGIC ||
     hdr->h_magic == R_BINFMT_MACHO32_CIGAM)
    return 1;

  return 0;
}

static r_binfmt_arch_e r_binfmt_macho32_getarch(r_binfmt_s *bin) {
  r_binfmt_macho32_header_s *hdr;
  u32 cpu;

  hdr = (r_binfmt_macho32_header_s*)(bin->mapped);
  cpu = r_binfmt_get_int32((byte_t*)&hdr->h_cpu, bin->endian);

  if(cpu == R_BINFMT_MACHO_CPU_X86)
    return R_BINFMT_ARCH_X86;

  return R_BINFMT_ARCH_UNDEF;
}

static r_binfmt_endian_e r_binfmt_macho32_getendian(r_binfmt_s *bin) {
  r_binfmt_macho32_header_s *hdr;

  hdr = (r_binfmt_macho32_header_s*)(bin->mapped);

#if __ORDER_LITTLE_ENDIAN__
  if(hdr->h_magic == R_BINFMT_MACHO32_MAGIC)
    return R_BINFMT_ENDIAN_LITTLE;
  if(hdr->h_magic == R_BINFMT_MACHO32_CIGAM)
    return R_BINFMT_ENDIAN_BIG;
#elif __ORDER_BIG_ENDIAN__
  if(hdr->h_magic == R_BINFMT_MACHO32_MAGIC)
    return R_BINFMT_ENDIAN_BIG;
  if(hdr->h_magic == R_BINFMT_MACHO32_CIGAM)
    return R_BINFMT_ENDIAN_LITTLE;
#else
#error "Fix endian constantes !"
#endif
  return R_BINFMT_ENDIAN_UNDEF;
}

static void r_binfmt_macho32_load_segment(r_binfmt_s *bin, r_binfmt_macho32_segment_s *s) {
  r_binfmt_segment_s *seg;
  u32 vaddr, filesz, fileoff, initprot;
  u32 flags;

  seg = r_binfmt_segment_new();

  vaddr    = r_binfmt_get_int32((byte_t*)&s->vm_addr, bin->endian);
  filesz   = r_binfmt_get_int32((byte_t*)&s->file_size, bin->endian);
  fileoff  = r_binfmt_get_int32((byte_t*)&s->file_off, bin->endian);
  initprot = r_binfmt_get_int32((byte_t*)&s->init_prot, bin->endian);

  flags = 0;
  if(initprot & R_BINFMT_MACHO_PROT_R)
    flags |= R_BINFMT_MEM_FLAG_PROT_R;
  if(initprot & R_BINFMT_MACHO_PROT_W)
    flags |= R_BINFMT_MEM_FLAG_PROT_W;
  if(initprot & R_BINFMT_MACHO_PROT_X)
    flags |= R_BINFMT_MEM_FLAG_PROT_X;

  seg->flags = flags;
  seg->addr = vaddr;
  seg->start = bin->mapped + fileoff;
  seg->length = filesz;

  r_utils_list_push(&bin->segments, seg);
}

static void r_binfmt_macho32_load_segments(r_binfmt_s *bin) {
  r_binfmt_macho32_header_s *hdr;
  r_binfmt_macho_cmd_s *cmd;
  u32 i, cmd_num, type, off;

  hdr = (r_binfmt_macho32_header_s*)(bin->mapped);
  cmd_num = r_binfmt_get_int32((byte_t*)&hdr->h_cmd_num, bin->endian);


  off = 0;
  for(i = 0; i < cmd_num; i++) {
    cmd = (r_binfmt_macho_cmd_s*)(bin->mapped + sizeof(r_binfmt_macho32_header_s) + off);
    type = r_binfmt_get_int32((byte_t*)&cmd->type, bin->endian);
    if(type == R_BINFMT_MACHO_CMD_TYPE_SEGMENT) {
      r_binfmt_macho32_load_segment(bin, (r_binfmt_macho32_segment_s*)cmd);
    }

    off += r_binfmt_get_int32((byte_t*)&cmd->size, bin->endian);
  }
}

/* Check the fields of the machoXX segment */
static int r_binfmt_macho32_check_segment(r_binfmt_s *bin, r_binfmt_macho32_segment_s *seg) {
  u32 filesz, fileoff;
  u32 off;

  off = ((byte_t*)seg) - bin->mapped;

  if(!r_utils_add32(NULL, off, sizeof(*seg)))
    return 0;

  if(bin->mapped_size < off + sizeof(*seg))
    return 0;

  filesz   = r_binfmt_get_int32((byte_t*)&seg->file_size, bin->endian);
  fileoff  = r_binfmt_get_int32((byte_t*)&seg->file_off, bin->endian);

  if(!r_utils_add32(&off, fileoff, filesz))
    return 0;

  if(bin->mapped_size < off)
    return 0;

  return 1;
}

/* Check evil or malformed files */
static int r_binfmt_macho32_check(r_binfmt_s *bin) {
  r_binfmt_macho32_header_s *hdr;
  r_binfmt_macho_cmd_s *cmd;
  u32 tmp, i, cmd_num, cmd_size, off, type;

  /* Already checked in r_binfmt_machoXX_is(),
     but if the check is removed in the future, the
     r_binfmt_machoXX_check() function must handle this case */
  if(bin->mapped_size < sizeof(*hdr))
    return 0;

  hdr = (r_binfmt_macho32_header_s*)(bin->mapped);

  cmd_num = r_binfmt_get_int32((byte_t*)&hdr->h_cmd_num, bin->endian);

  /* Check each command */
  off = 0;
  for(i = 0; i < cmd_num; i++) {

    /* Check if off+sizeof(*hdr)+sizeof(*cmd) isn't greater than
       bin->mapped_size */
    if(!r_utils_add32(&tmp, sizeof(*hdr)+sizeof(*cmd), off))
      return 0;
    if(bin->mapped_size < tmp)
      return 0;

    cmd = (r_binfmt_macho_cmd_s*)(bin->mapped + off + sizeof(*hdr));

    /* Now check command */
    type = r_binfmt_get_int32((byte_t*)&cmd->type, bin->endian);
    if(type == R_BINFMT_MACHO_CMD_TYPE_SEGMENT) {
      if(!r_binfmt_macho32_check_segment(bin, (r_binfmt_macho32_segment_s*)cmd))
	return 0;
    }

    cmd_size = r_binfmt_get_int32((byte_t*)&cmd->size, bin->endian);
    if(!cmd_size)
      return 0;
    if(!r_utils_add32(&off, off, cmd_size))
      return 0;
  }

  return 1;
}

/* Fill the r_binfmt_s structure if it's a correct Mach-O 32 file */
r_binfmt_err_e r_binfmt_macho32_load(r_binfmt_s *bin) {

  if(!r_binfmt_macho32_is(bin))
    return R_BINFMT_ERR_UNRECOGNIZED;

  bin->type = R_BINFMT_TYPE_MACHO32;
  bin->endian = r_binfmt_macho32_getendian(bin);
  bin->arch = r_binfmt_macho32_getarch(bin);

  if(bin->arch == R_BINFMT_ARCH_UNDEF)
    return R_BINFMT_ERR_NOTSUPPORTED;

  if(bin->endian == R_BINFMT_ENDIAN_UNDEF)
    return R_BINFMT_ERR_NOTSUPPORTED;

  if(!r_binfmt_macho32_check(bin))
    return R_BINFMT_ERR_MALFORMEDFILE;

  bin->entry = 0;
  r_binfmt_macho32_load_segments(bin);

  return R_BINFMT_ERR_OK;
}
