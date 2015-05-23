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
   This file implement functions for parsing ELF32 binaries
   ======================================================================= */

/* Fill bin->mlist structure */
static void r_binfmt_elf32_load_mlist(r_binfmt_s *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)bin->mapped;
  Elf32_Phdr *phdr;
  int i;
  u32 flags;
  u32 p_type, p_flags, p_vaddr, p_offset, p_filesz;
  u16 e_phnum;

  bin->mlist = r_binfmt_mlist_new();

  phdr = (Elf32_Phdr*)(bin->mapped + r_binfmt_get_int32((byte_t*)&ehdr->e_phoff, bin->endian));

  e_phnum = r_binfmt_get_int16((byte_t*)&ehdr->e_phnum, bin->endian);

  for(i = 0; i < e_phnum; i++) {
    p_type = r_binfmt_get_int32((byte_t*)&phdr[i].p_type, bin->endian);
    p_flags = r_binfmt_get_int32((byte_t*)&phdr[i].p_flags, bin->endian);
    p_vaddr = r_binfmt_get_int32((byte_t*)&phdr[i].p_vaddr, bin->endian);
    p_offset = r_binfmt_get_int32((byte_t*)&phdr[i].p_offset, bin->endian);
    p_filesz = r_binfmt_get_int32((byte_t*)&phdr[i].p_filesz, bin->endian);

    if(p_type == PT_LOAD) {

      flags = 0;
      if(p_flags & PF_X)
	flags |= R_BINFMT_MEM_FLAG_PROT_X;
      if(p_flags & PF_R)
	flags |= R_BINFMT_MEM_FLAG_PROT_R;
      if(p_flags & PF_W)
	flags |= R_BINFMT_MEM_FLAG_PROT_W;

      r_binfmt_mlist_add(bin->mlist,
		     p_vaddr,
		     bin->mapped + p_offset,
		     p_filesz,
		     flags);
    }
  }
}

/* Check some ELF fields */
static int r_binfmt_elf32_check(r_binfmt_s *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)bin->mapped;
  Elf32_Phdr *phdr;
  int i;
  u32 r1, r2;
  u32 e_phoff, p_offset, p_filesz;
  u16 e_phnum;

  e_phoff = r_binfmt_get_int32((byte_t*)&ehdr->e_phoff, bin->endian);
  e_phnum = r_binfmt_get_int16((byte_t*)&ehdr->e_phnum, bin->endian);

  /* Check some ehdr fields */
  if(e_phoff >= bin->mapped_size)
    return 0;

  if(!r_utils_mul32(&r1, e_phnum, sizeof(Elf32_Phdr)))
    return 0;

  if(!r_utils_add32(&r2, e_phoff, e_phnum*sizeof(Elf32_Phdr)))
    return 0;

  if(r1 + r2 >= bin->mapped_size)
    return 0;

  /* check some phdr fields; */
  phdr = (Elf32_Phdr*)(bin->mapped + e_phoff);

  for(i = 0; i < e_phnum; i++) {
    p_offset = r_binfmt_get_int32((byte_t*)&phdr[i].p_offset, bin->endian);
    p_filesz = r_binfmt_get_int32((byte_t*)&phdr[i].p_filesz, bin->endian);

    if(!r_utils_add32(&r1, p_offset, p_filesz))
      return 0;
    if(r1 >= bin->mapped_size)
      return 0;
  }

  return 1;
}

/* Check if the binary is an ELF32 file */
static int r_binfmt_elf32_is(r_binfmt_s *bin) {

  if(bin->mapped_size < sizeof(Elf32_Ehdr))
     return 0;

  if(memcmp(bin->mapped, ELFMAG, SELFMAG))
    return 0;

  if(bin->mapped[EI_CLASS] != ELFCLASS32)
    return 0;

  return 1;
}

/* Get the architecture */
static r_binfmt_arch_e r_binfmt_elf32_getarch(r_binfmt_s *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)bin->mapped;

  if(ehdr->e_machine == EM_386)
    return R_BINFMT_ARCH_X86;
  if(ehdr->e_machine == EM_ARM)
    return R_BINFMT_ARCH_ARM;

  return R_BINFMT_ARCH_UNDEF;
}

/* Get the endianness */
static r_binfmt_endian_e r_binfmt_elf32_getendian(r_binfmt_s *bin) {
  if(bin->mapped[EI_DATA] == ELFDATA2LSB)
    return R_BINFMT_ENDIAN_LITTLE;
  if(bin->mapped[EI_DATA] == ELFDATA2MSB)
    return R_BINFMT_ENDIAN_BIG;

  return R_BINFMT_ENDIAN_UNDEF;
}

static addr_t r_binfmt_elf32_getentry(r_binfmt_s *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)(bin->mapped);
  return r_binfmt_get_int32((byte_t*)&ehdr->e_entry, bin->endian);
}

/* Check if NX bit is enabled */
static r_binfmt_nx_e r_binfmt_elf32_check_nx(r_binfmt_s *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)(bin->mapped);
  Elf32_Phdr *phdr;
  u32 i, p_type;
  u16 e_phnum;

  phdr = (Elf32_Phdr*)(bin->mapped + r_binfmt_get_int32((byte_t*)&ehdr->e_phoff, bin->endian));

  e_phnum = r_binfmt_get_int16((byte_t*)&ehdr->e_phnum, bin->endian);

  for(i = 0; i < e_phnum; i++) {
    p_type = r_binfmt_get_int32((byte_t*)&phdr[i].p_type, bin->endian);
    if(p_type == PT_GNU_STACK)
      return R_BINFMT_NX_ENABLED;
  }
  return R_BINFMT_NX_DISABLED;
}

/* Fill the BINFMT structure if it's a correct ELF32 */
r_binfmt_err_e r_binfmt_elf32_load(r_binfmt_s *bin) {

  if(!r_binfmt_elf32_is(bin))
    return R_BINFMT_ERR_UNRECOGNIZED;

  bin->type = R_BINFMT_TYPE_ELF32;
  bin->arch = r_binfmt_elf32_getarch(bin);
  bin->endian = r_binfmt_elf32_getendian(bin);

  if(bin->arch == R_BINFMT_ARCH_UNDEF)
    return R_BINFMT_ERR_NOTSUPPORTED;

  if(bin->endian == R_BINFMT_ENDIAN_UNDEF)
    return R_BINFMT_ERR_NOTSUPPORTED;

  if(!r_binfmt_elf32_check(bin))
    return R_BINFMT_ERR_MALFORMEDFILE;

  bin->entry = r_binfmt_elf32_getentry(bin);
  bin->nx = r_binfmt_elf32_check_nx(bin);

  r_binfmt_elf32_load_mlist(bin);

  return R_BINFMT_ERR_OK;
}
