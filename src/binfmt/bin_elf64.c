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


/* =========================================================================
   This file contain the functions for loading ELF64 binaries
   ======================================================================= */

/* Load the ELF binary in the bin->mlist */
static void elf64_load_mlist(BINFMT *bin) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)bin->mapped;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(bin->mapped + ehdr->e_phoff);
  int i;
  uint64_t flags;
  uint64_t p_vaddr, p_offset, p_filesz;
  uint32_t p_type, p_flags;
  uint16_t e_phnum;

  bin->mlist = mlist_new();

  e_phnum = endian_get16((byte_t*)&ehdr->e_phnum, bin->endian);

  for(i = 0; i < e_phnum; i++) {
    p_type = endian_get32((byte_t*)&phdr[i].p_type, bin->endian);
    p_flags = endian_get32((byte_t*)&phdr[i].p_flags, bin->endian);
    p_vaddr = endian_get64((byte_t*)&phdr[i].p_vaddr, bin->endian);
    p_offset = endian_get64((byte_t*)&phdr[i].p_offset, bin->endian);
    p_filesz = endian_get64((byte_t*)&phdr[i].p_filesz, bin->endian);

    if(p_type == PT_LOAD) {

      flags = 0;
      if(p_flags & PF_X)
	flags |= MEM_FLAG_PROT_X;
      if(p_flags & PF_R)
	flags |= MEM_FLAG_PROT_R;
      if(p_flags & PF_W)
	flags |= MEM_FLAG_PROT_W;

      mlist_add(bin->mlist, 
		p_vaddr,
		bin->mapped + p_offset,
		p_filesz,
		flags);
    }
  }
}

/* Check some ELF structure fields */
static int elf64_check(BINFMT *bin) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)bin->mapped;
  Elf64_Phdr *phdr;
  int i;
  uint64_t r1, r2;
  uint64_t e_phoff, p_offset, p_filesz;
  uint16_t e_phnum;

  e_phoff = endian_get64((byte_t*)&ehdr->e_phoff, bin->endian);
  e_phnum = endian_get16((byte_t*)&ehdr->e_phnum, bin->endian);
  
  /* Check some ehdr fields */
  if(e_phoff >= bin->mapped_size)
    return 0;

  if(!safe_mul64(&r1, e_phnum, sizeof(Elf64_Phdr)))
    return 0;

  if(!safe_add64(&r2, e_phoff, e_phnum*sizeof(Elf64_Phdr)))
    return 0;

  if(r1 + r2 >= bin->mapped_size)
    return 0;

  /* check some phdr fields; */
  phdr = (Elf64_Phdr*)(bin->mapped + e_phoff);

  for(i = 0; i < e_phnum; i++) {
    p_offset = endian_get64((byte_t*)&phdr[i].p_offset, bin->endian);
    p_filesz = endian_get64((byte_t*)&phdr[i].p_filesz, bin->endian);

    if(!safe_add64(&r1, p_offset, p_filesz))
      return 0;
    if(r1 >= bin->mapped_size)
      return 0;
  }

  return 1;
}

/* Check if it's a ELF64 binary */
static int elf64_is(BINFMT *bin) {

  if(bin->mapped_size < sizeof(Elf64_Ehdr))
     return 0;

  if(memcmp(bin->mapped, ELFMAG, SELFMAG))
    return 0;

  if(bin->mapped[EI_CLASS] != ELFCLASS64)
    return 0;

  return 1;
}

/* Get the architecture */
enum BINFMT_ARCH elf64_getarch(BINFMT *bin) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)bin->mapped;
  
  if(ehdr->e_machine == EM_IA_64)
    return BINFMT_ARCH_X86_64;

  return BINFMT_ARCH_UNDEF;
}

/* Get the endianess */
enum BINFMT_ENDIAN elf64_getendian(BINFMT *bin) {
  if(bin->mapped[EI_DATA] == ELFDATA2LSB)
    return BINFMT_ENDIAN_LITTLE;

  if(bin->mapped[EI_DATA] == ELFDATA2MSB)
    return BINFMT_ENDIAN_BIG;

  return BINFMT_ENDIAN_UNDEF;
}

/* Load elf64, and check the binary */
enum BINFMT_ERR elf64_load(BINFMT *bin) {

  if(!elf64_is(bin))
    return BINFMT_ERR_UNRECOGNIZED;

  bin->type = BINFMT_TYPE_ELF64;
  bin->arch = elf64_getarch(bin);
  bin->endian = elf64_getendian(bin);

  if(bin->arch == BINFMT_ARCH_UNDEF)
    return BINFMT_ERR_NOTSUPPORTED;

  if(bin->endian == BINFMT_ENDIAN_UNDEF)
    return BINFMT_ERR_NOTSUPPORTED;

  if(!elf64_check(bin))
    return BINFMT_ERR_MALFORMEDFILE;

  elf64_load_mlist(bin);

  return BINFMT_ERR_OK;
}
