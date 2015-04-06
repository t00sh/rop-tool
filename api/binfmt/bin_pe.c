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

/*
	libpe - the PE library

	Copyright (C) 2010 - 2012 Fernando Mercês
	Copyright (C) 2013 - 2014 Duret Simon (-TOSH-)

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define PE32 0x10b
#define PE64 0x20b
#define MZ 0x5a4d

typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint64_t QWORD;

enum PE_MACHINE {
  PE_MACHINE_UNDEF=0,
  PE_MACHINE_I386=0x14c,
  PE_MACHINE_I860=0x14d,
  PE_MACHINE_IA64=0x200,
  PE_MACHINE_AMD64=0x8664,
};

enum PE_IMAGE_SCN {
  IMAGE_SCN_TYPE_NO_PAD=0x8,
  IMAGE_SCN_CNT_CODE=0x20,
  IMAGE_SCN_CNT_INITIALIZED_DATA=0x80,
  IMAGE_SCN_CNT_UNINITIALIZED_DATA=0X100,
  IMAGE_SCN_MEM_EXECUTE=0x20000000,
  IMAGE_SCN_MEM_READ=0x40000000,
  IMAGE_SCN_MEM_WRITE=0x80000000
};

typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER, IMAGE_COFF_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER_32 {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	DWORD BaseOfData; // only PE32
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Reserved1;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	// IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_32;

/* note some fields are quad-words */
typedef struct _IMAGE_OPTIONAL_HEADER_64 {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	QWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Reserved1;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	QWORD SizeOfStackReserve;
	QWORD SizeOfStackCommit;
	QWORD SizeOfHeapReserve;
	QWORD SizeOfHeapCommit;
	DWORD LoaderFlags; /* must be zero */
	DWORD NumberOfRvaAndSizes;
	// IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_64;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress; // same value as next field
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations; // always zero in executables
	DWORD PointerToLinenumbers; // deprecated
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers; // deprecated
	DWORD Characteristics;
} IMAGE_SECTION_HEADER;


#define R_BINFMT_PE_MAGIC 0x4550

/* Get the dos header */
static IMAGE_DOS_HEADER* pe_get_dos(r_binfmt_s *bin) {
  return (IMAGE_DOS_HEADER*)(bin->mapped);
}

/* Get the address of the coff header */
static WORD pe_get_addr_coff(r_binfmt_s *bin) {
  IMAGE_DOS_HEADER *dos;

  dos = pe_get_dos(bin);

  return dos->e_lfanew + 4;
}

/* Get the coff header */
static IMAGE_COFF_HEADER* pe_get_coff(r_binfmt_s *bin) {
  IMAGE_COFF_HEADER *coff;
  WORD addr_coff;

  addr_coff = pe_get_addr_coff(bin);

  coff = (IMAGE_COFF_HEADER*)(bin->mapped + addr_coff);

  return coff;
}

/* Get the PE arch (PE32 or PE64) */
static int pe_get_arch(r_binfmt_s *bin) {
  WORD arch;
  WORD addr_coff;

  addr_coff = pe_get_addr_coff(bin);

  arch = *((WORD*)(bin->mapped + addr_coff + sizeof(IMAGE_COFF_HEADER)));

  return arch;
}

/* Get the offset of the sections table */
static WORD pe_get_addr_sections(r_binfmt_s *bin) {
  WORD addr_optional;
  WORD addr_coff;
  WORD arch;

  addr_coff = pe_get_addr_coff(bin);
  addr_optional = addr_coff + sizeof(IMAGE_COFF_HEADER);
  arch = pe_get_arch(bin);

  switch(arch) {
  case PE32:
    return addr_optional + sizeof(IMAGE_OPTIONAL_HEADER_32)  +
      ((IMAGE_OPTIONAL_HEADER_32*)(bin->mapped + addr_optional))->NumberOfRvaAndSizes *
      sizeof(IMAGE_DATA_DIRECTORY);
  case PE64:
    return addr_optional + sizeof(IMAGE_OPTIONAL_HEADER_64)  +
      ((IMAGE_OPTIONAL_HEADER_64*)(bin->mapped + addr_optional))->NumberOfRvaAndSizes *
      sizeof(IMAGE_DATA_DIRECTORY);
  }
  return 0;
}

/* Get the entry point */
static u64 pe_getentry(r_binfmt_s *bin) {
  WORD addr_optional;
  WORD addr_coff;
  WORD arch;

  addr_coff = pe_get_addr_coff(bin);
  addr_optional = addr_coff + sizeof(IMAGE_COFF_HEADER);
  arch = pe_get_arch(bin);

  switch(arch) {
  case PE32:
    return ((IMAGE_OPTIONAL_HEADER_32*)(bin->mapped + addr_optional))->AddressOfEntryPoint +
      ((IMAGE_OPTIONAL_HEADER_32*)(bin->mapped + addr_optional))->ImageBase;
  case PE64:
    return ((IMAGE_OPTIONAL_HEADER_64*)(bin->mapped + addr_optional))->AddressOfEntryPoint +
      ((IMAGE_OPTIONAL_HEADER_64*)(bin->mapped + addr_optional))->ImageBase;
  }

  return 0;
}

/* Load the PE file in the bin->mlist */
static void pe_load_mlist(r_binfmt_s *bin) {
  uint32_t flags;
  IMAGE_COFF_HEADER *coff;
  IMAGE_SECTION_HEADER *shdr;
  WORD sections_addr;
  int i;

  bin->mlist = r_binfmt_mlist_new();

  /* Get sections table */
  coff = (IMAGE_COFF_HEADER*)(pe_get_addr_coff(bin) + bin->mapped);
  sections_addr = pe_get_addr_sections(bin);
  shdr = (IMAGE_SECTION_HEADER*)(bin->mapped + sections_addr);


  /* Load each section */
  for(i = 0; i < coff->NumberOfSections; i++) {
    flags = 0;

    if(shdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
      flags |= R_BINFMT_MEM_FLAG_PROT_X;
    if(shdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
      flags |= R_BINFMT_MEM_FLAG_PROT_W;
    if(shdr[i].Characteristics & IMAGE_SCN_MEM_READ)
      flags |= R_BINFMT_MEM_FLAG_PROT_R;

    if(flags)
      r_binfmt_mlist_add(bin->mlist, shdr[i].VirtualAddress,
			 bin->mapped + shdr[i].PointerToRawData,
			 shdr[i].SizeOfRawData,
			 flags);
  }

}

/* Get the machine type */
static r_binfmt_arch_e pe_get_machine(r_binfmt_s *bin) {
  IMAGE_COFF_HEADER *coff;
  WORD arch;

  coff = pe_get_coff(bin);

  arch = pe_get_arch(bin);

  if(arch != PE32 && arch != PE64)
    return R_BINFMT_ARCH_UNDEF;

  switch(coff->Machine) {
  case PE_MACHINE_I386:
    return R_BINFMT_ARCH_X86;
  case PE_MACHINE_IA64:
  case PE_MACHINE_AMD64:
    return R_BINFMT_ARCH_X86_64;
  default:
    return R_BINFMT_ARCH_UNDEF;
  }

  return R_BINFMT_ARCH_UNDEF;
}

/* Check if it's a PE file */
static int r_binfmt_pe_is(r_binfmt_s *bin) {
  IMAGE_DOS_HEADER *hdr;
  DWORD sig;

  if(bin->mapped_size < sizeof(*hdr))
    return 0;

  hdr = (IMAGE_DOS_HEADER*)(bin->mapped);

  /* check MZ header */
  if (hdr->e_magic != MZ)
    return 0;

  /* check PE signature */
  sig = *((DWORD*)(bin->mapped + hdr->e_lfanew));

  if (sig != R_BINFMT_PE_MAGIC)
    return 0;

  return 1;
}

static int r_binfmt_pe_check(r_binfmt_s *bin) {
  IMAGE_DOS_HEADER *dos;
  IMAGE_COFF_HEADER *coff;
  IMAGE_SECTION_HEADER *shdr;
  DWORD addr_optional, addr_sections, numberOfRvaAndSizes;
  WORD arch;
  size_t size_optional;
  u32 tmp, i;

  /********************/
  /* Check DOS header */
  /********************/
  if(bin->mapped_size < sizeof(*dos))
    return 0;

  dos = (IMAGE_DOS_HEADER*)(bin->mapped);

  /*********************/
  /* Check COFF header */
  /*********************/
  if(bin->mapped_size < (DWORD)dos->e_lfanew)
    return 0;

  /* COFF+magic+arch */
  if(!r_utils_add32(&tmp, 8+sizeof(*coff), dos->e_lfanew))
    return 0;

  if(bin->mapped_size < tmp)
    return 0;

  coff = pe_get_coff(bin);

  /**************************/
  /* Check optionnal header */
  /**************************/
  arch = pe_get_arch(bin);

  switch(arch) {
  case PE32:
    size_optional = sizeof(IMAGE_OPTIONAL_HEADER_32);
    break;
  case PE64:
    size_optional = sizeof(IMAGE_OPTIONAL_HEADER_64);
    break;
  default:
    return 0;
  }

  if(!r_utils_add32(&tmp, 4+sizeof(*coff)+dos->e_lfanew, size_optional))
    return 0;

  if(bin->mapped_size < tmp)
    return 0;

  addr_optional = pe_get_addr_coff(bin) + sizeof(*coff);

  /******************/
  /* Check sections */
  /******************/
  switch(arch) {
  case PE32:
    numberOfRvaAndSizes = ((IMAGE_OPTIONAL_HEADER_32*)(bin->mapped + addr_optional))->NumberOfRvaAndSizes;
    break;
  case PE64:
    numberOfRvaAndSizes = ((IMAGE_OPTIONAL_HEADER_32*)(bin->mapped + addr_optional))->NumberOfRvaAndSizes;
    break;
  default:
    return 0;
  }

  if(!r_utils_mul32(&addr_sections, numberOfRvaAndSizes, sizeof(IMAGE_DATA_DIRECTORY)))
    return 0;

  if(bin->mapped_size < addr_sections)
    return 0;

  if(!r_utils_mul32(&tmp, sizeof(IMAGE_SECTION_HEADER), coff->NumberOfSections))
    return 0;

  if(!r_utils_add32(&tmp, tmp, addr_sections))
    return 0;

  if(bin->mapped_size < tmp)
    return 0;

  shdr = (IMAGE_SECTION_HEADER*)(bin->mapped + pe_get_addr_sections(bin));

  for(i = 0; i < coff->NumberOfSections; i++) {

    if(!r_utils_add32(&tmp, shdr[i].PointerToRawData, shdr[i].SizeOfRawData))
      return 0;
    if(bin->mapped_size < tmp)
      return 0;
  }

  return 1;
}

/* Main/public function : fill the r_binfmt_s structure */
r_binfmt_err_e r_binfmt_pe_load(r_binfmt_s *bin) {
  if(!r_binfmt_pe_is(bin))
    return R_BINFMT_ERR_UNRECOGNIZED;

  if(!r_binfmt_pe_check(bin))
    return R_BINFMT_ERR_MALFORMEDFILE;

  bin->type = R_BINFMT_TYPE_PE;
  bin->arch = pe_get_machine(bin);

  // TODO: check endianness for PE files
  bin->endian = R_BINFMT_ENDIAN_LITTLE;

  // TODO: handle PE entry point
  bin->entry = pe_getentry(bin);
  pe_load_mlist(bin);

  return R_BINFMT_ERR_OK;
}
