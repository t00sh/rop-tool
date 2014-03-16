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


#include "ropc.h"

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
  PE_MACHINE_IA64=0X200
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


IMAGE_DOS_HEADER* pe_get_dos(BINFMT *bin) {
  return (IMAGE_DOS_HEADER*)(bin->mapped);
}

WORD pe_get_addr_coff(BINFMT *bin) {
  IMAGE_DOS_HEADER *dos;

  dos = pe_get_dos(bin);

  return dos->e_lfanew + 4;
}

IMAGE_COFF_HEADER* pe_get_coff(BINFMT *bin) {
  IMAGE_COFF_HEADER *coff;
  WORD addr_coff;

  addr_coff = pe_get_addr_coff(bin);

  coff = (IMAGE_COFF_HEADER*)(bin->mapped + addr_coff);

  return coff;
}

int pe_get_arch(BINFMT *bin) {
  WORD arch;
  WORD addr_coff;

  addr_coff = pe_get_addr_coff(bin);

  arch = *((WORD*)(bin->mapped + addr_coff + sizeof(IMAGE_COFF_HEADER)));

  return arch;
}

WORD pe_get_addr_sections(BINFMT *bin) {
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

void pe_load_mlist(BINFMT *bin) {
  uint32_t flags;
  IMAGE_COFF_HEADER *coff;
  IMAGE_SECTION_HEADER *shdr;
  WORD sections_addr;
  int i;

  bin->mlist = mlist_new();
  
  coff = (IMAGE_COFF_HEADER*)(pe_get_addr_coff(bin) + bin->mapped);
  sections_addr = pe_get_addr_sections(bin);
  shdr = (IMAGE_SECTION_HEADER*)(bin->mapped + sections_addr);


  for(i = 0; i < coff->NumberOfSections; i++) {
    flags = 0;

    if(shdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
      flags |= MEM_FLAG_PROT_X;
    if(shdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
      flags |= MEM_FLAG_PROT_W;
    if(shdr[i].Characteristics & IMAGE_SCN_MEM_READ)
      flags |= MEM_FLAG_PROT_R;

    if(flags)
      mlist_add(bin->mlist, shdr[i].VirtualAddress,
		bin->mapped + shdr[i].PointerToRawData,
		shdr[i].SizeOfRawData,
		flags);
  }
  
}

enum BINFMT_ARCH pe_get_machine(BINFMT *bin) {
  IMAGE_COFF_HEADER *coff;
  WORD arch;

  coff = pe_get_coff(bin);

  arch = pe_get_arch(bin);

  if(arch != PE32 && arch != PE64)
    return BINFMT_ARCH_UNDEF;

  switch(coff->Machine) {
  case PE_MACHINE_I386:
    return BINFMT_ARCH_X86;
  case PE_MACHINE_IA64:
    return BINFMT_ARCH_X86_64;
  default:
    return BINFMT_ARCH_UNDEF;
  }

  return BINFMT_ARCH_UNDEF;
}

int pe_is(BINFMT *bin) {
  WORD header;
  LONG elfanew;
  DWORD pesig;

  header = elfanew = pesig = 0;

  header = *((WORD*)(bin->mapped));

  /* check MZ header */
  if (header != MZ)
    return 0;

  /* check PE signature */
  elfanew = *((LONG*)(bin->mapped + sizeof(IMAGE_DOS_HEADER) - sizeof(LONG)));
  pesig = *((DWORD*)(bin->mapped + elfanew));

  if (pesig != 0x4550) // "PE\0\0"
    return 0;	

  return 1;
}

enum BINFMT_ERR pe_load(BINFMT *bin) {
  if(!pe_is(bin))
    return BINFMT_ERR_UNRECOGNIZED;

  pe_load_mlist(bin);

  bin->type = BINFMT_TYPE_PE;
  bin->arch = pe_get_machine(bin);
  
  return BINFMT_ERR_OK;
}
