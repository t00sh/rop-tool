#include "ropc.h"

#define ELF_EICLASS(elf) (elf->e_ident[EI_CLASS])

#define ELF_MIN_SIZE (sizeof(Elf32_Ehdr) > sizeof(Elf64_Ehdr) ? sizeof(Elf32_Ehdr) : sizeof(Elf64_Ehdr))

static void elf_set_ehdr_64(ELF *elf) {
  elf->ehdr.x64 = (Elf64_Ehdr*)elf->mem.start;
}

static void elf_set_shdr_64(ELF *elf) {
  elf->shdr.x64 = (Elf64_Shdr*)(elf->mem.start + elf->ehdr.x64->e_shoff);
}

static void elf_set_phdr_64(ELF *elf) {
  elf->phdr.x64 = (Elf64_Phdr*)(elf->mem.start + elf->ehdr.x64->e_phoff);
}

static void elf_check_phdr_64(ELF *elf) {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  uint16_t i;

  ehdr = elf->ehdr.x64;
  phdr = elf->phdr.x64;

  for(i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_offset >= elf->mem.length)
      FATAL_ERROR("ELF: bad p_offset for segment %u", i);

    if(phdr[i].p_offset + phdr[i].p_filesz > elf->mem.length)
      FATAL_ERROR("ELF: bad p_filesz for segment %u", i);
  }
}

static void elf_check_ehdr_64(ELF *elf) {
  MEM *mem = &elf->mem;

  if(elf->ehdr.x64->e_phoff >= mem->length)
    FATAL_ERROR("ELF: bad e_phoff");

  if(elf->ehdr.x64->e_phoff + elf->ehdr.x64->e_phnum * sizeof(Elf64_Phdr) >= mem->length)
    FATAL_ERROR("ELF: bad e_phoff");
}

static MEM elf_getseg_64(ELF *elf, uint32_t p_type, uint32_t p_flags) {
  MEM mem;
  uint16_t i;

  memset(&mem, 0, sizeof(mem));

  for(i = 0; i < elf->ehdr.x64->e_phnum; i++) {
    if(elf->phdr.x64->p_type == p_type) {
      if(elf->phdr.x64[i].p_flags == p_flags) {
	mem.addr = elf->phdr.x64[i].p_vaddr;
	mem.length = elf->phdr.x64[i].p_filesz;
	mem.start = elf->mem.start + elf->phdr.x64[i].p_offset;
	break;
      }
    }
  }
  return mem;
}

static void elf_set_ehdr_32(ELF *elf) {
  elf->ehdr.x32 = (Elf32_Ehdr*)elf->mem.start;
}

static void elf_set_shdr_32(ELF *elf) {
  elf->shdr.x32 = (Elf32_Shdr*)(elf->mem.start + elf->ehdr.x32->e_shoff);
}

static void elf_set_phdr_32(ELF *elf) {
  elf->phdr.x32 = (Elf32_Phdr*)(elf->mem.start + elf->ehdr.x32->e_phoff);
}

static void elf_check_phdr_32(ELF *elf) {
  Elf32_Ehdr *ehdr;
  Elf32_Phdr *phdr;
  uint32_t i;

  ehdr = elf->ehdr.x32;
  phdr = elf->phdr.x32;

  for(i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_offset >= elf->mem.length)
      FATAL_ERROR("ELF: bad p_offset for segment %u", i);

    if(phdr[i].p_offset + phdr[i].p_filesz > elf->mem.length)
      FATAL_ERROR("ELF: bad p_filesz for segment %u", i);
  }
}

static void elf_check_ehdr_32(ELF *elf) {
  MEM *mem = &elf->mem;

  if(elf->ehdr.x32->e_phoff >= mem->length)
    FATAL_ERROR("ELF: bad e_phoff");

  if(elf->ehdr.x32->e_phoff + elf->ehdr.x32->e_phnum * sizeof(Elf64_Phdr) >= mem->length)
    FATAL_ERROR("ELF: bad e_phoff");
}



static void elf_check(ELF *elf) {
  MEM *mem = &elf->mem;

  if(mem->length < ELF_MIN_SIZE)
    FATAL_ERROR("ELF: bad length");

  if(memcmp(mem->start, ELFMAG, SELFMAG))
    FATAL_ERROR("ELF: bad ELFMAG");
}

static MEM elf_getseg_32(ELF *elf, uint32_t p_type, uint32_t p_flags) {
  MEM mem;
  uint16_t i;

  memset(&mem, 0, sizeof(mem));


  for(i = 0; i < elf->ehdr.x32->e_phnum; i++) {
    if(elf->phdr.x32[i].p_type == p_type) {
      if(elf->phdr.x32[i].p_flags == p_flags) {
	mem.addr = elf->phdr.x32[i].p_vaddr;
	mem.length = elf->phdr.x32[i].p_filesz;
	mem.start = elf->mem.start + elf->phdr.x32[i].p_offset;
	break;
      }
    }
  }
  return mem;
}

MEM elf_getseg(ELF *elf, uint32_t p_type, uint32_t p_flags) {
  int class = ELF_EICLASS(elf);
  
  if(class == ELFCLASS32)
    return elf_getseg_32(elf, p_type, p_flags);

  return elf_getseg_64(elf, p_type, p_flags);
}

/* Mmap ELF in memory */
void elf_load(ELF *elf, const char *filename) {
  struct stat st;
  int fd;

  assert(elf != NULL);
  assert(filename != NULL);

  memset(elf, 0, sizeof(ELF));

  if((fd = open(filename, O_RDONLY)) < 0)
    SYSCALL_FATAL_ERROR("Can't open %s", filename);
  
  if(fstat(fd, &st) < 0)
    SYSCALL_FATAL_ERROR("Failed to fstat");
  
  if((elf->mem.start = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    SYSCALL_FATAL_ERROR("Failed to mmap");

  elf->mem.length = st.st_size;

  elf->e_ident = elf->mem.start;

  elf_check(elf);

  if(ELF_EICLASS(elf) == ELFCLASS32) {
    elf_set_ehdr_32(elf);
    elf_check_ehdr_32(elf);
    elf_set_phdr_32(elf);
    elf_check_phdr_32(elf);
    elf_set_shdr_32(elf); 
  } else if(ELF_EICLASS(elf) == ELFCLASS64) {
    elf_set_ehdr_64(elf);
    elf_check_ehdr_64(elf);
    elf_set_phdr_64(elf);
    elf_check_phdr_64(elf);
    elf_set_shdr_64(elf); 
  } else {
    FATAL_ERROR("ELF: Bad EI_CLASS");
  }

  close(fd);
}


void elf_free(ELF *elf) {
  assert(elf != NULL);
  assert(elf->mem.start != NULL);
  assert(elf->mem.length != 0);

  munmap(elf->mem.start, elf->mem.length);
}


