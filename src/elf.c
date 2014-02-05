#include "ropc.h"

static void check_elf_phdr(DATA *data) {
  Elf32_Ehdr *ehdr;
  Elf32_Phdr *phdr;
  uint32_t i;

  ehdr = (Elf32_Ehdr*)data->data;
  phdr = (Elf32_Phdr*)(data->data + ehdr->e_phoff);

  for(i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_offset >= data->length)
      FATAL_ERROR("ELF: bad p_offset for segment %u", i);

    if(phdr[i].p_offset > 0xFFFFFFFF-phdr[i].p_filesz)
      FATAL_ERROR("ELF: overflow in p_offset for segment %u", i);

    if(phdr[i].p_offset + phdr[i].p_filesz > data->length)
      FATAL_ERROR("ELF: bad p_filesz for segment %u", i);
  }
}

static void check_elf(DATA *data) {
  Elf32_Ehdr *ehdr;

  if(data->length < sizeof(Elf32_Ehdr))
    FATAL_ERROR("ELF: bad length");

  if(memcmp(data->data, ELFMAG, SELFMAG))
    FATAL_ERROR("ELF: bad ELFMAG");

  ehdr = (Elf32_Ehdr*)data->data;

  if(ehdr->e_ident[EI_CLASS] != ELFCLASS32)
    FATAL_ERROR("ELF: EI_CLASS not supported");

  if(ehdr->e_phoff >= data->length)
    FATAL_ERROR("ELF: bad e_phoff");

  if(ehdr->e_phoff > 0xFFFFFFFF-(ehdr->e_phnum*sizeof(Elf32_Phdr)))
    FATAL_ERROR("ELF: overflow in e_phoff");

  if(ehdr->e_phoff + ehdr->e_phnum*sizeof(Elf32_Phdr) >= data->length)
    FATAL_ERROR("ELF: bad e_phoff");

  check_elf_phdr(data);
}

/* Mmap ELF in memory */
void load_elf(const char *filename, ELF *elf) {
  struct stat st;
  int fd;

  if((fd = open(filename, O_RDONLY)) < 0)
    SYSCALL_FATAL_ERROR("Can't open %s", filename);
  
  if(fstat(fd, &st) < 0)
    SYSCALL_FATAL_ERROR("Fstat failed");
  
  if((elf->data.data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == NULL)
    SYSCALL_FATAL_ERROR("Mmap failed");

  elf->data.length = st.st_size;

  check_elf(&elf->data);

  elf->ehdr = (Elf32_Ehdr*)elf->data.data;
  elf->shdr = (Elf32_Shdr*)(elf->data.data + elf->ehdr->e_shoff);
  elf->phdr = (Elf32_Phdr*)(elf->data.data + elf->ehdr->e_phoff);
}


void free_elf(ELF *elf) {
  
  munmap(elf->data.data, elf->data.length);
}


