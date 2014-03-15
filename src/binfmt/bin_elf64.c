#include "ropc.h"

static void elf64_load_mlist(BINFMT *bin) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)bin->mapped;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(bin->mapped + ehdr->e_phoff);
  int i;
  uint64_t flags;

  bin->mlist = mlist_new();

  for(i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_type == PT_LOAD) {

      flags = 0;
      if(phdr[i].p_flags & PF_X)
	flags |= MEM_FLAG_PROT_X;
      if(phdr[i].p_flags & PF_R)
	flags |= MEM_FLAG_PROT_R;
      if(phdr[i].p_flags & PF_W)
	flags |= MEM_FLAG_PROT_W;

      mlist_add(bin->mlist, 
		phdr[i].p_vaddr,
		bin->mapped + phdr[i].p_offset,
		phdr[i].p_filesz,
		flags);
    }
  }
}

static int elf64_check(BINFMT *bin) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)bin->mapped;
  Elf64_Phdr *phdr;
  int i;

  /* Check some ehdr fields */
  if(ehdr->e_phoff > bin->mapped_size)
    return 0;

  if(UINT16_MAX / ehdr->e_phnum < sizeof(Elf64_Phdr))
    return 0;

  if(UINT64_MAX - ehdr->e_phnum*sizeof(Elf64_Phdr) < ehdr->e_phoff)
    return 0;

  if(ehdr->e_phoff + ehdr->e_phnum*sizeof(Elf64_Phdr) > bin->mapped_size)
    return 0;

  /* check some phdr fields; */
  phdr = (Elf64_Phdr*)(bin->mapped + ehdr->e_phoff);

  for(i = 0; i < ehdr->e_phnum; i++) {
    if(UINT64_MAX - phdr[i].p_offset < phdr[i].p_filesz)
      return 0;
    if(phdr[i].p_offset + phdr[i].p_filesz > bin->mapped_size)
      return 0;
  }

  return 1;
}

static int elf64_is(BINFMT *bin) {

  if(bin->mapped_size < sizeof(Elf64_Ehdr))
     return 0;

  if(memcmp(bin->mapped, ELFMAG, SELFMAG))
    return 0;

  if(bin->mapped[EI_CLASS] != ELFCLASS64)
    return 0;

  return 1;
}

enum BINFMT_ARCH elf64_getarch(BINFMT *bin) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)bin->mapped;
  
  if(ehdr->e_machine == EM_X86_64)
    return BINFMT_ARCH_X86_64;

  return BINFMT_ARCH_UNDEF;
}

enum BINFMT_ENDIAN elf64_getendian(BINFMT *bin) {
  if(bin->mapped[EI_DATA] == ELFDATA2LSB)
    return BINFMT_ENDIAN_LITTLE;

  return BINFMT_ENDIAN_UNDEF;
}

/* Mmap ELF in memory */
enum BINFMT_ERR elf64_load(BINFMT *bin) {

  if(!elf64_is(bin))
    return BINFMT_ERR_UNRECOGNIZED;

  if(!elf64_check(bin))
    return BINFMT_ERR_MALFORMEDFILE;

  elf64_load_mlist(bin);

  bin->type = BINFMT_TYPE_ELF64;
  bin->arch = elf64_getarch(bin);
  bin->endian = elf64_getendian(bin);

  return BINFMT_ERR_OK;
}
