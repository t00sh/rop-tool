#include "ropc.h"

static void elf32_load_mlist(BINFMT *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)bin->mapped;
  Elf32_Phdr *phdr = (Elf32_Phdr*)(bin->mapped + ehdr->e_phoff);
  int i;
  uint32_t flags;

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

static int elf32_check(BINFMT *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)bin->mapped;
  Elf32_Phdr *phdr;
  int i;

  /* Check some ehdr fields */
  if(ehdr->e_phoff > bin->mapped_size)
    return 0;

  if(UINT16_MAX / ehdr->e_phnum < sizeof(Elf32_Phdr))
    return 0;

  if(UINT32_MAX - ehdr->e_phnum*sizeof(Elf32_Phdr) < ehdr->e_phoff)
    return 0;

  if(ehdr->e_phoff + ehdr->e_phnum*sizeof(Elf32_Phdr) > bin->mapped_size)
    return 0;

  /* check some phdr fields; */
  phdr = (Elf32_Phdr*)(bin->mapped + ehdr->e_phoff);

  for(i = 0; i < ehdr->e_phnum; i++) {
    if(UINT32_MAX - phdr[i].p_offset < phdr[i].p_filesz)
      return 0;
    if(phdr[i].p_offset + phdr[i].p_filesz > bin->mapped_size)
      return 0;
  }

  return 1;
}

static int elf32_is(BINFMT *bin) {

  if(bin->mapped_size < sizeof(Elf32_Ehdr))
     return 0;

  if(memcmp(bin->mapped, ELFMAG, SELFMAG))
    return 0;

  if(bin->mapped[EI_CLASS] != ELFCLASS32)
    return 0;

  return 1;
}

enum BINFMT_ARCH elf32_getarch(BINFMT *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)bin->mapped;
  
  if(ehdr->e_machine == EM_386)
    return BINFMT_ARCH_X86;

  return BINFMT_ARCH_UNDEF;
}

enum BINFMT_ENDIAN elf32_getendian(BINFMT *bin) {
  if(bin->mapped[EI_DATA] == ELFDATA2LSB)
    return BINFMT_ENDIAN_LITTLE;

  return BINFMT_ENDIAN_UNDEF;
}

/* Mmap ELF in memory */
enum BINFMT_ERR elf32_load(BINFMT *bin) {

  if(!elf32_is(bin))
    return BINFMT_ERR_UNRECOGNIZED;

  if(!elf32_check(bin))
    return BINFMT_ERR_MALFORMEDFILE;

  elf32_load_mlist(bin);

  bin->type = BINFMT_TYPE_ELF32;
  bin->arch = elf32_getarch(bin);
  bin->endian = elf32_getendian(bin);

  return BINFMT_ERR_OK;
}
