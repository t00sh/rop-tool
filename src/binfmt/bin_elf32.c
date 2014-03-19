#include "ropc.h"

static void elf32_load_mlist(BINFMT *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)bin->mapped;
  Elf32_Phdr *phdr = (Elf32_Phdr*)(bin->mapped + ehdr->e_phoff);
  int i;
  uint32_t flags;
  uint32_t p_type, p_flags, p_vaddr, p_offset, p_filesz;
  uint16_t e_phnum;

  bin->mlist = mlist_new();

  e_phnum = endian_get16((byte_t*)&ehdr->e_phnum, bin->endian);

  for(i = 0; i < e_phnum; i++) {
    p_type = endian_get32((byte_t*)&phdr[i].p_type, bin->endian);
    p_flags = endian_get32((byte_t*)&phdr[i].p_flags, bin->endian);
    p_vaddr = endian_get32((byte_t*)&phdr[i].p_vaddr, bin->endian);
    p_offset = endian_get32((byte_t*)&phdr[i].p_offset, bin->endian);
    p_filesz = endian_get32((byte_t*)&phdr[i].p_filesz, bin->endian);

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

static int elf32_check(BINFMT *bin) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)bin->mapped;
  Elf32_Phdr *phdr;
  int i;
  uint32_t r1, r2;
  uint32_t e_phoff, p_offset, p_filesz;
  uint16_t e_phnum;

  e_phoff = endian_get32((byte_t*)&ehdr->e_phoff, bin->endian);
  e_phnum = endian_get16((byte_t*)&ehdr->e_phnum, bin->endian);

  /* Check some ehdr fields */
  if(e_phoff >= bin->mapped_size)
    return 0;

  if(!safe_mul32(&r1, e_phnum, sizeof(Elf32_Phdr)))
    return 0;

  if(!safe_add32(&r2, e_phoff, e_phnum*sizeof(Elf32_Phdr)))
    return 0;

  if(r1 + r2 >= bin->mapped_size)
    return 0;

  /* check some phdr fields; */
  phdr = (Elf32_Phdr*)(bin->mapped + e_phoff);

  for(i = 0; i < e_phnum; i++) {
    p_offset = endian_get32((byte_t*)&phdr[i].p_offset, bin->endian);
    p_filesz = endian_get32((byte_t*)&phdr[i].p_filesz, bin->endian);

    if(!safe_add32(&r1, p_offset, p_filesz))
      return 0;
    if(r1 >= bin->mapped_size)
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
  if(bin->mapped[EI_DATA] == ELFDATA2MSB)
    return BINFMT_ENDIAN_BIG;

  return BINFMT_ENDIAN_UNDEF;
}

enum BINFMT_ERR elf32_load(BINFMT *bin) {

  if(!elf32_is(bin))
    return BINFMT_ERR_UNRECOGNIZED;

  bin->type = BINFMT_TYPE_ELF32;
  bin->arch = elf32_getarch(bin);
  bin->endian = elf32_getendian(bin);

  if(!elf32_check(bin))
    return BINFMT_ERR_MALFORMEDFILE;

  elf32_load_mlist(bin);

  return BINFMT_ERR_OK;
}
