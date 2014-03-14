#include "ropc.h"

static uint32_t sfind_get_addr(MEM *mem, uint8_t *start, uint32_t length) {
  uint32_t addr;
  uint32_t off, index;

  off = 0;

  do {
    index = memsearch(mem->start+off, mem->length-off, start, length);

    if(index == (uint32_t)-1)
      return 0;

    addr = mem->addr + off + index;
    off += index + 1;

  }while(!is_good_addr(addr, &options_bad));

  return addr;
}

static void sfind_in_mem(SLIST *slist, MEM *mem, BLIST *blist) {
  uint32_t i, j, addr;
  char *tmp;
  BLIST op;
  int found;

  for(i = 0; i < blist->length; i++) {
    found = 0;

    for(j = blist->length-i; j > 0; j--) {
      addr = sfind_get_addr(mem, blist->start+i, j);

      if(addr != 0) {
	op.start = blist->start+i;
	op.length = j;

	tmp = blist_to_opcodes(&op);
	slist_add(slist, tmp, addr);
	i += j - 1;
	found = 1;
	break;
      }
    }
    if(!found) {
      op.start = blist->start+i;
      op.length = 1;
      tmp = blist_to_opcodes(&op);
      slist_add(slist, tmp, 0);
    }
  }  
}

void sfind_in_elf(SLIST *slist, ELF *elf, BLIST *blist) {
  MEM mem;

  mem = elf_getseg(elf, PT_LOAD, PF_R | PF_X);
  sfind_in_mem(slist, &mem, blist);
}
