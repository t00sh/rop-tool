#include "ropc.h"

static addr_t sfind_get_addr(MEM *mem, byte_t *start, len_t length) {
  addr_t addr;
  addr_t off, index;

  off = 0;

  do {
    index = memsearch(mem->start+off, mem->length-off, start, length);

    if(index == NOT_FOUND)
      return 0;

    addr = mem->addr + off + index;
    off += index + 1;

  }while(!is_good_addr(addr, &options_bad));

  return addr;
}

static void sfind_in_mem(SLIST *slist, MEM *mem, BLIST *blist) {
  addr_t i, j, addr;
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
      slist_add(slist, tmp, NOT_FOUND);
    }
  }  
}

void sfind_in_bin(SLIST *slist, BINFMT *bin, BLIST *blist) {
  MEM *m;

  for(m = bin->mlist->head; m != NULL; m = m->next) {
    /* TODO: search in all +R mem */
    if(m->flags & MEM_FLAG_PROT_R && m->flags & MEM_FLAG_PROT_X)
      sfind_in_mem(slist, m, blist);
  }
}
