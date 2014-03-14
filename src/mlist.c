#include "ropc.h"

MLIST* mlist_new(void) {
  MLIST *mlist;

  mlist = xcalloc(1, sizeof(MLIST)); 

  return mlist;
}

void mlist_add(MLIST *mlist, addr_t addr, byte_t *start, len_t length, uint32_t flags) {
  MEM *new;

  new = xmalloc(sizeof(MEM));

  new->addr = addr;
  new->start = start;
  new->length = length;
  new->flags = flags;

  new->next = mlist->head;

  mlist->head = new;
 
  mlist->size++;
}

void mlist_free(MLIST **mlist) {
  MEM *m, *tmp;

  m = (*mlist)->head;
  while(m != NULL) {
    tmp = m->next;
    free(m);
    m = tmp;
  }

  free(*mlist);
  *mlist = NULL;
}

void mlist_foreach(MLIST *mlist, void (*callback)(MEM*)) {
  MEM *m;

  for(m = mlist->head; m != NULL; m = m->next) {
    callback(m);
  }
}

int mlist_size(MLIST *mlist) {
  return mlist->size;
}
