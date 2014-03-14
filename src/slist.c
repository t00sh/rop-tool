#include "ropc.h"

SLIST* slist_new(void) {
  SLIST *slist;

  slist = xcalloc(1, sizeof(SLIST)); 

  return slist;
}

void slist_add(SLIST *slist, char *string, addr_t addr) {
  STRING *new;

  new = xmalloc(sizeof(STRING));

  new->string = string;
  new->addr = addr;
  new->next = NULL;

  if(slist->tail != NULL) {
    slist->tail->next = new;
  }
  slist->tail = new;

  if(slist->head == NULL) {
    slist->head = new;
  }
 
  slist->size++;
}

void slist_free(SLIST **slist) {
  STRING *s, *tmp;

  s = (*slist)->head;
  while(s != NULL) {
    tmp = s->next;
    free(s->string);
    free(s);
    s = tmp;
  }

  free(*slist);
  *slist = NULL;
}

void slist_foreach(SLIST *slist, void (*callback)(STRING*)) {
  STRING *s;

  for(s = slist->head; s != NULL; s = s->next) {
    callback(s);
  }
}

int slist_size(SLIST *slist) {
  return slist->size;
}
