#include "ropc.h"

void payload_make(const GLIST *src, PAYLOAD *dst) {
  gmake_syscall(src, dst);
}

PAYLOAD* payload_new(void) {
  PAYLOAD *payload;

  payload = xcalloc(1, sizeof(PAYLOAD)); 

  return payload;
}

void payload_add(PAYLOAD *payload, const char *comment, addr_t addr) {
  GADGET *new;

  new = xmalloc(sizeof(GADGET));

  strcpy(new->comment, comment);
  new->addr = addr;
  new->next = NULL;

  if(payload->tail != NULL) {
   payload->tail->next = new;
  }
  payload->tail = new;

  if(payload->head == NULL) {
    payload->head = new;
  }
 
  payload->size++;
}

void payload_free(PAYLOAD **payload) {
  GADGET *g, *tmp;

  g = (*payload)->head;
  while(g != NULL) {
    tmp = g->next;
    free(g);
    g = tmp;
  }

  free(*payload);
  *payload = NULL;
}

void payload_foreach(PAYLOAD *payload, void (*callback)(GADGET*)) {
  GADGET *g;

  for(g = payload->head; g != NULL; g = g->next) {
    callback(g);
  }
}

int payload_size(PAYLOAD *payload) {
  return payload->size;
}
