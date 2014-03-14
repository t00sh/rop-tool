#include "ropc.h"

void gmake_setreg(const GLIST *src, PAYLOAD *dst, const char *reg, addr_t value) {
  char gadget[GADGET_COMMENT_LEN];
  GADGET *g;

  snprintf(gadget, GADGET_COMMENT_LEN, "pop %s ; ret  ; ", reg);

  if((g = gfilter_search(src, gadget)) != NULL) {
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }

  snprintf(gadget, GADGET_COMMENT_LEN, "set %s to value %.8x", reg, value);
  payload_add(dst, gadget, value);
}

void gmake_swapstack(const GLIST *src, PAYLOAD *dst, addr_t addr) {
  char gadget[GADGET_COMMENT_LEN];
  GADGET *g;

  gmake_setreg(src, dst, "ebp", addr+4);
  strcpy(gadget, "leave  ; ret  ; ");

  if((g = gfilter_search(src, gadget)) != NULL) {
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }
}

void gmake_setmem(const GLIST *src, PAYLOAD *dst, addr_t addr, addr_t value) {
  char gadget[GADGET_COMMENT_LEN];
  char r1[4], r2[4];
  GADGET *g;


  strcpy(gadget, "mov  [%R], %R ; ret  ; ");
  if((g = gfilter_search(src, gadget)) != NULL) {
    strncpy(r1, g->comment+6, 3);
    strncpy(r2, g->comment+12, 3);
    r1[3] = r2[3] = '\0';

    gmake_setreg(src, dst, r1, addr);
    gmake_setreg(src, dst, r2, value);
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }
}

void gmake_syscall(const GLIST *src, PAYLOAD *dst) {
  char gadget[GADGET_COMMENT_LEN];
  GADGET *g;

  strcpy(gadget, "int 0x80 ; ret  ; ");

  if((g = gfilter_search(src, gadget)) != NULL) {
    payload_add(dst, g->comment, g->addr);
  } else {
    payload_add(dst, gadget, NOT_FOUND);
  }
}
