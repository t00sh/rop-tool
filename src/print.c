#include "ropc.h"

/* =========================================================================
   ======================================================================= */

/* print a gadget */
static void print_gadget(GADGET *g) {
  if(options_color) {
    printf(COLOR_BLACK 
	   COLOR_BG_WHITE "0x%.8x" 
	   COLOR_RESET "  ->  " 
	   "%s%s\n" 
	   COLOR_RESET, 	   
	   g->addr, 
	   g->addr == NOT_FOUND ? COLOR_RED : COLOR_GREEN,
	   g->comment);
  } else {
    printf("0x%.8x  ->  %s %s\n", 
	   g->addr, 
	   g->comment,
	   g->addr == NOT_FOUND ? "(NOT FOUND)" : "");
  }
}

/* print a gadget list */
void print_glist(GLIST *glist) {
  glist_foreach(glist, print_gadget);
  printf("\n  *** %d gadgets found ***\n\n", glist_size(glist));
}

/* =========================================================================
   ======================================================================= */

static void print_string(STRING *s) {
  if(options_color) {
    printf(COLOR_BLACK 
	   COLOR_BG_WHITE "0x%.8x" 
	   COLOR_RESET "  ->  " 
	   "%s%s\n"
	   COLOR_RESET, 
	   s->addr, 
	   s->addr == NOT_FOUND ? COLOR_RED : COLOR_GREEN,
	   s->string);

  } else {
    printf("0x%.8x  ->  %s %s\n", 
	   s->addr, 
	   s->string, 
	   s->addr == NOT_FOUND ? "(NOT FOUND)" : "");
  }
}

void print_slist(SLIST *slist) {
  slist_foreach(slist, print_string);
  printf("\n  *** %d strings found ***\n\n", slist_size(slist));
}

/* =========================================================================
   ======================================================================= */

void print_payload(PAYLOAD *payload) {
  payload_foreach(payload, print_gadget);
  printf("\n  *** %d gadgets found ***\n\n", payload_size(payload));
}
