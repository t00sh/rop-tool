#include "ropc.h"

/* print a gadget */
static void print_gadget(GADGET *g) {
  if(options_color) {
    printf(COLOR_BLACK 
	   COLOR_BG_WHITE "0x%.8x" 
	   COLOR_RESET "  ->  " 
	   COLOR_GREEN "%s\n"
	   COLOR_RESET, 
	   g->value, g->comment);
  } else {
    printf("0x%.8x  ->  %s\n", g->value, g->comment);
  }
}

/* print a gadget list */
void print_glist(GLIST *glist) {
  glist_foreach(glist, print_gadget);
  printf("\n  *** %u gadgets found ***\n\n", glist_size(glist));
}

static void print_string(STRING *s) {
  if(options_color) {
    printf(COLOR_BLACK 
	   COLOR_BG_WHITE "0x%.8x" 
	   COLOR_RESET "  ->  " 
	   COLOR_GREEN "%s "
	   COLOR_RED   "%s\n"
	   COLOR_RESET, 
	   s->addr, 
	   s->string,
	   (s->addr) == 0 ? "(NOT FOUND)" : "");
  } else {
    printf("0x%.8x  ->  %s %s\n", 
	   s->addr, 
	   s->string, 
	   (s->addr == 0) ? "(NOT FOUND)" : "");
  }
}

void print_slist(SLIST *slist) {
  slist_foreach(slist, print_string);
  printf("\n  *** %u strings found ***\n\n", slist_size(slist));
}
