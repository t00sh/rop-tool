#include "ropc.h"

int main(int argc, char **argv) {
  ELF elf;
  GLIST *glist;
  SLIST *slist;

  options_parse(argc, argv);
  
  elf_load(&elf, options_filename);

  if(options_mode == MODE_GADGET) {
    glist = glist_new();
    gfind_in_elf(glist, &elf);
    print_glist(glist);
    glist_free(&glist);
  }

  if(options_mode == MODE_STRING) {
    slist = slist_new();
    sfind_in_elf(slist, &elf, &options_search);
    print_slist(slist);
    slist_free(&slist);
  }

  /* cleanup */
  elf_free(&elf);
  if(options_search.start)
    free(options_search.start);
  if(options_bad.start)
    free(options_bad.start);

  return 0;
}
