#include "ropc.h"

int main(int argc, char **argv) {
  BINFMT bin;
  GLIST *glist;
  SLIST *slist;
  PAYLOAD *payload;

  options_parse(argc, argv);
  
  bin_load(&bin, options_filename);

  if(options_mode == MODE_GADGET) {
    glist = glist_new();
    gfind_in_bin(glist, &bin);
    print_glist(glist);
    glist_free(&glist);
  }

  if(options_mode == MODE_STRING) {
    slist = slist_new();
    sfind_in_bin(slist, &bin, &options_search);
    print_slist(slist);
    slist_free(&slist);
  }

  if(options_mode == MODE_PAYLOAD) {
    glist = glist_new();
    gfind_in_bin(glist, &bin);
    payload = payload_new();

    payload_make(glist, payload);
    print_payload(payload);
    glist_free(&glist);
    payload_free(&payload);
  }
  /* cleanup */

  bin_free(&bin);
  if(options_search.start)
    free(options_search.start);
  if(options_bad.start)
    free(options_bad.start);

  return 0;
}
