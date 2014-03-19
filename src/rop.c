#include "ropc.h"

/************************************************************************/
/* RopC - A Return Oriented Programming tool			        */
/* 								        */
/* Copyright 2013-2014, -TOSH-					        */
/* File coded by -TOSH-						        */
/* 								        */
/* This file is part of RopC.					        */
/* 								        */
/* RopC is free software: you can redistribute it and/or modify	        */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* RopC is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with RopC.  If not, see <http://www.gnu.org/licenses/>	        */
/************************************************************************/

/* =========================================================================
   This file is the entry point of RopC
   ======================================================================= */

int main(int argc, char **argv) {
  BINFMT bin;
  GLIST *glist;
  SLIST *slist;
  PAYLOAD *payload;

  /* Parse command line options */
  options_parse(argc, argv);
  
  /* Mmap bin file and parse it */
  bin_load(&bin, options_filename);

  /* Gadget mode */
  if(options_mode == MODE_GADGET) {
    glist = glist_new();
    gfind_in_bin(glist, &bin);
    print_glist(glist);
    glist_free(&glist);
  }

  /* String mode */
  if(options_mode == MODE_STRING) {
    slist = slist_new();
    sfind_in_bin(slist, &bin, &options_search);
    print_slist(slist);
    slist_free(&slist);
  }

  /* Payload mode */
  if(options_mode == MODE_PAYLOAD) {
    glist = glist_new();
    gfind_in_bin(glist, &bin);
    payload = payload_new();

    payload_make(&bin, glist, payload, options_payload);
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

  return EXIT_SUCCESS;
}
