/************************************************************************/
/* rop-tool - A Return Oriented Programming and binary exploitation     */
/*            tool                                                      */
/* 								        */
/* Copyright 2013-2015, -TOSH-					        */
/* File coded by -TOSH-						        */
/* 								        */
/* This file is part of rop-tool.	       			        */
/* 								        */
/* rop-tool is free software: you can redistribute it and/or modif      */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* rop-tool is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with rop-tool.  If not, see <http://www.gnu.org/licenses/>     */
/************************************************************************/
#include "rop_disassemble.h"

const char *dis_options_filename = "a.out";


void dis_help(void) {
  printf("Usage : %s dis [OPTIONS] [FILENAME]\n\n", PACKAGE);
  printf("OPTIONS:\n");
  printf("  --help, -h               Print this help message\n");
  printf("\n");
}


/* Parse command line options */
void dis_options_parse(int argc, char **argv) {
  int opt;

  const struct option opts[] = {
    {"help",          no_argument,       NULL, 'h'},
    {NULL,            0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
    switch(opt) {

    case 'h':
      dis_help();
      exit(EXIT_FAILURE);
      break;

    default:
      dis_help();
      exit(EXIT_FAILURE);
    }
  }

  if(optind < argc) {
    dis_options_filename = argv[optind];
  }
}


void dis_cmd(int argc, char **argv) {
  r_binfmt_s bin;

  dis_options_parse(argc, argv);

  r_binfmt_load(&bin, dis_options_filename, 0);

  r_binfmt_free(&bin);
}
