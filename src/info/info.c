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
#include "rop_info.h"
const char *info_options_filename = "a.out";
int info_options_color = 1;

void info_help(void) {
  printf("Usage : %s info [OPTIONS] [FILENAME]\n\n", PACKAGE);
  printf("OPTIONS:\n");
  printf("  --filename, -f      [f]  Specify the filename\n");
  printf("  --help, -h               Print this help message\n");
  printf("  --no-color, -n           Disable colors\n");
  printf("\n");
}


/* Parse command line options */
void info_options_parse(int argc, char **argv) {
  int opt;

  const struct option opts[] = {
    {"filename",      required_argument, NULL, 'f'},
    {"help",          no_argument,       NULL, 'h'},
    {"no-color",      no_argument,       NULL, 'n'},
    {NULL,            0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "f:hn", opts, NULL)) != -1) {
    switch(opt) {

    case 'f':
      info_options_filename = optarg;
      break;

    case 'h':
      info_help();
      exit(EXIT_FAILURE);
      break;

    case 'n':
      info_options_color = 0;
      break;

    default:
      info_help();
      exit(EXIT_FAILURE);
    }
  }

  if(optind < argc) {
    info_options_filename = argv[optind];
  }
}

void info_cmd(int argc, char **argv) {
  r_binfmt_s bin;

  info_options_parse(argc, argv);

  r_binfmt_load(&bin, info_options_filename, 0);
  r_binfmt_print_infos(&bin, info_options_color);

  r_binfmt_free(&bin);
}
