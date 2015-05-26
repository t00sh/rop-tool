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
#ifndef __WINDOWS__
#include "rop_heap.h"
#include "api/libheap.h"

#define HEAP_DEFAULT_TMPPATH "/tmp/"

char **heap_options_command = NULL;
const char *heap_options_tmppath = HEAP_DEFAULT_TMPPATH;
const char *heap_options_color = "1";

void heap_help(void) {
  printf("Usage : %s heap [OPTIONS] [COMMAND]\n\n", PACKAGE);
  printf("OPTIONS:\n");
  printf("  --help, -h               Print this help message\n");
  printf("  --tmp, -t     <d>        Specify the writable directory, to dump the library (default: %s)\n", HEAP_DEFAULT_TMPPATH);
  printf("  --no-color, -N           Do not colorize output\n");
  printf("\n");
}

/* Parse command line options */
void heap_options_parse(int argc, char **argv) {
  int opt;

  const struct option opts[] = {
    {"help",          no_argument,       NULL, 'h'},
    {"tmp",           required_argument, NULL, 't'},
    {"no-color",      no_argument,       NULL, 'N'},
    {NULL,            0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "+ht:N", opts, NULL)) != -1) {
    switch(opt) {


    case 'h':
      heap_help();
      exit(EXIT_FAILURE);
      break;

   case 't':
      heap_options_tmppath = optarg;
      break;

    case 'N':
      heap_options_color = "0";
      break;

    default:
      heap_help();
      exit(EXIT_FAILURE);
    }
  }

  heap_options_command = argv+optind;

  if(heap_options_command[0] == NULL) {
    heap_help();
    exit(EXIT_FAILURE);
  }
}

static void heap_dump_lib(char *filename) {
  FILE *f;

  if((f = fopen(filename, "w")) == NULL)
    R_UTILS_ERR("Can't open %s", filename);

  fwrite(r_lib_heap, 1, sizeof(r_lib_heap), f);

  fclose(f);
}

void heap_cmd(int argc, char **argv) {
  char libname[72];
  int len;

  heap_options_parse(argc, argv);

  len = strlen(heap_options_tmppath);

  if(len > 64 || len <= 0)
    R_UTILS_ERRX("Bad tmp path len ! (can't excess 64 chars)");

  strcpy(libname, heap_options_tmppath);

  if(libname[len-1] != '/') {
    libname[len] = '/';
    libname[len+1] = 0;
    len++;
  }

  strcat(libname, "libheap_tmp.so");
  heap_dump_lib(libname);

  if(setenv("LD_PRELOAD", libname, 1) == -1) {
    fprintf(stderr, "Can't set LD_PRELOAD environment variable\n");
    exit(EXIT_FAILURE);
  }

  if(setenv("LIBHEAP_COLOR", heap_options_color, 0) == -1) {
    fprintf(stderr, "Can't set LIBHEAP_COLOR environment variable\n");
    exit(EXIT_FAILURE);
  }

  execvp(heap_options_command[0], heap_options_command);
}
#endif
