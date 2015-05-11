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

#define HEAP_DEFAULT_FORMAT "ascii"
#define HEAP_DEFAULT_LIBPATH "./libheap-" ARCHITECTURE ".so"

char **heap_options_command = NULL;
const char *heap_options_libpath = HEAP_DEFAULT_LIBPATH;
const char *heap_options_output = NULL;
const char *heap_options_format = HEAP_DEFAULT_FORMAT;
const char *heap_options_color = "1";

void heap_help(void) {
  printf("Usage : %s heap [OPTIONS] [COMMAND]\n\n", PACKAGE);
  printf("OPTIONS:\n");
  printf("  --format, -f      <f>    Select output format (default: %s)\n", HEAP_DEFAULT_FORMAT);
  printf("  --help, -h               Print this help message\n");
  printf("  --library, -l     <l>    Specify the library path for libheap.so (default : %s)\n", HEAP_DEFAULT_LIBPATH);
  printf("  --no-color, -N           Do not colorize output\n");
  printf("  --output, -O      <f>    Write trace in a file\n");
  printf("\n");
}


/* Parse command line options */
void heap_options_parse(int argc, char **argv) {
  int opt;

  const struct option opts[] = {
    {"format",        required_argument, NULL, 'f'},
    {"help",          no_argument,       NULL, 'h'},
    {"library",       required_argument, NULL, 'l'},
    {"no-color",      no_argument,       NULL, 'N'},
    {"output",        required_argument, NULL, 'O'},
    {NULL,            0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "+f:hl:NO:", opts, NULL)) != -1) {
    switch(opt) {


    case 'h':
      heap_help();
      exit(EXIT_FAILURE);
      break;

   case 'l':
      heap_options_libpath = optarg;
      break;

    case 'N':
      heap_options_color = "0";
      break;

    case 'O':
      heap_options_output = optarg;
      break;

    case 'f':
      heap_options_format = optarg;
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

void heap_cmd(int argc, char **argv) {
  heap_options_parse(argc, argv);

  if(setenv("LD_PRELOAD", heap_options_libpath, 1) == -1) {
    fprintf(stderr, "Can't set LD_PRELOAD environment variable\n");
    exit(EXIT_FAILURE);
  }

  if(setenv("LIBHEAP_FORMAT", heap_options_format, 0) == -1) {
    fprintf(stderr, "Can't set LIBHEAP_FORMAT environment variable\n");
    exit(EXIT_FAILURE);
  }

  if(heap_options_output) {
    if(setenv("LIBHEAP_OUTPUT", heap_options_output, 0) == -1) {
      fprintf(stderr, "Can't set LIBHEAP_OUTPUT environment variable\n");
      exit(EXIT_FAILURE);
    }
  }

  if(setenv("LIBHEAP_COLOR", heap_options_color, 0) == -1) {
    fprintf(stderr, "Can't set LIBHEAP_COLOR environment variable\n");
    exit(EXIT_FAILURE);
  }

  execvp(heap_options_command[0], heap_options_command);
}
#endif
