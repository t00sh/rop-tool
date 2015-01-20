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

/* =====================================================================
   This file implement functions used to parse the command line options
   ===================================================================== */

/* exported options */
const char *options_filename          = "./a.out";
enum MODE options_mode                = MODE_GADGET;
enum FLAVOR options_flavor            = FLAVOR_INTEL;
enum OUTPUT options_output            = OUTPUT_PERL;
enum ARCH options_arch                = ARCH_X86;
int options_color                     = 1;
int options_raw                       = 0;
uint8_t options_depth                 = 5;
int options_filter                    = 1;
const char *options_payload           = "x86-linux-bin-sh";
BLIST options_bad                     = {NULL, 0};
BLIST options_search                  = {NULL, 0};

/* Display program version & quit */
static void version(void) {
  printf("%s version %s\n", PACKAGE, VERSION);
  printf("Compiled the %s at %s\n", __DATE__, __TIME__);
  exit(EXIT_SUCCESS);
}

/* Display program usage & quit */
static void usage(const char *progname) {
  printf("Usage : %s [OPTIONS] filename\n", progname);
  printf("Tool for searching Gadgets in ELF and PE binaries\n");
  printf("\n");
  printf("MODES\n");
  printf("  -G, --gadget       Gadget searching mode\n");
  printf("  -S, --string       String searching mode (argument required)\n");
  printf("  -P, --payload      Payload generator mode\n");
  printf("\n");
  printf("Payload options\n");
  printf("  -p, --ptype       Specify the payload generator to use\n");
  printf("  -l, --list        List payload generators available\n");
  printf("\n");
  printf("Filter options\n");
  printf("  -b, --bad          Specify bad chars\n");
  printf("  -d, --depth        Specify the depth searching (gadget mode only)\n");
  printf("  -a, --all          Display all gadgets (gadget mode only)\n");
  printf("\n");
  printf("Output options\n");
  printf("  -n, --no-color     No colors\n");
  printf("  -f, --flavor       Specify the flavor (gadget mode only) : intel or att\n");
  printf("\n");
  printf("Arch options\n");
  printf("  -c, --cpu          Specify the architecture  (raw mode) : x86 or x86_64\n");
  printf("\n");
  printf("General options\n");
  printf("  -r, --raw          Open file in raw mode\n");
  printf("  -h, --help         Print help\n");
  printf("  -v, --version      Print version\n");
  exit(EXIT_SUCCESS);
}

/* Handle --flavor option */
static enum FLAVOR options_set_flavor(const char *flavor) {
  if(!strcmp(flavor, "intel"))
    return FLAVOR_INTEL;
  if(!strcmp(flavor, "att"))
    return FLAVOR_ATT;

  FATAL_ERROR("%s: bad flavor", flavor);

  return FLAVOR_NONE;
}

/* Handle --cpu option */
static enum ARCH options_set_arch(const char *arch) {
  if(!strcmp(arch, "x86"))
    return ARCH_X86;
  if(!strcmp(arch, "x86_64"))
    return ARCH_X86_64;

  FATAL_ERROR("%s: bad architecture", arch);

  return ARCH_NONE;
}

/* Parse command line options */
void options_parse(int argc, char **argv) {
  int list = 0;
  int opt;
  char *progname = argv[0];
  const struct option opts[] = {
    {"payload",     no_argument,       NULL, 'P'},
    {"gadget",      no_argument,       NULL, 'G'},
    {"string",      required_argument, NULL, 'S'},
    {"cpu",         required_argument, NULL, 'c'},
    {"list",        no_argument,       NULL, 'l'},
    {"ptype",       required_argument, NULL, 'p'},
    {"flavor",      required_argument, NULL, 'f'},
    {"bad",         required_argument, NULL, 'b'},
    {"depth",       required_argument, NULL, 'd'},
    {"all",         no_argument,       NULL, 'a'},
    {"help",        no_argument,       NULL, 'h'},
    {"no-color",    no_argument,       NULL, 'n'},
    {"raw",         no_argument,       NULL, 'r'},
    {"version",     no_argument,       NULL, 'v'},
    {NULL,          0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "PGS:lc:p:f:b:d:ahnvr", opts, NULL)) != -1) {
    switch(opt) {

    case 'P':
      options_mode = MODE_PAYLOAD;
      break;

    case 'G':
      options_mode = MODE_GADGET;
      break;

    case 'S':
      options_mode = MODE_STRING;
      options_search = opcodes_to_blist(optarg);
      break;

    case 'c':
      options_arch = options_set_arch(optarg);
      break;

    case 'p':
      options_payload = optarg;
      break;

    case 'l':
      list = 1;
      break;

    case 'f':
      options_flavor = options_set_flavor(optarg);
      break;

    case 'b':
      options_bad = opcodes_to_blist(optarg);
      break;

    case 'd':
      options_depth = atoi(optarg);
      break;

    case 'a':
      options_filter = 0;
      break;

    case 'h':
      usage(progname);
      break;

    case 'n':
      options_color = 0;
      break;

    case 'v':
      version();
      break;

    case 'r':
      options_raw = 1;
      break;

    default:
      usage(progname);
    }
  }

  if(list) {
    payload_list();
    exit(EXIT_FAILURE);
  }

  if(options_depth > MAX_DEPTH)
    FATAL_ERROR("Depth must be in range 0-%d", MAX_DEPTH);

  if(optind < argc) {
    options_filename = argv[optind];
  }
}
