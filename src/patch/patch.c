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
#include "rop_patch.h"

addr_t patch_options_address = R_BINFMT_BAD_ADDR;
addr_t patch_options_offset = R_BINFMT_BAD_ADDR;
r_utils_bytes_s *patch_options_bytes = NULL;
const char *patch_options_filename = "a.out";
const char *patch_options_output = NULL;
int patch_options_raw = 0;

void patch_help(void) {
  printf("Usage : %s patch [OPTIONS] [FILENAME]\n\n", PACKAGE);
  printf("OPTIONS:\n");
  printf("  --address, -a       [a]  Select an address to patch\n");
  printf("  --bytes, -b         [b]  A byte sequence (e.g. : \"\\xaa\\xbb\\xcc\") to write\n");
  printf("  --help, -h               Print this help message\n");
  printf("  --offset, -o        [o]  Select an offset to patch (from start of the file)\n");
  printf("  --output, -O        [o]  Write to an another filename\n");
  printf("  --raw, -r                Open file in raw mode\n");
  printf("\n");
}


/* Parse command line options */
void patch_options_parse(int argc, char **argv) {
  int opt;

  const struct option opts[] = {
    {"address",       required_argument, NULL, 'a'},
    {"bytes",         required_argument, NULL, 'b'},
    {"help",          no_argument,       NULL, 'h'},
    {"offset",        required_argument, NULL, 'o'},
    {"output",        required_argument, NULL, 'O'},
    {"raw",           no_argument,       NULL, 'r'},
    {NULL,            0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "a:b:ho:O:r", opts, NULL)) != -1) {
    switch(opt) {

    case 'a':
      patch_options_address = strtoull(optarg, NULL, 0);
      break;

    case 'b':
      patch_options_bytes = r_utils_bytes_unhexlify(optarg);
      break;

    case 'h':
      patch_help();
      exit(EXIT_FAILURE);
      break;

    case 'o':
      patch_options_offset = strtoull(optarg, NULL, 0);
      break;

    case 'O':
      patch_options_output = optarg;
      break;

    case 'r':
      patch_options_raw = 1;
      break;

    default:
      patch_help();
      exit(EXIT_FAILURE);
    }
  }

  if(optind < argc) {
    patch_options_filename = argv[optind];
  }

  if(patch_options_address == R_BINFMT_BAD_ADDR && patch_options_offset == R_BINFMT_BAD_ADDR)
    R_UTILS_ERR("Where I patch ? Random location ?! Use --offset or --address options");
  if(patch_options_address != R_BINFMT_BAD_ADDR && patch_options_offset != R_BINFMT_BAD_ADDR)
    R_UTILS_ERR("I need an offset XOR an address, not twice !");
  if(patch_options_bytes == NULL)
    R_UTILS_ERR("I patch what ? use --bytes option !");
}

void patch_cmd(int argc, char **argv) {
  r_binfmt_s bin;

  patch_options_parse(argc, argv);

  r_binfmt_load(&bin, patch_options_filename, patch_options_raw);

  if(patch_options_offset != R_BINFMT_BAD_ADDR) {
    if(patch_options_offset >= bin.mapped_size-patch_options_bytes->len)
      R_UTILS_ERR("Offset is too big !");
    memcpy(bin.mapped + patch_options_offset,
	   patch_options_bytes->bytes,
	   patch_options_bytes->len);

  } else {
    /* TODO */
  }

  if(patch_options_output != NULL)
    r_binfmt_write(&bin, patch_options_output);
  else
    r_binfmt_write(&bin, patch_options_filename);

  r_binfmt_free(&bin);
}
