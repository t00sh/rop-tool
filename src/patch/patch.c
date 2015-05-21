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
r_binfmt_arch_e patch_options_arch = R_BINFMT_ARCH_UNDEF;

void patch_help(void) {
  printf("Usage : %s patch [OPTIONS] [FILENAME]\n\n", PACKAGE);
  printf("OPTIONS:\n");
  printf("  --address, -a       [a]  Select an address to patch\n");
  printf("  --bytes, -b         [b]  A byte sequence (e.g. : \"\\xaa\\xbb\\xcc\") to write\n");
  printf("  --filename, -f      [f]  Specify the filename\n");
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
    {"filename",      required_argument, NULL, 'f'},
    {"help",          no_argument,       NULL, 'h'},
    {"offset",        required_argument, NULL, 'o'},
    {"output",        required_argument, NULL, 'O'},
    {"raw",           no_argument,       NULL, 'r'},
    {NULL,            0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "a:b:f:ho:O:r", opts, NULL)) != -1) {
    switch(opt) {

    case 'a':
      patch_options_address = strtoull(optarg, NULL, 0);
      break;

    case 'b':
      patch_options_bytes = r_utils_bytes_unhexlify(optarg);
      break;

    case 'f':
      patch_options_filename = optarg;
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
      patch_options_arch = R_BINFMT_ARCH_X86;
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
    R_UTILS_ERR("Where I patch ? Random location ?! Use --offset or --address options !");
  if(patch_options_address != R_BINFMT_BAD_ADDR && patch_options_offset != R_BINFMT_BAD_ADDR)
    R_UTILS_ERR("I need an offset OR an address, not twice !");
  if(patch_options_bytes == NULL)
    R_UTILS_ERR("I patch what ? use --bytes option !");
}


static void patch_address(r_binfmt_s *bin, addr_t addr, void *bytes, u64 len) {
  r_binfmt_mem_s *m;
  u64 off;

  for(m = bin->mlist->head; m; m = m->next) {
    if(addr >= m->addr && addr <= m->addr+m->length) {
      if(addr+len >= m->addr+m->length) {
	R_UTILS_ERR("Too many bytes to copy !");
      }

      off = addr - m->addr;
      memcpy(m->start+off, bytes, len);
      return;
    }
  }
  R_UTILS_ERR("Address not found...");
}

static void patch_offset(r_binfmt_s *bin, addr_t off, void *bytes, u64 len) {
  if(off >= bin->mapped_size || off+len > bin->mapped_size) {
    R_UTILS_ERR("Offset out of range !");
  }
  memcpy(bin->mapped+off, bytes, len);
}

void patch_cmd(int argc, char **argv) {
  r_binfmt_s bin;

  patch_options_parse(argc, argv);

  r_binfmt_load(&bin, patch_options_filename, patch_options_arch);

  if(patch_options_offset != R_BINFMT_BAD_ADDR) {
    patch_offset(&bin,
		 patch_options_offset,
		 patch_options_bytes->bytes,
		 patch_options_bytes->len);

  } else {
    patch_address(&bin,
		  patch_options_address,
		  patch_options_bytes->bytes,
		  patch_options_bytes->len);
  }

  if(patch_options_output == NULL)
    patch_options_output = patch_options_filename;


  r_binfmt_write(&bin, patch_options_output);
  printf("[+] Patched %" PRIu64 " bytes (result saved in %s)\n", patch_options_bytes->len, patch_options_output);


  r_binfmt_free(&bin);
}
