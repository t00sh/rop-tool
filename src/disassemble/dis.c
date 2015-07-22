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

/* Disassemble options */
const char *dis_options_filename = "a.out";
int dis_options_color = 1;
addr_t dis_options_address = R_BINFMT_BAD_ADDR;
addr_t dis_options_offset = R_BINFMT_BAD_OFFSET;
u64 dis_options_len = 0;
r_binfmt_arch_e dis_options_arch = R_BINFMT_TYPE_UNDEF;
r_disa_flavor_e dis_options_flavor = R_DISA_FLAVOR_INTEL;
const char *dis_options_sym = NULL;

/* Print disassemble help */
void dis_help(void) {
  printf("Usage : %s dis [OPTIONS] [FILENAME]\n\n", PACKAGE);
  printf("OPTIONS:\n");
  printf("  --help, -h               Print this help message\n");
  printf("  --no-color, -N           Do not colorize output\n");
  printf("  --address, -a    <a>     Start disassembling at address <a>\n");
  printf("  --offset, -o     <o>     Start disassembling at offset <o>\n");
  printf("  --sym, -s        <s>     Disassemble symbol\n");
  printf("  --len, -l        <l>     Disassemble only <l> bytes\n");
  printf("  --arch, -A       <a>     Select architecture (x86, x86-64, arm, arm64)\n");
  printf("  --flavor, -f     <f>     Change flavor (intel, att)\n");
  printf("\n");
}


/* Parse command line options */
void dis_options_parse(int argc, char **argv) {
  int opt;

  const struct option opts[] = {
    {"address",       required_argument, NULL, 'a'},
    {"arch",          required_argument, NULL, 'A'},
    {"sym",           required_argument, NULL, 's'},
    {"flavor",        required_argument, NULL, 'f'},
    {"help",          no_argument,       NULL, 'h'},
    {"len",           required_argument, NULL, 'l'},
    {"no-color",      no_argument,       NULL, 'N'},
    {"offset",        required_argument, NULL, 'o'},
    {NULL,            0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "a:A:s:f:hl:No:", opts, NULL)) != -1) {
    switch(opt) {

    case 'a':
      dis_options_address = strtoull(optarg, NULL, 0);
      break;

    case 's':
      dis_options_sym = optarg;
      break;

    case 'A':
      dis_options_arch = r_binfmt_string_to_arch(optarg);
      if(dis_options_arch == R_BINFMT_ARCH_UNDEF)
	R_UTILS_ERR("%s: bad architecture.", optarg);
      break;

    case 'f':
      dis_options_flavor = r_disa_string_to_flavor(optarg);
      if(dis_options_flavor == R_DISA_FLAVOR_UNDEF)
	R_UTILS_ERR("%s: bad flavor.", optarg);
      break;

    case 'h':
      dis_help();
      exit(EXIT_FAILURE);
      break;

    case 'l':
      dis_options_len = strtoull(optarg, NULL, 0);
      break;

    case 'N':
      dis_options_color = 0;
      break;

    case 'o':
      dis_options_offset = strtoull(optarg, NULL, 0);
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

/* Disassemble binary at specified address */
void dis_address(r_disa_s *dis, r_binfmt_s *bin, addr_t addr, u64 len, int stop_next_sym) {
  r_binfmt_segment_s *seg;
  r_disa_instr_t *instr;
  const char *sym;
  u64 length;
  u64 off;
  size_t i, num;
  int sym_processed = 0;

  num = r_utils_list_size(&bin->segments);

  /* Test every loadable segment */
  for(i = 0; i < num; i++) {

    seg = r_utils_list_access(&bin->segments, i);

    /* addr is in [seg->addr, seg->addr+seg->length] range */
    if(addr >= seg->addr && addr <= seg->addr+seg->length) {

      /* In case of len is out of range */
      if(len == 0 || len > seg->length - (addr - seg->addr))
        len = seg->length - (addr - seg->addr);

      length = 0;

      while(length < len) {
        off = (addr - seg->addr) + length;
        r_disa_code(dis, seg->start+off, seg->length-off, seg->addr+off, 1);
        instr = r_disa_next_instr(dis);

        /* We have disassembled the instruction, now print it ! */
        if(instr != NULL) {

          /* Print symbol, if it exists */
          if((sym = r_binfmt_get_sym_by_addr(bin, instr->address)) != NULL) {
            if(stop_next_sym) {
              if(sym_processed > 0)
                return;
              else
                sym_processed++;
            }
            R_UTILS_PRINT_YELLOW_BG_BLACK(dis_options_color, "\n<%s>:\n", sym);
          }

          if(r_binfmt_addr_size(bin->arch) == 8) {
            R_UTILS_PRINT_GREEN_BG_BLACK(dis_options_color, " %.16"PRIx64"   ", instr->address);
          } else {
            R_UTILS_PRINT_GREEN_BG_BLACK(dis_options_color, " %.8"PRIx32"   ", (u32)(instr->address));
          }
          R_UTILS_PRINT_YELLOW_BG_BLACK(dis_options_color, "%-8s ", instr->mnemonic);
          R_UTILS_PRINT_RED_BG_BLACK(dis_options_color, "%s\n", instr->op_str);
          length += instr->size;
        } else {
          /* We have failed to disassemble instruction, print the BAD instruction */
          if(r_binfmt_addr_size(bin->arch) == 8) {
            R_UTILS_PRINT_GREEN_BG_BLACK(dis_options_color, " %.16"PRIx64"   ", addr+length);
          } else {
            R_UTILS_PRINT_GREEN_BG_BLACK(dis_options_color, " %.8"PRIx32"   ", (u32)(addr+length));
          }
          R_UTILS_PRINT_YELLOW_BG_BLACK(dis_options_color, "BAD\n");
          length += 1;
        }
      }
    }
  }
}

/* Disassemble binary in range [offset, offset+len] */
void dis_offset(r_disa_s *dis, r_binfmt_s *bin, u64 offset, u64 len) {
  r_disa_instr_t *instr;
  u64 length;
  u64 off;

  /* Check offset */
  if(offset >= bin->mapped_size)
    R_UTILS_ERR("Offset out of range");

  /* Len is out of range, adjust it */
  if(len == 0 || len > bin->mapped_size - offset)
    len = bin->mapped_size - offset;

  length = 0;

  while(length < len) {
    off = offset + length;
    r_disa_code(dis, bin->mapped+off, bin->mapped_size-off, off, 1);
    instr = r_disa_next_instr(dis);

    /* We have disassembled an instruction */
    if(instr != NULL) {

      R_UTILS_PRINT_GREEN_BG_BLACK(dis_options_color, " %.16"PRIx64"   ", off);
      R_UTILS_PRINT_YELLOW_BG_BLACK(dis_options_color, "%-8s ", instr->mnemonic);
      R_UTILS_PRINT_RED_BG_BLACK(dis_options_color, "%s\n", instr->op_str);
      length += instr->size;
    } else {
      /* Disassembler failed : print BAD instruction */
      R_UTILS_PRINT_GREEN_BG_BLACK(dis_options_color, " %.16"PRIx64"   ", off);
      R_UTILS_PRINT_YELLOW_BG_BLACK(dis_options_color, "BAD\n");
      length += 1;
    }
  }
}

/* Main function of disassemble command */
void dis_cmd(int argc, char **argv) {
  int stop_next_sym = 0;
  addr_t sym;
  r_binfmt_s bin;
  r_disa_s dis;

  dis_options_parse(argc, argv);

  r_binfmt_load(&bin, dis_options_filename, dis_options_arch);

  /* Init disassembler */
  if(!r_disa_init(&dis, bin.arch))
    R_UTILS_ERR("Can't init disassembler");

  if(!r_disa_set_flavor(&dis, dis_options_flavor))
    R_UTILS_ERR("Can't set flavor");

  /* Try to find symbol, if option is set */
  if(dis_options_sym != NULL) {
    if((sym = r_binfmt_get_sym_by_name(&bin, dis_options_sym)) == R_BINFMT_BAD_ADDR)
      R_UTILS_ERR("Symbol <%s> not found", dis_options_sym);
    dis_options_address = sym;
    stop_next_sym = 1;
  }

  /* Can't disassemble offset + address at the same time */
  if(dis_options_offset != R_BINFMT_BAD_OFFSET &&
     dis_options_address != R_BINFMT_BAD_ADDR)
    R_UTILS_ERR("You must specify offset or address, not twice !");

  /* First, try disassemble at offset */
  if(dis_options_offset != R_BINFMT_BAD_OFFSET) {
    dis_offset(&dis, &bin, dis_options_offset, dis_options_len);
  } else {
    /* Now check if address if specified */
    if(dis_options_address != R_BINFMT_BAD_ADDR) {
      dis_address(&dis, &bin, dis_options_address, dis_options_len, stop_next_sym);
    /* If not, try to disassemble starting at entry point */
    } else if(bin.entry != 0) {
      dis_address(&dis, &bin, bin.entry, dis_options_len, stop_next_sym);
    /* Entry point is bad...Start at beginning of the file */
    } else {
      dis_offset(&dis, &bin, 0, dis_options_len);
    }
  }

  r_binfmt_free(&bin);
  r_disa_close(&dis);
}
