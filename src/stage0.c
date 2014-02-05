#include "ropc.h"


void stage0_strcpy(void) {
  STRINGS s;
  uint32_t i;
  uint32_t addr;
  Elf32_Phdr *ph;

  for(i = 0; i < File.ehdr->e_phnum; i++) {
    if(File.phdr[i].p_type == PT_LOAD) {
      if(File.phdr[i].p_flags & PF_W) {
	break;
      }
    }
  }

  if(i >= File.ehdr->e_phnum)
    FATAL_ERROR("PT_LOAD +W not found");

  ph = &File.phdr[i];

  s = searching_strings_in_elf(&File, &String);
  addr = ph->p_vaddr;

  for(i = 0; i < s.entries; i++) {
    fprintf(Options.out, "# %s\n", data_to_opcodes(s.lst[i]));
    fprintf(Options.out, "$payload .= pack('L', $strcpy_plt);\n");
    fprintf(Options.out, "$payload .= pack('L', $pop2_ret);\n");
    fprintf(Options.out, "$payload .= pack('L', 0x%.8x);\n", addr);
    fprintf(Options.out, "$payload .= pack('L', 0x%.8x);\n", s.lst[i]->addr);
    fprintf(Options.out, "\n");
    addr += s.lst[i]->length;
  }
}

